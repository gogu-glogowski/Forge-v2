//! Trusted base-image cache with signed-checksum verification.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

pub const FEDORA_RELEASE: &str = "44";
pub const FEDORA_ARCH: &str = "x86_64";
pub const FEDORA_FILENAME: &str = "Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2";
pub const FEDORA_SOURCE_URL: &str = "https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2";
pub const FEDORA_CHECKSUM_URL: &str = "https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/Fedora-Cloud-44-1.7-x86_64-CHECKSUM";
pub const FEDORA_KEYRING_URL: &str = "https://fedoraproject.org/fedora.gpg";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImageStatus {
    Missing,
    Downloading,
    Unverified,
    Verified,
    Invalid,
}

impl fmt::Display for ImageStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageMetadata {
    pub distro: String,
    pub release: String,
    pub architecture: String,
    pub source_url: String,
    pub local_path: PathBuf,
    pub expected_checksum: Option<String>,
    pub actual_checksum: Option<String>,
    pub verified_at_unix_seconds: Option<u64>,
    pub status: ImageStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageDirectories {
    pub images: PathBuf,
    pub downloads: PathBuf,
}

#[derive(Debug)]
pub enum ImageError {
    Io(io::Error),
    Metadata(String),
    Download(String),
    SignatureVerification(String),
    IncompleteVerificationData,
    ChecksumMismatch { expected: String, actual: String },
    VerifiedImageExists(PathBuf),
    InvalidTransition { from: ImageStatus, to: ImageStatus },
    UnsupportedImage(String),
}

impl fmt::Display for ImageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "image I/O failed: {error}"),
            Self::Metadata(error) => write!(formatter, "image metadata is invalid: {error}"),
            Self::Download(error) => write!(formatter, "image download failed: {error}"),
            Self::SignatureVerification(error) => {
                write!(
                    formatter,
                    "Fedora CHECKSUM signature verification failed: {error}"
                )
            }
            Self::IncompleteVerificationData => {
                formatter.write_str("official verification data is incomplete")
            }
            Self::ChecksumMismatch { expected, actual } => {
                write!(
                    formatter,
                    "image checksum mismatch: expected {expected}, got {actual}"
                )
            }
            Self::VerifiedImageExists(path) => {
                write!(
                    formatter,
                    "verified image already exists: {}",
                    path.display()
                )
            }
            Self::InvalidTransition { from, to } => {
                write!(formatter, "invalid image state transition: {from} -> {to}")
            }
            Self::UnsupportedImage(name) => write!(formatter, "unsupported image: {name}"),
        }
    }
}

impl std::error::Error for ImageError {}

impl From<io::Error> for ImageError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub trait ArtifactFetcher {
    /// # Errors
    /// Returns an error when the URL cannot be saved at the destination.
    fn download(&mut self, url: &str, destination: &Path) -> Result<(), ImageError>;

    /// Verifies a clear-signed checksum and writes its authenticated payload.
    ///
    /// # Errors
    /// Returns an error when the signature is not valid for the supplied keyring.
    fn verify_checksum_signature(
        &mut self,
        checksum: &Path,
        keyring: &Path,
        verified_output: &Path,
    ) -> Result<(), ImageError>;
}

pub struct SystemArtifactFetcher;

impl ArtifactFetcher for SystemArtifactFetcher {
    fn download(&mut self, url: &str, destination: &Path) -> Result<(), ImageError> {
        let output = Command::new("curl")
            .args(["--fail", "--location", "--show-error", "--output"])
            .arg(destination)
            .arg(url)
            .output()?;
        if output.status.success() {
            Ok(())
        } else {
            Err(ImageError::Download(
                String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            ))
        }
    }

    fn verify_checksum_signature(
        &mut self,
        checksum: &Path,
        keyring: &Path,
        verified_output: &Path,
    ) -> Result<(), ImageError> {
        let output = Command::new("gpgv")
            .arg("--keyring")
            .arg(keyring)
            .arg("--output")
            .arg(verified_output)
            .arg(checksum)
            .output()?;
        if output.status.success() {
            Ok(())
        } else {
            Err(ImageError::SignatureVerification(
                String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            ))
        }
    }
}

#[must_use]
pub fn default_directories() -> Option<ImageDirectories> {
    let home = env::var_os("HOME").map(PathBuf::from)?;
    Some(ImageDirectories {
        images: home.join(".local/share/forge/images"),
        downloads: home.join(".cache/forge/downloads"),
    })
}

#[must_use]
pub fn can_transition(from: ImageStatus, to: ImageStatus) -> bool {
    matches!(
        (from, to),
        (ImageStatus::Missing, ImageStatus::Downloading)
            | (ImageStatus::Downloading, ImageStatus::Unverified)
            | (
                ImageStatus::Downloading | ImageStatus::Unverified,
                ImageStatus::Invalid
            )
            | (ImageStatus::Unverified, ImageStatus::Verified)
    )
}

/// Reads Fedora metadata, returning a synthetic Missing record when absent.
///
/// # Errors
/// Returns an error when existing metadata cannot be read or decoded.
pub fn inspect(directories: &ImageDirectories) -> Result<ImageMetadata, ImageError> {
    let metadata_path = metadata_path(directories);
    if !metadata_path.exists() {
        return Ok(base_metadata(directories, ImageStatus::Missing));
    }
    let bytes = fs::read(metadata_path)?;
    serde_json::from_slice(&bytes).map_err(|error| ImageError::Metadata(error.to_string()))
}

/// Lists the single Fedora image known in v1.
///
/// # Errors
/// Returns an error when Fedora metadata is corrupt or unreadable.
pub fn list(directories: &ImageDirectories) -> Result<Vec<ImageMetadata>, ImageError> {
    Ok(vec![inspect(directories)?])
}

/// Fetches and cryptographically verifies the official Fedora Cloud image.
///
/// # Errors
/// Returns an error for failed downloads, invalid signatures/checksums,
/// incomplete verification data, or attempts to overwrite a verified image.
pub fn fetch_fedora<F: ArtifactFetcher>(
    directories: &ImageDirectories,
    fetcher: &mut F,
) -> Result<ImageMetadata, ImageError> {
    fs::create_dir_all(&directories.images)?;
    fs::create_dir_all(&directories.downloads)?;
    let existing = inspect(directories)?;
    if existing.status == ImageStatus::Verified && existing.local_path.exists() {
        let expected = existing
            .expected_checksum
            .as_deref()
            .ok_or(ImageError::IncompleteVerificationData)?;
        let actual = sha256_file(&existing.local_path)?;
        if actual == expected {
            return Ok(existing);
        }
        return Err(ImageError::VerifiedImageExists(existing.local_path));
    }

    let mut metadata = base_metadata(directories, ImageStatus::Missing);
    transition(&mut metadata, ImageStatus::Downloading)?;
    write_metadata_atomic(directories, &metadata)?;

    let image_temp = directories
        .downloads
        .join(format!("{FEDORA_FILENAME}.part"));
    let checksum_file = directories
        .downloads
        .join("Fedora-Cloud-44-1.7-x86_64-CHECKSUM");
    let keyring_file = directories.downloads.join("fedora.gpg");
    let verified_checksum = directories.downloads.join("fedora-checksum.verified");
    fetcher.download(FEDORA_SOURCE_URL, &image_temp)?;
    fetcher.download(FEDORA_CHECKSUM_URL, &checksum_file)?;
    fetcher.download(FEDORA_KEYRING_URL, &keyring_file)?;
    transition(&mut metadata, ImageStatus::Unverified)?;
    write_metadata_atomic(directories, &metadata)?;

    if let Err(error) =
        fetcher.verify_checksum_signature(&checksum_file, &keyring_file, &verified_checksum)
    {
        mark_invalid(directories, &mut metadata)?;
        return Err(error);
    }
    let verified_text = fs::read_to_string(&verified_checksum)?;
    let Some(expected) = checksum_for(&verified_text, FEDORA_FILENAME) else {
        mark_invalid(directories, &mut metadata)?;
        return Err(ImageError::IncompleteVerificationData);
    };
    let actual = sha256_file(&image_temp)?;
    metadata.expected_checksum = Some(expected.clone());
    metadata.actual_checksum = Some(actual.clone());
    if expected != actual {
        mark_invalid(directories, &mut metadata)?;
        return Err(ImageError::ChecksumMismatch { expected, actual });
    }
    if metadata.local_path.exists() {
        return Err(ImageError::VerifiedImageExists(metadata.local_path));
    }
    fs::rename(&image_temp, &metadata.local_path)?;
    metadata.verified_at_unix_seconds = Some(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| ImageError::Metadata(error.to_string()))?
            .as_secs(),
    );
    transition(&mut metadata, ImageStatus::Verified)?;
    write_metadata_atomic(directories, &metadata)?;
    Ok(metadata)
}

fn base_metadata(directories: &ImageDirectories, status: ImageStatus) -> ImageMetadata {
    ImageMetadata {
        distro: "Fedora Cloud Base".to_owned(),
        release: FEDORA_RELEASE.to_owned(),
        architecture: FEDORA_ARCH.to_owned(),
        source_url: FEDORA_SOURCE_URL.to_owned(),
        local_path: directories.images.join(FEDORA_FILENAME),
        expected_checksum: None,
        actual_checksum: None,
        verified_at_unix_seconds: None,
        status,
    }
}

fn transition(metadata: &mut ImageMetadata, next: ImageStatus) -> Result<(), ImageError> {
    if !can_transition(metadata.status, next) {
        return Err(ImageError::InvalidTransition {
            from: metadata.status,
            to: next,
        });
    }
    metadata.status = next;
    Ok(())
}

fn mark_invalid(
    directories: &ImageDirectories,
    metadata: &mut ImageMetadata,
) -> Result<(), ImageError> {
    transition(metadata, ImageStatus::Invalid)?;
    write_metadata_atomic(directories, metadata)
}

fn metadata_path(directories: &ImageDirectories) -> PathBuf {
    directories.images.join("fedora.metadata.json")
}

fn write_metadata_atomic(
    directories: &ImageDirectories,
    metadata: &ImageMetadata,
) -> Result<(), ImageError> {
    let destination = metadata_path(directories);
    let temporary = directories.images.join("fedora.metadata.json.tmp");
    let bytes = serde_json::to_vec_pretty(metadata)
        .map_err(|error| ImageError::Metadata(error.to_string()))?;
    fs::write(&temporary, bytes)?;
    fs::rename(temporary, destination)?;
    Ok(())
}

#[must_use]
pub fn checksum_for(contents: &str, filename: &str) -> Option<String> {
    contents.lines().find_map(|line| {
        let gnu = line
            .split_once("  ")
            .map(|(checksum, candidate)| (candidate.trim_start_matches('*'), checksum));
        let bsd = line
            .strip_prefix("SHA256 (")
            .and_then(|rest| rest.split_once(") = "));
        let (candidate, checksum) = gnu.or(bsd)?;
        (candidate == filename
            && checksum.len() == 64
            && checksum
                .chars()
                .all(|character| character.is_ascii_hexdigit()))
        .then(|| checksum.to_ascii_lowercase())
    })
}

/// Calculates a file's SHA-256 checksum.
///
/// # Errors
/// Returns an error when the file cannot be read.
pub fn sha256_file(path: &Path) -> Result<String, ImageError> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    struct TestDirectories {
        root: PathBuf,
        directories: ImageDirectories,
    }

    impl TestDirectories {
        fn new() -> Self {
            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let root =
                env::temp_dir().join(format!("forge-images-test-{}-{id}", std::process::id()));
            let directories = ImageDirectories {
                images: root.join("images"),
                downloads: root.join("downloads"),
            };
            Self { root, directories }
        }
    }

    impl Drop for TestDirectories {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    struct FixtureFetcher {
        image: Vec<u8>,
        verified_checksum: String,
        downloads: usize,
        signature_valid: bool,
    }

    impl FixtureFetcher {
        fn valid(image: &[u8]) -> Self {
            let checksum = format!("{:x}", Sha256::digest(image));
            Self {
                image: image.to_vec(),
                verified_checksum: format!("{checksum}  {FEDORA_FILENAME}\n"),
                downloads: 0,
                signature_valid: true,
            }
        }
    }

    impl ArtifactFetcher for FixtureFetcher {
        fn download(&mut self, url: &str, destination: &Path) -> Result<(), ImageError> {
            self.downloads += 1;
            if url == FEDORA_SOURCE_URL {
                fs::write(destination, &self.image)?;
            } else {
                fs::write(destination, b"fixture")?;
            }
            Ok(())
        }

        fn verify_checksum_signature(
            &mut self,
            _: &Path,
            _: &Path,
            verified_output: &Path,
        ) -> Result<(), ImageError> {
            if !self.signature_valid {
                return Err(ImageError::SignatureVerification(
                    "bad signature".to_owned(),
                ));
            }
            fs::write(verified_output, &self.verified_checksum)?;
            Ok(())
        }
    }

    #[test]
    fn image_state_machine_allows_only_safe_progression() {
        assert!(can_transition(
            ImageStatus::Missing,
            ImageStatus::Downloading
        ));
        assert!(can_transition(
            ImageStatus::Downloading,
            ImageStatus::Unverified
        ));
        assert!(can_transition(
            ImageStatus::Unverified,
            ImageStatus::Verified
        ));
        assert!(can_transition(
            ImageStatus::Unverified,
            ImageStatus::Invalid
        ));
        assert!(!can_transition(ImageStatus::Missing, ImageStatus::Verified));
        assert!(!can_transition(
            ImageStatus::Verified,
            ImageStatus::Downloading
        ));
    }

    #[test]
    fn checksum_parser_accepts_fedoras_signed_bsd_format() {
        let checksum = "28680fe5b371a5a82ebf43a31926e086a168e59949d03969c5093e7071f90b7f";
        let contents = format!("SHA256 ({FEDORA_FILENAME}) = {checksum}");
        assert_eq!(
            checksum_for(&contents, FEDORA_FILENAME).as_deref(),
            Some(checksum)
        );
    }

    #[test]
    fn matching_checksum_promotes_atomically_to_verified() {
        let test = TestDirectories::new();
        let mut fetcher = FixtureFetcher::valid(b"trusted image");
        let metadata = fetch_fedora(&test.directories, &mut fetcher).unwrap();
        assert_eq!(metadata.status, ImageStatus::Verified);
        assert!(metadata.local_path.exists());
        assert!(
            !test
                .directories
                .downloads
                .join(format!("{FEDORA_FILENAME}.part"))
                .exists()
        );
        assert_eq!(metadata.expected_checksum, metadata.actual_checksum);
    }

    #[test]
    fn incorrect_checksum_never_promotes_image() {
        let test = TestDirectories::new();
        let mut fetcher = FixtureFetcher::valid(b"actual image");
        fetcher.verified_checksum = format!("{}  {FEDORA_FILENAME}\n", "0".repeat(64));
        assert!(matches!(
            fetch_fedora(&test.directories, &mut fetcher),
            Err(ImageError::ChecksumMismatch { .. })
        ));
        assert_eq!(
            inspect(&test.directories).unwrap().status,
            ImageStatus::Invalid
        );
        assert!(!test.directories.images.join(FEDORA_FILENAME).exists());
    }

    #[test]
    fn verified_image_is_idempotent_and_not_downloaded_again() {
        let test = TestDirectories::new();
        let mut fetcher = FixtureFetcher::valid(b"trusted image");
        fetch_fedora(&test.directories, &mut fetcher).unwrap();
        let downloads = fetcher.downloads;
        let metadata = fetch_fedora(&test.directories, &mut fetcher).unwrap();
        assert_eq!(metadata.status, ImageStatus::Verified);
        assert_eq!(fetcher.downloads, downloads);
    }

    #[test]
    fn existing_verified_path_is_never_overwritten_when_corrupt() {
        let test = TestDirectories::new();
        let mut fetcher = FixtureFetcher::valid(b"trusted image");
        let metadata = fetch_fedora(&test.directories, &mut fetcher).unwrap();
        fs::write(&metadata.local_path, b"changed").unwrap();
        assert!(matches!(
            fetch_fedora(&test.directories, &mut fetcher),
            Err(ImageError::VerifiedImageExists(_))
        ));
        assert_eq!(fs::read(metadata.local_path).unwrap(), b"changed");
    }

    #[test]
    fn metadata_contains_supply_chain_fields() {
        let test = TestDirectories::new();
        let metadata = base_metadata(&test.directories, ImageStatus::Missing);
        assert_eq!(metadata.distro, "Fedora Cloud Base");
        assert_eq!(metadata.release, "44");
        assert_eq!(metadata.architecture, "x86_64");
        assert_eq!(metadata.source_url, FEDORA_SOURCE_URL);
        assert!(metadata.local_path.starts_with(&test.directories.images));
    }

    #[test]
    fn incomplete_verified_checksum_is_rejected() {
        let test = TestDirectories::new();
        let mut fetcher = FixtureFetcher::valid(b"trusted image");
        fetcher.verified_checksum = "no image checksum here\n".to_owned();
        assert!(matches!(
            fetch_fedora(&test.directories, &mut fetcher),
            Err(ImageError::IncompleteVerificationData)
        ));
        assert_eq!(
            inspect(&test.directories).unwrap().status,
            ImageStatus::Invalid
        );
    }
}
