//! Trusted base-image cache with signed-checksum verification.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

pub const FEDORA_RELEASE: &str = "44";
pub const FEDORA_ARCH: &str = "x86_64";
pub const FEDORA_FILENAME: &str = "Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2";
pub const FEDORA_SOURCE_URL: &str = "https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2";
pub const FEDORA_CHECKSUM_URL: &str = "https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/Fedora-Cloud-44-1.7-x86_64-CHECKSUM";
pub const FEDORA_KEYRING_URL: &str = "https://fedoraproject.org/fedora.gpg";
pub const KALI_RELEASE: &str = "2026.2";
pub const KALI_ARCHIVE_FILENAME: &str = "kali-linux-2026.2-qemu-amd64.7z";
pub const KALI_QCOW2_FILENAME: &str = "kali-linux-2026.2-qemu-amd64.qcow2";
pub const KALI_SOURCE_URL: &str =
    "https://cdimage.kali.org/current/kali-linux-2026.2-qemu-amd64.7z";
pub const KALI_SUMS_URL: &str = "https://cdimage.kali.org/current/SHA256SUMS";
pub const KALI_SUMS_SIGNATURE_URL: &str = "https://cdimage.kali.org/current/SHA256SUMS.gpg";
pub const KALI_KEY_URL: &str = "https://archive.kali.org/archive-key.asc";
pub const KALI_SIGNING_KEY_FINGERPRINT: &str = "827C8569F2518CC677FECA1AED65462EC8D5E4C5";

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KaliImageMetadata {
    pub release: String,
    pub architecture: String,
    pub source_url: String,
    pub archive_path: PathBuf,
    pub prepared_qcow2_path: PathBuf,
    pub authenticated_archive_checksum: Option<String>,
    pub actual_archive_checksum: Option<String>,
    pub prepared_qcow2_checksum: Option<String>,
    pub signing_key_fingerprint: String,
    pub verified_at_unix_seconds: Option<u64>,
    pub status: ImageStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KaliPreparationState {
    Missing,
    Preparing,
    Verified(Box<KaliImageMetadata>),
    InterruptedPreparation,
    OrphanedPreparedImage,
    Conflict(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct KaliPreparationIntent {
    status: String,
    archive_path: PathBuf,
    prepared_qcow2_path: PathBuf,
    authenticated_archive_checksum: String,
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
    SourceNotVerified,
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
                    "image checksum signature verification failed: {error}"
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
            Self::SourceNotVerified => formatter
                .write_str("image is not locally verified against its authenticated checksum"),
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

    /// Verifies a detached signature with a pinned signing-key fingerprint.
    ///
    /// # Errors
    /// Returns an error when the implementation cannot prove the signature and key identity.
    fn verify_detached_signature(
        &mut self,
        _checksum: &Path,
        _signature: &Path,
        _key: &Path,
        _expected_fingerprint: &str,
    ) -> Result<(), ImageError> {
        Err(ImageError::UnsupportedImage(
            "detached signature verification is unsupported".to_owned(),
        ))
    }

    /// Extracts exactly the expected qcow2 member from an archive.
    ///
    /// # Errors
    /// Returns an error for unsupported or ambiguous archive contents.
    fn extract_qcow2(
        &mut self,
        _archive: &Path,
        _expected_member: &str,
        _destination: &Path,
    ) -> Result<(), ImageError> {
        Err(ImageError::UnsupportedImage(
            "qcow2 archive extraction is unsupported".to_owned(),
        ))
    }
}

pub struct SystemArtifactFetcher;

/// Validates the file-entry section emitted by `7z l -slt`.
///
/// # Errors
/// Refuses traversal, absolute/nested paths, links, and anything other than one
/// exact flat qcow2 member.
pub fn validate_7z_listing(listing: &str, expected_member: &str) -> Result<(), ImageError> {
    if expected_member.is_empty()
        || expected_member.contains(['/', '\\'])
        || unsafe_archive_path(expected_member)
    {
        return Err(ImageError::UnsupportedImage(
            "expected archive member is not a flat relative path".to_owned(),
        ));
    }
    let normalized = listing.replace("\r\n", "\n");
    let entries = normalized
        .split_once("----------")
        .map(|(_, entries)| entries)
        .ok_or_else(|| ImageError::UnsupportedImage("7z listing has no file section".to_owned()))?;
    let mut qcow2 = Vec::new();
    let mut entry_count = 0_usize;
    for block in entries.split("\n\n") {
        let fields = block
            .lines()
            .filter_map(|line| line.split_once(" = "))
            .collect::<Vec<_>>();
        let Some(path) = fields
            .iter()
            .find_map(|(key, value)| (*key == "Path").then_some(*value))
        else {
            continue;
        };
        entry_count += 1;
        let link = fields.iter().any(|(key, value)| {
            matches!(*key, "Symbolic Link" | "Hard Link")
                || (*key == "Attributes"
                    && value
                        .split_whitespace()
                        .any(|item| item == "L" || item.starts_with('l')))
        });
        let directory = fields
            .iter()
            .any(|(key, value)| *key == "Folder" && *value == "+");
        if link || directory || unsafe_archive_path(path) || path.contains(['/', '\\']) {
            return Err(ImageError::UnsupportedImage(format!(
                "unsafe Kali archive entry: {path}"
            )));
        }
        if Path::new(path)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("qcow2"))
        {
            qcow2.push(path);
        }
    }
    if entry_count == 0 || qcow2 != [expected_member] {
        return Err(ImageError::UnsupportedImage(
            "Kali archive must contain exactly the expected qcow2".to_owned(),
        ));
    }
    Ok(())
}

fn unsafe_archive_path(path: &str) -> bool {
    path.starts_with(['/', '\\'])
        || path.as_bytes().get(1) == Some(&b':')
        || path
            .split(['/', '\\'])
            .any(|component| matches!(component, "" | "." | ".."))
}

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

    fn verify_detached_signature(
        &mut self,
        checksum: &Path,
        signature: &Path,
        key: &Path,
        expected_fingerprint: &str,
    ) -> Result<(), ImageError> {
        let keyring = key.with_extension("gpg");
        let import = Command::new("gpg")
            .args(["--batch", "--yes", "--dearmor", "--output"])
            .arg(&keyring)
            .arg(key)
            .output()?;
        if !import.status.success() {
            return Err(ImageError::SignatureVerification(
                String::from_utf8_lossy(&import.stderr).trim().to_owned(),
            ));
        }
        let inspect = Command::new("gpg")
            .args(["--batch", "--show-keys", "--with-colons"])
            .arg(&keyring)
            .output()?;
        let inspect_text = String::from_utf8_lossy(&inspect.stdout);
        let fingerprint = inspect_text.lines().find_map(|line| {
            let fields = line.split(':').collect::<Vec<_>>();
            (fields.first() == Some(&"fpr"))
                .then(|| fields.get(9).copied())
                .flatten()
        });
        if !inspect.status.success() || fingerprint != Some(expected_fingerprint) {
            return Err(ImageError::SignatureVerification(
                "Kali signing key fingerprint mismatch".to_owned(),
            ));
        }
        let verify = Command::new("gpgv")
            .arg("--keyring")
            .arg(&keyring)
            .arg(signature)
            .arg(checksum)
            .output()?;
        if verify.status.success() {
            Ok(())
        } else {
            Err(ImageError::SignatureVerification(
                String::from_utf8_lossy(&verify.stderr).trim().to_owned(),
            ))
        }
    }

    fn extract_qcow2(
        &mut self,
        archive: &Path,
        expected_member: &str,
        destination: &Path,
    ) -> Result<(), ImageError> {
        let listing = Command::new("7z")
            .args(["l", "-slt"])
            .arg(archive)
            .output()?;
        if !listing.status.success() {
            return Err(ImageError::Download(
                "cannot inspect Kali archive".to_owned(),
            ));
        }
        let listing_text = String::from_utf8_lossy(&listing.stdout);
        validate_7z_listing(&listing_text, expected_member)?;
        let output_directory = destination.parent().ok_or_else(|| {
            ImageError::Metadata("prepared image destination has no parent".to_owned())
        })?;
        let root_metadata = fs::symlink_metadata(output_directory)?;
        if !root_metadata.file_type().is_dir() || destination.exists() {
            return Err(ImageError::UnsupportedImage(
                "extraction root is not an empty controlled directory".to_owned(),
            ));
        }
        let canonical_root = fs::canonicalize(output_directory)?;
        let output = Command::new("7z")
            .arg("e")
            .arg("-y")
            .arg(format!("-o{}", output_directory.display()))
            .arg(archive)
            .arg(expected_member)
            .output()?;
        if !output.status.success() {
            return Err(ImageError::Download(
                "Kali qcow2 extraction failed".to_owned(),
            ));
        }
        validate_extracted_file(&canonical_root, destination)
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

/// Revalidates the trusted Fedora artifact against its recorded authenticated checksum.
///
/// # Errors
/// Returns an error unless metadata is Verified, both checksums agree, the file exists,
/// and a fresh SHA-256 calculation matches the authenticated checksum.
pub fn verified_fedora(directories: &ImageDirectories) -> Result<ImageMetadata, ImageError> {
    let metadata = inspect(directories)?;
    let expected = metadata
        .expected_checksum
        .as_deref()
        .ok_or(ImageError::SourceNotVerified)?;
    if metadata.status != ImageStatus::Verified
        || metadata.actual_checksum.as_deref() != Some(expected)
        || !metadata.local_path.is_file()
        || sha256_file(&metadata.local_path)? != expected
    {
        return Err(ImageError::SourceNotVerified);
    }
    Ok(metadata)
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

/// Fetches, authenticates, and extracts the official Kali QEMU image.
///
/// Trust is anchored in the pinned Kali archive-key fingerprint. The detached
/// signature authenticates SHA256SUMS, which authenticates the 7z archive; the
/// prepared qcow2 digest records the exact single member extracted from it.
///
/// # Errors
///
/// Refuses signature, fingerprint, checksum, archive-shape, and overwrite failures.
pub fn fetch_kali<F: ArtifactFetcher>(
    directories: &ImageDirectories,
    fetcher: &mut F,
) -> Result<KaliImageMetadata, ImageError> {
    fs::create_dir_all(&directories.images)?;
    fs::create_dir_all(&directories.downloads)?;
    match inspect_kali_preparation(directories)? {
        KaliPreparationState::Missing => {}
        KaliPreparationState::Verified(_) => return verified_kali(directories),
        state => {
            return Err(ImageError::Metadata(format!(
                "Kali image preparation requires explicit recovery: {state:?}"
            )));
        }
    }
    let archive = directories.downloads.join(KALI_ARCHIVE_FILENAME);
    let sums = directories.downloads.join("kali-SHA256SUMS");
    let signature = directories.downloads.join("kali-SHA256SUMS.gpg");
    let key = directories.downloads.join("kali-archive-key.asc");
    let prepared = directories.images.join(KALI_QCOW2_FILENAME);
    fetcher.download(KALI_SOURCE_URL, &archive)?;
    fetcher.download(KALI_SUMS_URL, &sums)?;
    fetcher.download(KALI_SUMS_SIGNATURE_URL, &signature)?;
    fetcher.download(KALI_KEY_URL, &key)?;
    fetcher.verify_detached_signature(&sums, &signature, &key, KALI_SIGNING_KEY_FINGERPRINT)?;
    let authenticated_sums = fs::read_to_string(&sums)?;
    let expected = checksum_for(&authenticated_sums, KALI_ARCHIVE_FILENAME)
        .ok_or(ImageError::IncompleteVerificationData)?;
    let actual = sha256_file(&archive)?;
    if !is_single_regular_file(&archive) {
        return Err(ImageError::UnsupportedImage(
            "verified Kali archive is not one regular file".to_owned(),
        ));
    }
    if expected != actual {
        return Err(ImageError::ChecksumMismatch { expected, actual });
    }
    let intent = KaliPreparationIntent {
        status: "Preparing".to_owned(),
        archive_path: archive.clone(),
        prepared_qcow2_path: prepared.clone(),
        authenticated_archive_checksum: expected.clone(),
    };
    write_kali_intent_atomic(directories, &intent)?;
    let extraction_root = create_extraction_root(&directories.downloads)?;
    let extracted = extraction_root.join(KALI_QCOW2_FILENAME);
    let extraction = (|| {
        fetcher.extract_qcow2(&archive, KALI_QCOW2_FILENAME, &extracted)?;
        let canonical_root = fs::canonicalize(&extraction_root)?;
        validate_extracted_file(&canonical_root, &extracted)?;

        // Re-read the authenticated input after extraction so a concurrent or
        // faulty extractor cannot silently change the verified archive.
        let archive_after_extraction = sha256_file(&archive)?;
        if archive_after_extraction != expected {
            return Err(ImageError::ChecksumMismatch {
                expected: expected.clone(),
                actual: archive_after_extraction,
            });
        }
        let extracted_checksum = sha256_file(&extracted)?;
        promote_without_overwrite(&extracted, &prepared, &extracted_checksum)?;
        Ok(extracted_checksum)
    })();
    let cleanup = cleanup_extraction_root(&directories.downloads, &extraction_root);
    let prepared_checksum = match (extraction, cleanup) {
        (Ok(checksum), Ok(())) => checksum,
        (Err(error), Ok(())) => {
            clear_kali_intent(directories)?;
            return Err(error);
        }
        (Err(error), Err(_)) | (Ok(_), Err(error)) => return Err(error),
    };
    let metadata = KaliImageMetadata {
        release: KALI_RELEASE.to_owned(),
        architecture: "x86_64".to_owned(),
        source_url: KALI_SOURCE_URL.to_owned(),
        archive_path: archive,
        prepared_qcow2_path: prepared,
        authenticated_archive_checksum: Some(expected),
        actual_archive_checksum: Some(actual),
        prepared_qcow2_checksum: Some(prepared_checksum),
        signing_key_fingerprint: KALI_SIGNING_KEY_FINGERPRINT.to_owned(),
        verified_at_unix_seconds: Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|error| ImageError::Metadata(error.to_string()))?
                .as_secs(),
        ),
        status: ImageStatus::Verified,
    };
    write_kali_metadata_atomic(directories, &metadata)?;
    clear_kali_intent(directories)?;
    Ok(metadata)
}

/// Classifies on-disk Kali preparation without trusting an orphan by name.
///
/// # Errors
/// Returns an error only when filesystem inspection itself cannot be completed.
pub fn inspect_kali_preparation(
    directories: &ImageDirectories,
) -> Result<KaliPreparationState, ImageError> {
    let metadata_path = directories.images.join("kali.metadata.json");
    let metadata_temporary_path = directories.images.join("kali.metadata.json.tmp");
    let prepared = directories.images.join(KALI_QCOW2_FILENAME);
    let intent_path = kali_intent_path(directories);
    let temporary_roots = kali_extraction_roots(&directories.downloads)?;

    if fs::symlink_metadata(&metadata_path).is_ok() {
        return match verified_kali(directories) {
            Ok(metadata) => Ok(KaliPreparationState::Verified(Box::new(metadata))),
            Err(error) => Ok(KaliPreparationState::Conflict(error.to_string())),
        };
    }
    if fs::symlink_metadata(&prepared).is_ok() {
        if !is_single_regular_file(&prepared) {
            return Ok(KaliPreparationState::Conflict(
                "orphaned prepared path is not one regular file".to_owned(),
            ));
        }
        return Ok(KaliPreparationState::OrphanedPreparedImage);
    }
    if fs::symlink_metadata(&intent_path).is_ok()
        || fs::symlink_metadata(&metadata_temporary_path).is_ok()
        || !temporary_roots.is_empty()
    {
        if temporary_roots.len() > 1 {
            return Ok(KaliPreparationState::Conflict(
                "multiple Kali extraction roots exist".to_owned(),
            ));
        }
        if temporary_roots.iter().any(|root| {
            fs::symlink_metadata(root).map_or(true, |metadata| !metadata.file_type().is_dir())
        }) {
            return Ok(KaliPreparationState::Conflict(
                "Kali extraction root is not a directory".to_owned(),
            ));
        }
        if fs::symlink_metadata(&intent_path).is_ok() {
            let Some(intent) = fs::read(&intent_path)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<KaliPreparationIntent>(&bytes).ok())
            else {
                return Ok(KaliPreparationState::Conflict(
                    "Kali preparation intent is corrupt".to_owned(),
                ));
            };
            if intent.status != "Preparing"
                || intent.archive_path != directories.downloads.join(KALI_ARCHIVE_FILENAME)
                || intent.prepared_qcow2_path != prepared
                || intent.authenticated_archive_checksum.len() != 64
                || !intent
                    .authenticated_archive_checksum
                    .chars()
                    .all(|character| character.is_ascii_hexdigit())
            {
                return Ok(KaliPreparationState::Conflict(
                    "Kali preparation intent identity is inconsistent".to_owned(),
                ));
            }
        }
        return Ok(KaliPreparationState::InterruptedPreparation);
    }
    Ok(KaliPreparationState::Missing)
}

/// Reads Kali metadata without treating absence as trust.
///
/// # Errors
/// Returns an error for unreadable or corrupt metadata.
pub fn inspect_kali(
    directories: &ImageDirectories,
) -> Result<Option<KaliImageMetadata>, ImageError> {
    let path = directories.images.join("kali.metadata.json");
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| ImageError::Metadata(error.to_string())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Revalidates both the authenticated archive and its exact extracted qcow2.
///
/// # Errors
/// Refuses missing, unverified, changed, or incomplete Kali image state.
pub fn verified_kali(directories: &ImageDirectories) -> Result<KaliImageMetadata, ImageError> {
    let metadata = inspect_kali(directories)?.ok_or(ImageError::SourceNotVerified)?;
    let expected_archive_path = directories.downloads.join(KALI_ARCHIVE_FILENAME);
    let expected_prepared_path = directories.images.join(KALI_QCOW2_FILENAME);
    let archive = metadata
        .authenticated_archive_checksum
        .as_deref()
        .ok_or(ImageError::SourceNotVerified)?;
    let prepared = metadata
        .prepared_qcow2_checksum
        .as_deref()
        .ok_or(ImageError::SourceNotVerified)?;
    if metadata.status != ImageStatus::Verified
        || metadata.signing_key_fingerprint != KALI_SIGNING_KEY_FINGERPRINT
        || metadata.archive_path != expected_archive_path
        || metadata.prepared_qcow2_path != expected_prepared_path
        || metadata.actual_archive_checksum.as_deref() != Some(archive)
        || !is_single_regular_file(&metadata.archive_path)
        || !is_single_regular_file(&metadata.prepared_qcow2_path)
        || sha256_file(&metadata.archive_path)? != archive
        || sha256_file(&metadata.prepared_qcow2_path)? != prepared
    {
        return Err(ImageError::SourceNotVerified);
    }
    Ok(metadata)
}

fn create_extraction_root(downloads: &Path) -> Result<PathBuf, ImageError> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| ImageError::Metadata(error.to_string()))?
        .as_nanos();
    let root = downloads.join(format!(".kali-extract-{}-{nonce}", std::process::id()));
    fs::create_dir(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    sync_directory(&root)?;
    sync_directory(downloads)?;
    Ok(root)
}

fn kali_extraction_roots(downloads: &Path) -> Result<Vec<PathBuf>, ImageError> {
    let entries = match fs::read_dir(downloads) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut roots = Vec::new();
    for entry in entries {
        let entry = entry?;
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(".kali-extract-"))
        {
            roots.push(entry.path());
        }
    }
    roots.sort();
    Ok(roots)
}

fn cleanup_extraction_root(downloads: &Path, root: &Path) -> Result<(), ImageError> {
    let controlled_name = root
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with(".kali-extract-"));
    if root.parent() != Some(downloads) || !controlled_name {
        return Err(ImageError::Metadata(
            "refusing to clean an uncontrolled extraction path".to_owned(),
        ));
    }
    match fs::remove_dir_all(root) {
        Ok(()) => sync_directory(downloads),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn validate_extracted_file(canonical_root: &Path, destination: &Path) -> Result<(), ImageError> {
    let metadata = fs::symlink_metadata(destination)?;
    let canonical_destination = fs::canonicalize(destination)?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || canonical_destination.parent() != Some(canonical_root)
        || !canonical_destination.starts_with(canonical_root)
    {
        return Err(ImageError::UnsupportedImage(
            "extracted Kali qcow2 is not one regular file inside the controlled root".to_owned(),
        ));
    }
    Ok(())
}

fn is_single_regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .is_ok_and(|metadata| metadata.file_type().is_file() && metadata.nlink() == 1)
}

fn promote_without_overwrite(
    source: &Path,
    destination: &Path,
    expected_checksum: &str,
) -> Result<(), ImageError> {
    let source_metadata = fs::symlink_metadata(source)?;
    let destination_parent = destination.parent().ok_or_else(|| {
        ImageError::Metadata("prepared Kali destination has no parent".to_owned())
    })?;
    let destination_parent_metadata = fs::symlink_metadata(destination_parent)?;
    if !source_metadata.file_type().is_file()
        || source_metadata.nlink() != 1
        || !destination_parent_metadata.file_type().is_dir()
        || source_metadata.dev() != destination_parent_metadata.dev()
    {
        return Err(ImageError::UnsupportedImage(
            "Kali promotion requires one regular source on the prepared filesystem".to_owned(),
        ));
    }
    File::open(source)?.sync_all()?;
    match fs::hard_link(source, destination) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            return Err(ImageError::VerifiedImageExists(destination.to_owned()));
        }
        Err(error) => return Err(error.into()),
    }
    sync_directory(destination_parent)?;
    if let Err(error) = fs::remove_file(source) {
        let _ = fs::remove_file(destination);
        let _ = sync_directory(destination_parent);
        return Err(error.into());
    }
    let source_parent = source
        .parent()
        .ok_or_else(|| ImageError::Metadata("extracted Kali source has no parent".to_owned()))?;
    sync_directory(source_parent)?;
    if !is_single_regular_file(destination) {
        return Err(ImageError::UnsupportedImage(
            "promoted Kali qcow2 is not one regular file".to_owned(),
        ));
    }
    let actual = sha256_file(destination)?;
    if actual != expected_checksum {
        return Err(ImageError::ChecksumMismatch {
            expected: expected_checksum.to_owned(),
            actual,
        });
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), ImageError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn kali_intent_path(directories: &ImageDirectories) -> PathBuf {
    directories.images.join("kali.preparation.json")
}

fn write_kali_intent_atomic(
    directories: &ImageDirectories,
    intent: &KaliPreparationIntent,
) -> Result<(), ImageError> {
    write_json_atomic(
        &directories.images,
        "kali.preparation.json.tmp",
        "kali.preparation.json",
        intent,
    )
}

fn clear_kali_intent(directories: &ImageDirectories) -> Result<(), ImageError> {
    let path = kali_intent_path(directories);
    match fs::remove_file(path) {
        Ok(()) => sync_directory(&directories.images),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn write_kali_metadata_atomic(
    directories: &ImageDirectories,
    metadata: &KaliImageMetadata,
) -> Result<(), ImageError> {
    write_json_atomic(
        &directories.images,
        "kali.metadata.json.tmp",
        "kali.metadata.json",
        metadata,
    )
}

fn write_json_atomic<T: Serialize>(
    directory: &Path,
    temporary_name: &str,
    destination_name: &str,
    value: &T,
) -> Result<(), ImageError> {
    let temporary = directory.join(temporary_name);
    let destination = directory.join(destination_name);
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| ImageError::Metadata(error.to_string()))?;
    let mut file = File::create(&temporary)?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, &destination)?;
    sync_directory(directory)
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

/// Reads the virtual capacity from a qcow2 v1+ header without invoking QEMU.
///
/// # Errors
/// Returns an error when the file is unreadable, truncated, not qcow2, or has zero capacity.
pub fn qcow2_virtual_size(path: &Path) -> Result<u64, ImageError> {
    let mut file = File::open(path)?;
    let mut header = [0_u8; 32];
    file.read_exact(&mut header)?;
    if &header[..4] != b"QFI\xfb" {
        return Err(ImageError::Metadata("source is not qcow2".to_owned()));
    }
    let size = u64::from_be_bytes(
        header[24..32]
            .try_into()
            .map_err(|_| ImageError::Metadata("truncated qcow2 header".to_owned()))?,
    );
    if size == 0 {
        return Err(ImageError::Metadata(
            "qcow2 virtual size is zero".to_owned(),
        ));
    }
    Ok(size)
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
        extracted: Vec<u8>,
        verified_checksum: String,
        downloads: usize,
        signature_valid: bool,
        partial_extraction_failure: bool,
    }

    impl FixtureFetcher {
        fn valid(image: &[u8]) -> Self {
            let checksum = format!("{:x}", Sha256::digest(image));
            Self {
                image: image.to_vec(),
                extracted: image.to_vec(),
                verified_checksum: format!("{checksum}  {FEDORA_FILENAME}\n"),
                downloads: 0,
                signature_valid: true,
                partial_extraction_failure: false,
            }
        }
    }

    impl ArtifactFetcher for FixtureFetcher {
        fn download(&mut self, url: &str, destination: &Path) -> Result<(), ImageError> {
            self.downloads += 1;
            if matches!(url, FEDORA_SOURCE_URL | KALI_SOURCE_URL) {
                fs::write(destination, &self.image)?;
            } else if url == KALI_SUMS_URL {
                let checksum = self
                    .verified_checksum
                    .split_whitespace()
                    .next()
                    .expect("fixture checksum exists");
                fs::write(
                    destination,
                    format!("{checksum}  {KALI_ARCHIVE_FILENAME}\n"),
                )?;
            } else {
                fs::write(destination, b"fixture")?;
            }
            Ok(())
        }

        fn verify_detached_signature(
            &mut self,
            _: &Path,
            _: &Path,
            _: &Path,
            expected_fingerprint: &str,
        ) -> Result<(), ImageError> {
            if self.signature_valid && expected_fingerprint == KALI_SIGNING_KEY_FINGERPRINT {
                Ok(())
            } else {
                Err(ImageError::SignatureVerification(
                    "bad signature".to_owned(),
                ))
            }
        }

        fn extract_qcow2(
            &mut self,
            _: &Path,
            expected_member: &str,
            destination: &Path,
        ) -> Result<(), ImageError> {
            if expected_member != KALI_QCOW2_FILENAME {
                return Err(ImageError::UnsupportedImage(expected_member.to_owned()));
            }
            if self.partial_extraction_failure {
                fs::write(destination, b"partial")?;
                return Err(ImageError::Download(
                    "simulated interrupted extraction".to_owned(),
                ));
            }
            fs::write(destination, &self.extracted)?;
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
    fn kali_detached_signature_and_archive_checksum_produce_verified_qcow2() {
        let test = TestDirectories::new();
        let mut fetcher = FixtureFetcher::valid(b"trusted kali archive");
        fetcher.extracted = b"prepared qcow2".to_vec();
        let metadata = fetch_kali(&test.directories, &mut fetcher).unwrap();
        assert_eq!(metadata.status, ImageStatus::Verified);
        assert_eq!(
            metadata.signing_key_fingerprint,
            KALI_SIGNING_KEY_FINGERPRINT
        );
        assert_eq!(verified_kali(&test.directories).unwrap(), metadata);
    }

    fn seven_zip_listing(entries: &[&str]) -> String {
        format!("7-Zip fixture\n----------\n{}", entries.join("\n\n"))
    }

    #[test]
    fn kali_archive_listing_accepts_one_flat_regular_qcow2() {
        let listing = seven_zip_listing(&[&format!(
            "Path = {KALI_QCOW2_FILENAME}\nFolder = -\nAttributes = A_ -rw-r--r--"
        )]);
        assert!(validate_7z_listing(&listing, KALI_QCOW2_FILENAME).is_ok());
    }

    #[test]
    fn kali_archive_listing_refuses_traversal_absolute_and_nested_paths() {
        for path in [
            &format!("../{KALI_QCOW2_FILENAME}"),
            &format!("/{KALI_QCOW2_FILENAME}"),
            &format!("C:\\{KALI_QCOW2_FILENAME}"),
            &format!("nested/{KALI_QCOW2_FILENAME}"),
        ] {
            let listing = seven_zip_listing(&[&format!("Path = {path}\nFolder = -")]);
            assert!(matches!(
                validate_7z_listing(&listing, KALI_QCOW2_FILENAME),
                Err(ImageError::UnsupportedImage(_))
            ));
        }
    }

    #[test]
    fn kali_archive_listing_refuses_symbolic_and_hard_links() {
        for link_field in [
            "Symbolic Link = outside.qcow2",
            "Hard Link = outside.qcow2",
            "Attributes = A_ lrwxrwxrwx",
        ] {
            let listing = seven_zip_listing(&[&format!(
                "Path = {KALI_QCOW2_FILENAME}\nFolder = -\n{link_field}"
            )]);
            assert!(matches!(
                validate_7z_listing(&listing, KALI_QCOW2_FILENAME),
                Err(ImageError::UnsupportedImage(_))
            ));
        }
    }

    #[test]
    fn kali_archive_listing_refuses_multiple_or_missing_qcow2_members() {
        let multiple = seven_zip_listing(&[
            &format!("Path = {KALI_QCOW2_FILENAME}\nFolder = -"),
            "Path = second.qcow2\nFolder = -",
        ]);
        let missing = seven_zip_listing(&["Path = README.txt\nFolder = -"]);
        for listing in [multiple, missing] {
            assert!(matches!(
                validate_7z_listing(&listing, KALI_QCOW2_FILENAME),
                Err(ImageError::UnsupportedImage(_))
            ));
        }
    }

    #[test]
    fn interrupted_kali_extraction_never_promotes_and_cleans_controlled_temp() {
        let test = TestDirectories::new();
        let mut fetcher = FixtureFetcher::valid(b"trusted kali archive");
        fetcher.partial_extraction_failure = true;
        assert!(matches!(
            fetch_kali(&test.directories, &mut fetcher),
            Err(ImageError::Download(_))
        ));
        assert!(!test.directories.images.join(KALI_QCOW2_FILENAME).exists());
        assert!(inspect_kali(&test.directories).unwrap().is_none());
        let extraction_roots = fs::read_dir(&test.directories.downloads)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".kali-extract-")
            })
            .count();
        assert_eq!(extraction_roots, 0);
    }

    #[test]
    fn existing_untrusted_prepared_base_is_never_overwritten() {
        let test = TestDirectories::new();
        fs::create_dir_all(&test.directories.images).unwrap();
        let prepared = test.directories.images.join(KALI_QCOW2_FILENAME);
        fs::write(&prepared, b"existing conflict").unwrap();
        let mut fetcher = FixtureFetcher::valid(b"trusted kali archive");
        assert!(matches!(
            fetch_kali(&test.directories, &mut fetcher),
            Err(ImageError::Metadata(message))
                if message.contains("explicit recovery")
        ));
        assert_eq!(fs::read(prepared).unwrap(), b"existing conflict");
        assert_eq!(fetcher.downloads, 0);
    }

    #[test]
    fn prepared_promotion_is_atomic_no_clobber_without_large_file_copy() {
        let test = TestDirectories::new();
        fs::create_dir_all(&test.directories.downloads).unwrap();
        fs::create_dir_all(&test.directories.images).unwrap();
        let source = test.directories.downloads.join("extracted.qcow2");
        let destination = test.directories.images.join("prepared.qcow2");
        fs::write(&source, b"verified extracted image").unwrap();
        let source_inode = fs::metadata(&source).unwrap().ino();
        let checksum = sha256_file(&source).unwrap();

        promote_without_overwrite(&source, &destination, &checksum).unwrap();

        assert!(!source.exists());
        let destination_metadata = fs::metadata(&destination).unwrap();
        assert_eq!(destination_metadata.ino(), source_inode);
        assert_eq!(destination_metadata.nlink(), 1);
        assert_eq!(sha256_file(&destination).unwrap(), checksum);
    }

    fn crash_fixture(test: &TestDirectories) -> KaliImageMetadata {
        fs::create_dir_all(&test.directories.downloads).unwrap();
        fs::create_dir_all(&test.directories.images).unwrap();
        let archive = test.directories.downloads.join(KALI_ARCHIVE_FILENAME);
        let prepared = test.directories.images.join(KALI_QCOW2_FILENAME);
        fs::write(&archive, b"authenticated archive").unwrap();
        fs::write(&prepared, b"prepared qcow2").unwrap();
        let archive_checksum = sha256_file(&archive).unwrap();
        let prepared_checksum = sha256_file(&prepared).unwrap();
        KaliImageMetadata {
            release: KALI_RELEASE.to_owned(),
            architecture: "x86_64".to_owned(),
            source_url: KALI_SOURCE_URL.to_owned(),
            archive_path: archive,
            prepared_qcow2_path: prepared.clone(),
            authenticated_archive_checksum: Some(archive_checksum.clone()),
            actual_archive_checksum: Some(archive_checksum),
            prepared_qcow2_checksum: Some(prepared_checksum),
            signing_key_fingerprint: KALI_SIGNING_KEY_FINGERPRINT.to_owned(),
            verified_at_unix_seconds: Some(1),
            status: ImageStatus::Verified,
        }
    }

    #[test]
    fn crash_before_final_link_is_interrupted_and_never_trusted() {
        let test = TestDirectories::new();
        fs::create_dir_all(&test.directories.images).unwrap();
        fs::create_dir_all(&test.directories.downloads).unwrap();
        let root = test.directories.downloads.join(".kali-extract-crash");
        fs::create_dir(&root).unwrap();
        fs::write(root.join(KALI_QCOW2_FILENAME), b"partial or complete").unwrap();
        assert_eq!(
            inspect_kali_preparation(&test.directories).unwrap(),
            KaliPreparationState::InterruptedPreparation
        );
    }

    #[test]
    fn crash_after_final_link_before_unlink_is_conflict_not_trust() {
        let test = TestDirectories::new();
        fs::create_dir_all(&test.directories.images).unwrap();
        fs::create_dir_all(&test.directories.downloads).unwrap();
        let root = test.directories.downloads.join(".kali-extract-crash");
        fs::create_dir(&root).unwrap();
        let extracted = root.join(KALI_QCOW2_FILENAME);
        let prepared = test.directories.images.join(KALI_QCOW2_FILENAME);
        fs::write(&extracted, b"complete").unwrap();
        fs::hard_link(&extracted, &prepared).unwrap();
        assert!(matches!(
            inspect_kali_preparation(&test.directories).unwrap(),
            KaliPreparationState::Conflict(_)
        ));
    }

    #[test]
    fn crash_after_unlink_before_metadata_is_orphaned_not_trust() {
        let test = TestDirectories::new();
        crash_fixture(&test);
        assert_eq!(
            inspect_kali_preparation(&test.directories).unwrap(),
            KaliPreparationState::OrphanedPreparedImage
        );
    }

    #[test]
    fn crash_after_metadata_temp_write_is_orphaned_not_trust() {
        let test = TestDirectories::new();
        let metadata = crash_fixture(&test);
        fs::write(
            test.directories.images.join("kali.metadata.json.tmp"),
            serde_json::to_vec_pretty(&metadata).unwrap(),
        )
        .unwrap();
        assert_eq!(
            inspect_kali_preparation(&test.directories).unwrap(),
            KaliPreparationState::OrphanedPreparedImage
        );
    }

    #[test]
    fn crash_after_metadata_publish_is_verified_by_exact_identity() {
        let test = TestDirectories::new();
        let metadata = crash_fixture(&test);
        write_kali_metadata_atomic(&test.directories, &metadata).unwrap();
        assert_eq!(
            inspect_kali_preparation(&test.directories).unwrap(),
            KaliPreparationState::Verified(Box::new(metadata))
        );
    }

    #[test]
    fn kali_signature_or_checksum_mismatch_never_becomes_trusted() {
        let test = TestDirectories::new();
        let mut bad_signature = FixtureFetcher::valid(b"archive");
        bad_signature.signature_valid = false;
        assert!(matches!(
            fetch_kali(&test.directories, &mut bad_signature),
            Err(ImageError::SignatureVerification(_))
        ));
        assert!(inspect_kali(&test.directories).unwrap().is_none());

        let test = TestDirectories::new();
        let mut mismatch = FixtureFetcher::valid(b"archive");
        mismatch.image = b"changed after checksum construction".to_vec();
        assert!(matches!(
            fetch_kali(&test.directories, &mut mismatch),
            Err(ImageError::ChecksumMismatch { .. })
        ));
        assert!(inspect_kali(&test.directories).unwrap().is_none());
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

    #[test]
    fn verified_source_is_rehashed_before_use() {
        let test = TestDirectories::new();
        let mut fetcher = FixtureFetcher::valid(b"trusted image");
        let metadata = fetch_fedora(&test.directories, &mut fetcher).unwrap();
        assert_eq!(verified_fedora(&test.directories).unwrap(), metadata);
        fs::write(&metadata.local_path, b"tampered").unwrap();
        assert!(matches!(
            verified_fedora(&test.directories),
            Err(ImageError::SourceNotVerified)
        ));
    }

    #[test]
    fn reads_qcow2_virtual_capacity_from_header() {
        let test = TestDirectories::new();
        fs::create_dir_all(&test.directories.downloads).unwrap();
        let path = test.directories.downloads.join("header.qcow2");
        let mut header = [0_u8; 32];
        header[..4].copy_from_slice(b"QFI\xfb");
        header[4..8].copy_from_slice(&3_u32.to_be_bytes());
        header[24..32].copy_from_slice(&(5 * 1024_u64.pow(3)).to_be_bytes());
        fs::write(&path, header).unwrap();
        assert_eq!(qcow2_virtual_size(&path).unwrap(), 5 * 1024_u64.pow(3));
    }
}
