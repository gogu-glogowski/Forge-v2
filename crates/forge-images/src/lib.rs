//! Trusted base-image cache with signed-checksum verification.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::env;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
pub const WHONIX_RELEASE: &str = "18.2.1.9";
pub const WHONIX_ARCHIVE_FILENAME: &str = "Whonix-LXQt-18.2.1.9.Intel_AMD64.qcow2.libvirt.xz";
pub const WHONIX_SOURCE_URL: &str = "https://www.whonix.org/download/libvirt/18.2.1.9/Whonix-LXQt-18.2.1.9.Intel_AMD64.qcow2.libvirt.xz";
pub const WHONIX_SIGNATURE_URL: &str = "https://www.whonix.org/download/libvirt/18.2.1.9/Whonix-LXQt-18.2.1.9.Intel_AMD64.qcow2.libvirt.xz.asc";
pub const WHONIX_SHA512SUMS_URL: &str = "https://www.whonix.org/download/libvirt/18.2.1.9/Whonix-LXQt-18.2.1.9.Intel_AMD64.qcow2.libvirt.xz.sha512sums";
pub const WHONIX_SHA512SUMS_SIGNIFY_URL: &str = "https://www.whonix.org/download/libvirt/18.2.1.9/Whonix-LXQt-18.2.1.9.Intel_AMD64.qcow2.libvirt.xz.sha512sums.sig";
pub const WHONIX_SIGNING_KEY_URL: &str = "https://www.whonix.org/keys/derivative.asc";
pub const WHONIX_SIGNING_KEY_FINGERPRINT: &str = "916B8D99C38EAF5E8ADC7A2A8D66066A2EEACCDA";
pub const WHONIX_SIGNATURE_NOTATION: &str =
    "file@name=Whonix-LXQt-18.2.1.9.Intel_AMD64.qcow2.libvirt.xz";
pub const WHONIX_RELEASE_SIGNATURE_NOT_BEFORE: u64 = 1_784_073_600;
pub const WHONIX_GATEWAY_DISK_FILENAME: &str = "Whonix-Gateway-LXQt-18.2.1.9.Intel_AMD64.qcow2";
pub const WHONIX_GATEWAY_XML_FILENAME: &str = "Whonix-Gateway.xml";
pub const WHONIX_WORKSTATION_DISK_FILENAME: &str =
    "Whonix-Workstation-LXQt-18.2.1.9.Intel_AMD64.qcow2";
pub const WHONIX_WORKSTATION_XML_FILENAME: &str = "Whonix-Workstation.xml";
pub const WHONIX_WORKSTATION_VIRTUAL_BYTES: u64 = 100 * 1024 * 1024 * 1024;
pub const WHONIX_LICENSE_FILENAME: &str = "WHONIX_BINARY_LICENSE_AGREEMENT";
pub const WHONIX_DISCLAIMER_FILENAME: &str = "WHONIX_DISCLAIMER";
const WHONIX_TAR_EXTRACTION_OPTIONS: &[&str] = &[
    "--extract",
    "--xz",
    "--no-same-owner",
    "--no-same-permissions",
    "--no-xattrs",
    "--no-acls",
    "--no-selinux",
    "--touch",
    "--keep-old-files",
    "--no-wildcards",
    "--no-unquote",
    "--file",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum BundleArtifactRole {
    GatewayDisk,
    GatewayXml,
    WorkstationDisk,
    WorkstationXml,
    License,
    Disclaimer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveEntryKind {
    RegularFile,
    Directory,
    SymbolicLink,
    HardLink,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FullReadOperation {
    ArchiveHash,
    ArchiveOpenPgpVerification,
    ArchiveListing,
    ArchiveExtraction,
    GatewayHash,
    WorkstationHash,
    ExtractedBundleArtifactHash(BundleArtifactRole),
    WorkstationImport,
    OtherHash,
}

thread_local! {
    static FULL_READ_AUDIT: RefCell<Option<Vec<FullReadOperation>>> = const { RefCell::new(None) };
}

/// Runs one operation with a thread-local logical full-read audit.
/// Intended for performance-contract tests; it does not measure wall time.
pub fn audit_full_reads<T>(operation: impl FnOnce() -> T) -> (T, Vec<FullReadOperation>) {
    FULL_READ_AUDIT.with(|audit| *audit.borrow_mut() = Some(Vec::new()));
    let result = operation();
    let reads = FULL_READ_AUDIT.with(|audit| audit.borrow_mut().take().unwrap_or_default());
    (result, reads)
}

#[doc(hidden)]
pub fn record_full_read(operation: FullReadOperation) {
    FULL_READ_AUDIT.with(|audit| {
        if let Some(reads) = audit.borrow_mut().as_mut() {
            reads.push(operation);
        }
    });
}

/// Exact local filesystem identity captured around a byte-backed verification.
/// It is deliberately process-local evidence, not a metadata-only trust grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedFileIdentity {
    path: PathBuf,
    device: u64,
    inode: u64,
    bytes: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
    mode: u32,
    links: u64,
}

/// Byte-backed Workstation proof that may only be reused while every input
/// retains the exact filesystem identity observed during verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhonixWorkstationExecuteProof {
    metadata: WhonixGatewayImageMetadata,
    files: Vec<VerifiedFileIdentity>,
}

struct LifecycleVerifiedFile {
    file: File,
    identity: VerifiedFileIdentity,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveEntry {
    pub path: String,
    pub kind: ArchiveEntryKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedBundleEntry {
    pub role: BundleArtifactRole,
    pub path: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhonixBundleProvenance {
    pub release: String,
    pub archive_filename: String,
    pub source_url: String,
    pub signer_fingerprint: String,
    pub signature_notation: String,
    pub signature_unix_seconds: u64,
    pub archive_sha256: String,
    pub artifact_sha256: Vec<(BundleArtifactRole, String)>,
    pub bundle_identity_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhonixSignatureEvidence {
    pub signature_valid: bool,
    pub primary_signer_fingerprint: String,
    pub notation: String,
    pub signature_unix_seconds: u64,
}

#[must_use]
pub fn whonix_bundle_layout() -> Vec<ExpectedBundleEntry> {
    vec![
        ExpectedBundleEntry {
            role: BundleArtifactRole::GatewayDisk,
            path: WHONIX_GATEWAY_DISK_FILENAME,
        },
        ExpectedBundleEntry {
            role: BundleArtifactRole::GatewayXml,
            path: WHONIX_GATEWAY_XML_FILENAME,
        },
        ExpectedBundleEntry {
            role: BundleArtifactRole::WorkstationDisk,
            path: WHONIX_WORKSTATION_DISK_FILENAME,
        },
        ExpectedBundleEntry {
            role: BundleArtifactRole::WorkstationXml,
            path: WHONIX_WORKSTATION_XML_FILENAME,
        },
        ExpectedBundleEntry {
            role: BundleArtifactRole::License,
            path: WHONIX_LICENSE_FILENAME,
        },
        ExpectedBundleEntry {
            role: BundleArtifactRole::Disclaimer,
            path: WHONIX_DISCLAIMER_FILENAME,
        },
    ]
}

/// Validates the complete flat allowlist emitted by the official Whonix
/// release builder. No path or file type is inferred from a basename pattern.
///
/// # Errors
/// Refuses missing, duplicate, additional, nested, absolute, traversal, link,
/// directory, or other non-regular entries.
pub fn validate_whonix_bundle_entries(
    entries: &[ArchiveEntry],
) -> Result<Vec<(BundleArtifactRole, String)>, ImageError> {
    let expected = whonix_bundle_layout();
    if entries.len() != expected.len() {
        return Err(ImageError::UnsupportedImage(
            "Whonix bundle entry count differs from the official layout".to_owned(),
        ));
    }
    let mut identified = Vec::with_capacity(expected.len());
    for entry in entries {
        if entry.kind != ArchiveEntryKind::RegularFile
            || unsafe_archive_path(&entry.path)
            || entry.path.contains(['/', '\\'])
        {
            return Err(ImageError::UnsupportedImage(format!(
                "unsafe Whonix bundle entry: {}",
                entry.path
            )));
        }
        let Some(contract) = expected.iter().find(|item| item.path == entry.path) else {
            return Err(ImageError::UnsupportedImage(format!(
                "unexpected Whonix bundle entry: {}",
                entry.path
            )));
        };
        if identified
            .iter()
            .any(|(role, _): &(BundleArtifactRole, String)| *role == contract.role)
        {
            return Err(ImageError::UnsupportedImage(format!(
                "duplicate Whonix bundle role: {:?}",
                contract.role
            )));
        }
        identified.push((contract.role, entry.path.clone()));
    }
    identified.sort_by_key(|(role, _)| *role);
    Ok(identified)
}

/// Validates detached-signature evidence according to current upstream
/// requirements, including pinned primary signer, exact filename notation,
/// release floor, future-time refusal and rollback prevention.
///
/// # Errors
/// Returns fail-closed verification errors for incomplete or mismatching evidence.
pub fn validate_whonix_signature_evidence(
    evidence: &WhonixSignatureEvidence,
    now_unix_seconds: u64,
    previous_verified_signature_time: Option<u64>,
) -> Result<(), ImageError> {
    const MAX_FUTURE_SKEW_SECONDS: u64 = 24 * 60 * 60;
    if !evidence.signature_valid
        || evidence.primary_signer_fingerprint != WHONIX_SIGNING_KEY_FINGERPRINT
        || evidence.notation != WHONIX_SIGNATURE_NOTATION
        || evidence.signature_unix_seconds < WHONIX_RELEASE_SIGNATURE_NOT_BEFORE
        || evidence.signature_unix_seconds
            > now_unix_seconds.saturating_add(MAX_FUTURE_SKEW_SECONDS)
        || previous_verified_signature_time
            .is_some_and(|previous| evidence.signature_unix_seconds < previous)
    {
        return Err(ImageError::SignatureVerification(
            "Whonix signer, notation, or signature time could not be proven".to_owned(),
        ));
    }
    Ok(())
}

/// Constructs immutable same-bundle provenance only after every expected role
/// has an exact SHA-256 digest.
///
/// # Errors
/// Refuses incomplete or malformed digest evidence.
pub fn whonix_bundle_provenance(
    signature: &WhonixSignatureEvidence,
    now_unix_seconds: u64,
    archive_sha256: String,
    mut artifact_sha256: Vec<(BundleArtifactRole, String)>,
) -> Result<WhonixBundleProvenance, ImageError> {
    validate_whonix_signature_evidence(signature, now_unix_seconds, None)?;
    let expected_roles = whonix_bundle_layout()
        .into_iter()
        .map(|entry| entry.role)
        .collect::<Vec<_>>();
    artifact_sha256.sort_by_key(|(role, _)| *role);
    let roles = artifact_sha256
        .iter()
        .map(|(role, _)| *role)
        .collect::<Vec<_>>();
    if !valid_sha256(&archive_sha256)
        || roles != expected_roles
        || artifact_sha256
            .iter()
            .any(|(_, checksum)| !valid_sha256(checksum))
    {
        return Err(ImageError::IncompleteVerificationData);
    }
    let mut identity = Sha256::new();
    identity.update(WHONIX_RELEASE.as_bytes());
    identity.update(archive_sha256.as_bytes());
    for (role, checksum) in &artifact_sha256 {
        identity.update(format!("{role:?}").as_bytes());
        identity.update(checksum.as_bytes());
    }
    let bundle_identity_sha256 = format!("{:x}", identity.finalize());
    Ok(WhonixBundleProvenance {
        release: WHONIX_RELEASE.to_owned(),
        archive_filename: WHONIX_ARCHIVE_FILENAME.to_owned(),
        source_url: WHONIX_SOURCE_URL.to_owned(),
        signer_fingerprint: signature.primary_signer_fingerprint.clone(),
        signature_notation: signature.notation.clone(),
        signature_unix_seconds: signature.signature_unix_seconds,
        archive_sha256,
        artifact_sha256,
        bundle_identity_sha256,
    })
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhonixGatewayImageMetadata {
    pub prepared_qcow2_path: PathBuf,
    pub prepared_qcow2_checksum: String,
    pub prepared_logical_bytes: u64,
    pub prepared_allocated_bytes: u64,
    pub prepared_virtual_bytes: u64,
    pub provenance: WhonixBundleProvenance,
    pub status: ImageStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WhonixPreparationState {
    Missing,
    Preparing,
    Verified(Box<WhonixGatewayImageMetadata>),
    OrphanedPreparedImage,
    Conflict(String),
}

pub type WhonixWorkstationPreparationState = WhonixPreparationState;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct WhonixPreparationIntent {
    status: String,
    archive_path: PathBuf,
    prepared_qcow2_path: PathBuf,
    #[serde(default)]
    extraction_root: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhonixWorkstationRecoveryPlan {
    pub intent_path: PathBuf,
    pub extraction_root: PathBuf,
    pub extracted_workstation_path: PathBuf,
    intent: WhonixPreparationIntent,
    intent_identity: VerifiedFileIdentity,
    downloads_identity: VerifiedFileIdentity,
    root_identity: VerifiedFileIdentity,
    entry_identities: Vec<VerifiedFileIdentity>,
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

    /// Verifies the Whonix archive signature and returns its authenticated status evidence.
    ///
    /// # Errors
    /// Returns an error unless signer, notation, and signature time can be inspected.
    fn verify_whonix_signature(
        &mut self,
        _archive: &Path,
        _signature: &Path,
        _key: &Path,
    ) -> Result<WhonixSignatureEvidence, ImageError> {
        Err(ImageError::UnsupportedImage(
            "Whonix signature verification is unsupported".to_owned(),
        ))
    }

    /// Lists and extracts a Whonix bundle into the caller-owned empty directory.
    ///
    /// # Errors
    /// Returns an error for an unsafe layout or failed controlled extraction.
    fn extract_whonix_bundle(
        &mut self,
        _archive: &Path,
        _destination: &Path,
    ) -> Result<Vec<ArchiveEntry>, ImageError> {
        Err(ImageError::UnsupportedImage(
            "Whonix bundle extraction is unsupported".to_owned(),
        ))
    }
}

fn verify_whonix_signature_timed<F: ArtifactFetcher>(
    fetcher: &mut F,
    archive: &Path,
    signature: &Path,
    key: &Path,
) -> Result<WhonixSignatureEvidence, ImageError> {
    record_full_read(FullReadOperation::ArchiveOpenPgpVerification);
    let started = Instant::now();
    eprintln!("[forge] phase start: Whonix OpenPGP verification");
    let evidence = fetcher.verify_whonix_signature(archive, signature, key)?;
    eprintln!(
        "[forge] phase done: Whonix OpenPGP verification elapsed={:.1}s",
        started.elapsed().as_secs_f64()
    );
    Ok(evidence)
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

    fn verify_whonix_signature(
        &mut self,
        archive: &Path,
        signature: &Path,
        key: &Path,
    ) -> Result<WhonixSignatureEvidence, ImageError> {
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
        let verify = Command::new("gpgv")
            .args(["--status-fd", "1", "--keyring"])
            .arg(&keyring)
            .arg(signature)
            .arg(archive)
            .output()?;
        if !verify.status.success() {
            return Err(ImageError::SignatureVerification(
                String::from_utf8_lossy(&verify.stderr).trim().to_owned(),
            ));
        }
        parse_whonix_gpg_status(&String::from_utf8_lossy(&verify.stdout))
    }

    fn extract_whonix_bundle(
        &mut self,
        archive: &Path,
        destination: &Path,
    ) -> Result<Vec<ArchiveEntry>, ImageError> {
        let root = fs::symlink_metadata(destination)?;
        if !root.file_type().is_dir() || fs::read_dir(destination)?.next().is_some() {
            return Err(ImageError::UnsupportedImage(
                "Whonix extraction root is not an empty controlled directory".to_owned(),
            ));
        }
        record_full_read(FullReadOperation::ArchiveListing);
        let listing = Command::new("tar")
            .args([
                "--list",
                "--verbose",
                "--quoting-style=escape",
                "--numeric-owner",
                "--full-time",
                "--xz",
                "--file",
            ])
            .arg(archive)
            .output()?;
        if !listing.status.success() {
            return Err(ImageError::Download(
                String::from_utf8_lossy(&listing.stderr).trim().to_owned(),
            ));
        }
        let entries = parse_tar_verbose_listing(&String::from_utf8_lossy(&listing.stdout))?;
        validate_whonix_bundle_entries(&entries)?;
        record_full_read(FullReadOperation::ArchiveExtraction);
        let extraction = Command::new("tar")
            .args(WHONIX_TAR_EXTRACTION_OPTIONS)
            .arg(archive)
            .arg("--directory")
            .arg(destination)
            .arg("--")
            .args(whonix_bundle_layout().into_iter().map(|entry| entry.path))
            .output()?;
        if !extraction.status.success() {
            return Err(ImageError::Download(
                String::from_utf8_lossy(&extraction.stderr)
                    .trim()
                    .to_owned(),
            ));
        }
        let canonical_root = fs::canonicalize(destination)?;
        let actual_entries = fs::read_dir(destination)?
            .map(|entry| {
                let entry = entry?;
                let path = entry.file_name().into_string().map_err(|_| {
                    ImageError::UnsupportedImage(
                        "Whonix extracted member name is not UTF-8".to_owned(),
                    )
                })?;
                let file_type = entry.file_type()?;
                let kind = if file_type.is_file() {
                    ArchiveEntryKind::RegularFile
                } else if file_type.is_dir() {
                    ArchiveEntryKind::Directory
                } else if file_type.is_symlink() {
                    ArchiveEntryKind::SymbolicLink
                } else {
                    ArchiveEntryKind::Other
                };
                Ok(ArchiveEntry { path, kind })
            })
            .collect::<Result<Vec<_>, ImageError>>()?;
        validate_whonix_bundle_entries(&actual_entries)?;
        for entry in whonix_bundle_layout() {
            let path = destination.join(entry.path);
            validate_extracted_file(&canonical_root, &path)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
            validate_extracted_file(&canonical_root, &path)?;
        }
        Ok(entries)
    }
}

fn parse_whonix_gpg_status(status: &str) -> Result<WhonixSignatureEvidence, ImageError> {
    let mut valid = None;
    let mut notation_name = None;
    let mut notation_data = None;
    for line in status.lines() {
        let Some(value) = line.strip_prefix("[GNUPG:] ") else {
            continue;
        };
        let fields = value.split_whitespace().collect::<Vec<_>>();
        match fields.first().copied() {
            Some("VALIDSIG") if fields.len() >= 4 => {
                let primary = fields.last().copied().unwrap_or(fields[1]);
                let timestamp = fields[3].parse::<u64>().map_err(|_| {
                    ImageError::SignatureVerification(
                        "Whonix signature timestamp is malformed".to_owned(),
                    )
                })?;
                valid = Some((primary.to_owned(), timestamp));
            }
            Some("NOTATION_NAME") => notation_name = fields.get(1).map(|value| (*value).to_owned()),
            Some("NOTATION_DATA") => {
                notation_data = value.strip_prefix("NOTATION_DATA ").map(str::to_owned);
            }
            _ => {}
        }
    }
    let (primary_signer_fingerprint, signature_unix_seconds) = valid.ok_or_else(|| {
        ImageError::SignatureVerification("Whonix VALIDSIG evidence is missing".to_owned())
    })?;
    let notation = match (notation_name, notation_data) {
        (Some(name), Some(data)) => format!("{name}={data}"),
        _ => {
            return Err(ImageError::SignatureVerification(
                "Whonix signature notation is missing".to_owned(),
            ));
        }
    };
    Ok(WhonixSignatureEvidence {
        signature_valid: true,
        primary_signer_fingerprint,
        notation,
        signature_unix_seconds,
    })
}

fn parse_tar_verbose_listing(listing: &str) -> Result<Vec<ArchiveEntry>, ImageError> {
    listing
        .lines()
        .map(|line| {
            let kind = match line.as_bytes().first().copied() {
                Some(b'-') => ArchiveEntryKind::RegularFile,
                Some(b'd') => ArchiveEntryKind::Directory,
                Some(b'l') => ArchiveEntryKind::SymbolicLink,
                Some(b'h') => ArchiveEntryKind::HardLink,
                _ => ArchiveEntryKind::Other,
            };
            let path = remainder_after_fields(line, 5).ok_or_else(|| {
                ImageError::UnsupportedImage("malformed tar listing entry".to_owned())
            })?;
            Ok(ArchiveEntry {
                path: path.to_owned(),
                kind,
            })
        })
        .collect()
}

fn remainder_after_fields(line: &str, fields: usize) -> Option<&str> {
    let bytes = line.as_bytes();
    let mut index = 0;
    for _ in 0..fields {
        while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
            index += 1;
        }
        if index == bytes.len() {
            return None;
        }
        while bytes
            .get(index)
            .is_some_and(|byte| !byte.is_ascii_whitespace())
        {
            index += 1;
        }
    }
    while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
        index += 1;
    }
    (index < bytes.len()).then(|| &line[index..])
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

/// Acquires and prepares the Gateway disk from the authenticated Whonix bundle.
///
/// Every bundle role is validated and hashed before only the typed Gateway disk
/// is published. The Workstation digest remains part of immutable provenance.
///
/// # Errors
/// Refuses incomplete signature evidence, unsafe bundle layouts, interrupted
/// preparation, existing untrusted outputs, and post-extraction source drift.
pub fn fetch_whonix_gateway<F: ArtifactFetcher>(
    directories: &ImageDirectories,
    fetcher: &mut F,
) -> Result<WhonixGatewayImageMetadata, ImageError> {
    fs::create_dir_all(&directories.images)?;
    fs::create_dir_all(&directories.downloads)?;
    match inspect_whonix_preparation(directories)? {
        WhonixPreparationState::Missing => {}
        WhonixPreparationState::Verified(_) => return verified_whonix_gateway(directories),
        state => {
            return Err(ImageError::Metadata(format!(
                "Whonix image preparation requires explicit recovery: {state:?}"
            )));
        }
    }
    let archive = directories.downloads.join(WHONIX_ARCHIVE_FILENAME);
    let signature = directories
        .downloads
        .join(format!("{WHONIX_ARCHIVE_FILENAME}.asc"));
    let key = directories.downloads.join("whonix-derivative.asc");
    let prepared = directories.images.join(WHONIX_GATEWAY_DISK_FILENAME);
    fetcher.download(WHONIX_SOURCE_URL, &archive)?;
    fetcher.download(WHONIX_SIGNATURE_URL, &signature)?;
    fetcher.download(WHONIX_SIGNING_KEY_URL, &key)?;
    let signature_evidence = verify_whonix_signature_timed(fetcher, &archive, &signature, &key)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| ImageError::Metadata(error.to_string()))?
        .as_secs();
    validate_whonix_signature_evidence(&signature_evidence, now, None)?;
    if !is_single_regular_file(&archive) {
        return Err(ImageError::UnsupportedImage(
            "verified Whonix archive is not one regular file".to_owned(),
        ));
    }
    let archive_sha256 = sha256_file(&archive)?;
    write_json_atomic(
        &directories.images,
        "whonix.intent.json.tmp",
        "whonix.intent.json",
        &WhonixPreparationIntent {
            status: "Preparing".to_owned(),
            archive_path: archive.clone(),
            prepared_qcow2_path: prepared.clone(),
            extraction_root: None,
        },
    )?;
    let (prepared_qcow2_checksum, provenance) = prepare_whonix_bundle(
        directories,
        fetcher,
        &archive,
        &prepared,
        &signature_evidence,
        now,
        &archive_sha256,
    )?;
    let prepared_file_metadata = fs::metadata(&prepared)?;
    let prepared_virtual_bytes = qcow2_virtual_size(&prepared)?;
    let metadata = WhonixGatewayImageMetadata {
        prepared_qcow2_path: prepared,
        prepared_qcow2_checksum,
        prepared_logical_bytes: prepared_file_metadata.len(),
        prepared_allocated_bytes: prepared_file_metadata.blocks().saturating_mul(512),
        prepared_virtual_bytes,
        provenance,
        status: ImageStatus::Verified,
    };
    write_json_atomic(
        &directories.images,
        "whonix.metadata.json.tmp",
        "whonix.metadata.json",
        &metadata,
    )?;
    clear_whonix_intent(directories)?;
    Ok(metadata)
}

fn prepare_whonix_bundle<F: ArtifactFetcher>(
    directories: &ImageDirectories,
    fetcher: &mut F,
    archive: &Path,
    prepared: &Path,
    signature: &WhonixSignatureEvidence,
    now: u64,
    archive_sha256: &str,
) -> Result<(String, WhonixBundleProvenance), ImageError> {
    let extraction_root = create_extraction_root_for(&directories.downloads, ".whonix-extract-")?;
    let extraction = (|| {
        let extraction_started = Instant::now();
        eprintln!("[forge] phase start: Whonix extraction");
        let entries = fetcher.extract_whonix_bundle(archive, &extraction_root)?;
        eprintln!(
            "[forge] phase done: Whonix extraction elapsed={:.1}s",
            extraction_started.elapsed().as_secs_f64()
        );
        let identified = validate_whonix_bundle_entries(&entries)?;
        let canonical_root = fs::canonicalize(&extraction_root)?;
        let mut hashes = Vec::with_capacity(identified.len());
        for (role, path) in identified {
            let extracted = extraction_root.join(path);
            validate_extracted_file(&canonical_root, &extracted)?;
            hashes.push((role, sha256_file(&extracted)?));
        }
        let archive_after_extraction = sha256_file(archive)?;
        if archive_after_extraction != archive_sha256 {
            return Err(ImageError::ChecksumMismatch {
                expected: archive_sha256.to_owned(),
                actual: archive_after_extraction,
            });
        }
        let provenance =
            whonix_bundle_provenance(signature, now, archive_sha256.to_owned(), hashes)?;
        let gateway_checksum = provenance
            .artifact_sha256
            .iter()
            .find_map(|(role, hash)| {
                (*role == BundleArtifactRole::GatewayDisk).then(|| hash.clone())
            })
            .ok_or(ImageError::IncompleteVerificationData)?;
        let publication_started = Instant::now();
        eprintln!("[forge] phase start: Gateway publication");
        promote_without_overwrite(
            &extraction_root.join(WHONIX_GATEWAY_DISK_FILENAME),
            prepared,
            &gateway_checksum,
        )?;
        eprintln!(
            "[forge] phase done: Gateway publication elapsed={:.1}s",
            publication_started.elapsed().as_secs_f64()
        );
        Ok((gateway_checksum, provenance))
    })();
    let cleanup =
        cleanup_extraction_root_for(&directories.downloads, &extraction_root, ".whonix-extract-");
    match (extraction, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => {
            clear_whonix_intent(directories)?;
            Err(error)
        }
        (Err(error), Err(_)) | (Ok(_), Err(error)) => Err(error),
    }
}

/// Returns the Gateway base only when metadata and every exact identity still match.
///
/// # Errors
/// Returns an error when no fully verified prepared Gateway base is available.
pub fn verified_whonix_gateway(
    directories: &ImageDirectories,
) -> Result<WhonixGatewayImageMetadata, ImageError> {
    match inspect_whonix_preparation(directories)? {
        WhonixPreparationState::Verified(metadata) => Ok(*metadata),
        _ => Err(ImageError::SourceNotVerified),
    }
}

fn prove_existing_whonix_gateway(
    directories: &ImageDirectories,
) -> Result<
    (
        WhonixGatewayImageMetadata,
        LifecycleVerifiedFile,
        Vec<VerifiedFileIdentity>,
    ),
    ImageError,
> {
    let metadata_path = directories.images.join("whonix.metadata.json");
    let archive = directories.downloads.join(WHONIX_ARCHIVE_FILENAME);
    let gateway = directories.images.join(WHONIX_GATEWAY_DISK_FILENAME);
    let input_paths = [
        archive.clone(),
        directories
            .downloads
            .join(format!("{WHONIX_ARCHIVE_FILENAME}.asc")),
        directories.downloads.join("whonix-derivative.asc"),
        gateway.clone(),
        metadata_path.clone(),
    ];
    let before = input_paths
        .iter()
        .map(|path| verified_file_identity(path))
        .collect::<Result<Vec<_>, _>>()?;
    let metadata: WhonixGatewayImageMetadata =
        serde_json::from_slice(&fs::read(&metadata_path)?)
            .map_err(|error| ImageError::Metadata(error.to_string()))?;
    let archive_evidence = verify_file_bytes(
        &archive,
        &metadata.provenance.archive_sha256,
        FullReadOperation::ArchiveHash,
    )?;
    let gateway_evidence = verify_file_bytes(
        &gateway,
        &metadata.prepared_qcow2_checksum,
        FullReadOperation::GatewayHash,
    )?;
    let rebuilt = whonix_bundle_provenance(
        &WhonixSignatureEvidence {
            signature_valid: true,
            primary_signer_fingerprint: metadata.provenance.signer_fingerprint.clone(),
            notation: metadata.provenance.signature_notation.clone(),
            signature_unix_seconds: metadata.provenance.signature_unix_seconds,
        },
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| ImageError::Metadata(error.to_string()))?
            .as_secs(),
        archive_evidence.sha256.clone(),
        metadata.provenance.artifact_sha256.clone(),
    )?;
    let after = input_paths
        .iter()
        .map(|path| verified_file_identity(path))
        .collect::<Result<Vec<_>, _>>()?;
    if before != after
        || metadata.status != ImageStatus::Verified
        || metadata.prepared_qcow2_path != gateway
        || metadata.prepared_qcow2_checksum != gateway_evidence.sha256
        || metadata.prepared_logical_bytes != gateway_evidence.identity.bytes
        || qcow2_virtual_size(&gateway)? != metadata.prepared_virtual_bytes
        || rebuilt != metadata.provenance
        || metadata.provenance.release != WHONIX_RELEASE
        || metadata.provenance.archive_filename != WHONIX_ARCHIVE_FILENAME
        || metadata.provenance.source_url != WHONIX_SOURCE_URL
        || metadata.provenance.signer_fingerprint != WHONIX_SIGNING_KEY_FINGERPRINT
        || metadata.provenance.signature_notation != WHONIX_SIGNATURE_NOTATION
    {
        return Err(ImageError::SourceNotVerified);
    }
    Ok((metadata, archive_evidence, after))
}

/// Publishes the typed Workstation disk from the already downloaded, fully
/// authenticated Whonix bundle. No network download is performed.
///
/// # Errors
/// Refuses any incomplete Gateway provenance, signature or archive drift,
/// unexpected bundle member, unsafe publication state, or invalid Workstation
/// qcow2 identity.
#[allow(clippy::too_many_lines)]
fn prepare_whonix_workstation_with_evidence<F: ArtifactFetcher>(
    directories: &ImageDirectories,
    fetcher: &mut F,
) -> Result<(WhonixGatewayImageMetadata, Vec<VerifiedFileIdentity>), ImageError> {
    fs::create_dir_all(&directories.images)?;
    fs::create_dir_all(&directories.downloads)?;
    match inspect_whonix_workstation_preparation(directories)? {
        WhonixPreparationState::Missing => {}
        WhonixPreparationState::Verified(_) => {
            let metadata = revalidate_whonix_workstation(directories, fetcher)?;
            return Ok((metadata, capture_whonix_execute_inputs(directories)?));
        }
        state => {
            return Err(ImageError::Metadata(format!(
                "Whonix Workstation preparation requires explicit recovery: {state:?}"
            )));
        }
    }

    let (gateway, archive_evidence, existing_inputs) = prove_existing_whonix_gateway(directories)?;
    let archive = directories.downloads.join(WHONIX_ARCHIVE_FILENAME);
    let signature = directories
        .downloads
        .join(format!("{WHONIX_ARCHIVE_FILENAME}.asc"));
    let key = directories.downloads.join("whonix-derivative.asc");
    let signature_file = bind_file_identity(&signature)?;
    let key_file = bind_file_identity(&key)?;
    let (_archive_child_fd, bound_archive) = inheritable_fd_path(&archive_evidence.file)?;
    let (_signature_child_fd, bound_signature) = inheritable_fd_path(&signature_file.file)?;
    let signature_evidence =
        verify_whonix_signature_timed(fetcher, &bound_archive, &bound_signature, &key)?;
    revalidate_lifecycle_file(&archive_evidence)?;
    revalidate_lifecycle_file(&signature_file)?;
    revalidate_lifecycle_file(&key_file)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| ImageError::Metadata(error.to_string()))?
        .as_secs();
    validate_whonix_signature_evidence(
        &signature_evidence,
        now,
        Some(gateway.provenance.signature_unix_seconds),
    )?;
    if signature_evidence.primary_signer_fingerprint != gateway.provenance.signer_fingerprint
        || signature_evidence.notation != gateway.provenance.signature_notation
        || signature_evidence.signature_unix_seconds != gateway.provenance.signature_unix_seconds
    {
        return Err(ImageError::SourceNotVerified);
    }
    let prepared = directories.images.join(WHONIX_WORKSTATION_DISK_FILENAME);
    let extraction_root = extraction_root_path_for(&directories.downloads, ".whonix-extract-")?;
    write_json_atomic(
        &directories.images,
        "whonix-workstation.intent.json.tmp",
        "whonix-workstation.intent.json",
        &WhonixPreparationIntent {
            status: "Preparing".to_owned(),
            archive_path: archive.clone(),
            prepared_qcow2_path: prepared.clone(),
            extraction_root: Some(extraction_root.clone()),
        },
    )?;
    if let Err(error) = create_extraction_root_at(&directories.downloads, &extraction_root) {
        clear_whonix_workstation_intent(directories)?;
        return Err(error);
    }
    let preparation = (|| {
        let extraction_started = Instant::now();
        eprintln!("[forge] phase start: Whonix extraction");
        revalidate_lifecycle_file(&archive_evidence)?;
        let entries = fetcher.extract_whonix_bundle(&bound_archive, &extraction_root)?;
        revalidate_lifecycle_file(&archive_evidence)?;
        eprintln!(
            "[forge] phase done: Whonix extraction elapsed={:.1}s",
            extraction_started.elapsed().as_secs_f64()
        );
        let identified = validate_whonix_bundle_entries(&entries)?;
        let canonical_root = fs::canonicalize(&extraction_root)?;
        let mut hashes = Vec::with_capacity(identified.len());
        let mut workstation_evidence = None;
        for (role, path) in identified {
            let extracted = extraction_root.join(path);
            validate_extracted_file(&canonical_root, &extracted)?;
            fs::set_permissions(&extracted, fs::Permissions::from_mode(0o600))?;
            let expected = whonix_artifact_digest(&gateway.provenance, role)?;
            let operation = if role == BundleArtifactRole::WorkstationDisk {
                FullReadOperation::WorkstationHash
            } else {
                FullReadOperation::ExtractedBundleArtifactHash(role)
            };
            let evidence = verify_file_bytes(&extracted, &expected, operation)?;
            hashes.push((role, evidence.sha256.clone()));
            if role == BundleArtifactRole::WorkstationDisk {
                workstation_evidence = Some(evidence);
            }
        }
        let provenance = whonix_bundle_provenance(
            &signature_evidence,
            now,
            gateway.provenance.archive_sha256.clone(),
            hashes,
        )?;
        if provenance != gateway.provenance {
            return Err(ImageError::SourceNotVerified);
        }
        let workstation_checksum =
            whonix_artifact_digest(&provenance, BundleArtifactRole::WorkstationDisk)?;
        let extracted = extraction_root.join(WHONIX_WORKSTATION_DISK_FILENAME);
        if qcow2_virtual_size(&extracted)? != WHONIX_WORKSTATION_VIRTUAL_BYTES {
            return Err(ImageError::UnsupportedImage(
                "Whonix Workstation virtual size differs from profile policy".to_owned(),
            ));
        }
        let workstation_evidence = workstation_evidence.ok_or(ImageError::SourceNotVerified)?;
        revalidate_lifecycle_file(&workstation_evidence)?;
        let publication_started = Instant::now();
        eprintln!("[forge] phase start: Workstation publication");
        let published =
            promote_verified_without_overwrite(&extracted, &prepared, &workstation_evidence)?;
        eprintln!(
            "[forge] phase done: Workstation publication elapsed={:.1}s",
            publication_started.elapsed().as_secs_f64()
        );
        let file_metadata = fs::metadata(&prepared)?;
        Ok((
            WhonixGatewayImageMetadata {
                prepared_qcow2_path: prepared.clone(),
                prepared_qcow2_checksum: workstation_checksum,
                prepared_logical_bytes: file_metadata.len(),
                prepared_allocated_bytes: file_metadata.blocks().saturating_mul(512),
                prepared_virtual_bytes: WHONIX_WORKSTATION_VIRTUAL_BYTES,
                provenance,
                status: ImageStatus::Verified,
            },
            published,
        ))
    })();
    let cleanup =
        cleanup_extraction_root_for(&directories.downloads, &extraction_root, ".whonix-extract-");
    let (metadata, published) = match (preparation, cleanup) {
        (Ok(value), Ok(())) => value,
        (Err(error), Ok(())) => {
            clear_whonix_workstation_intent(directories)?;
            return Err(error);
        }
        (Err(error), Err(_)) | (Ok(_), Err(error)) => return Err(error),
    };
    write_json_atomic(
        &directories.images,
        "whonix-workstation.metadata.json.tmp",
        "whonix-workstation.metadata.json",
        &metadata,
    )?;
    clear_whonix_workstation_intent(directories)?;
    let final_inputs = capture_whonix_execute_inputs(directories)?;
    let final_workstation = final_inputs
        .iter()
        .find(|identity| identity.path == prepared)
        .ok_or(ImageError::SourceNotVerified)?;
    if final_inputs.get(..5) != Some(existing_inputs.as_slice()) || final_workstation != &published
    {
        return Err(ImageError::SourceNotVerified);
    }
    Ok((metadata, final_inputs))
}

/// Publishes the typed Workstation disk from the authenticated Whonix bundle.
///
/// # Errors
/// Refuses incomplete verification, unsafe extraction or publication, and any
/// lifecycle identity drift.
pub fn prepare_whonix_workstation<F: ArtifactFetcher>(
    directories: &ImageDirectories,
    fetcher: &mut F,
) -> Result<WhonixGatewayImageMetadata, ImageError> {
    prepare_whonix_workstation_with_evidence(directories, fetcher).map(|(metadata, _)| metadata)
}

/// Performs the full byte- and signature-backed execute-time revalidation for
/// an already prepared Workstation base.
///
/// # Errors
/// Refuses metadata-only evidence or any signature, archive, provenance,
/// prepared-file, permission, link-count, qcow2, or virtual-size drift.
pub fn revalidate_whonix_workstation<F: ArtifactFetcher>(
    directories: &ImageDirectories,
    fetcher: &mut F,
) -> Result<WhonixGatewayImageMetadata, ImageError> {
    let metadata = match inspect_whonix_workstation_preparation(directories)? {
        WhonixPreparationState::Verified(metadata) => *metadata,
        _ => return Err(ImageError::SourceNotVerified),
    };
    let archive = directories.downloads.join(WHONIX_ARCHIVE_FILENAME);
    let signature = directories
        .downloads
        .join(format!("{WHONIX_ARCHIVE_FILENAME}.asc"));
    let key = directories.downloads.join("whonix-derivative.asc");
    let evidence = verify_whonix_signature_timed(fetcher, &archive, &signature, &key)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| ImageError::Metadata(error.to_string()))?
        .as_secs();
    validate_whonix_signature_evidence(
        &evidence,
        now,
        Some(metadata.provenance.signature_unix_seconds),
    )?;
    if evidence.primary_signer_fingerprint != metadata.provenance.signer_fingerprint
        || evidence.notation != metadata.provenance.signature_notation
        || evidence.signature_unix_seconds != metadata.provenance.signature_unix_seconds
    {
        return Err(ImageError::SourceNotVerified);
    }
    Ok(metadata)
}

fn whonix_execute_input_paths(directories: &ImageDirectories) -> [PathBuf; 7] {
    [
        directories.downloads.join(WHONIX_ARCHIVE_FILENAME),
        directories
            .downloads
            .join(format!("{WHONIX_ARCHIVE_FILENAME}.asc")),
        directories.downloads.join("whonix-derivative.asc"),
        directories.images.join(WHONIX_GATEWAY_DISK_FILENAME),
        directories.images.join("whonix.metadata.json"),
        directories.images.join(WHONIX_WORKSTATION_DISK_FILENAME),
        directories.images.join("whonix-workstation.metadata.json"),
    ]
}

fn verified_file_identity(path: &Path) -> Result<VerifiedFileIdentity, ImageError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        return Err(ImageError::SourceNotVerified);
    }
    Ok(file_identity_from_metadata(path, &metadata))
}

fn file_identity_allow_links(path: &Path) -> Result<VerifiedFileIdentity, ImageError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(ImageError::SourceNotVerified);
    }
    Ok(file_identity_from_metadata(path, &metadata))
}

fn file_identity_from_metadata(path: &Path, metadata: &fs::Metadata) -> VerifiedFileIdentity {
    VerifiedFileIdentity {
        path: path.to_owned(),
        device: metadata.dev(),
        inode: metadata.ino(),
        bytes: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
        mode: metadata.mode(),
        links: metadata.nlink(),
    }
}

fn opened_file_identity(path: &Path, file: &File) -> Result<VerifiedFileIdentity, ImageError> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        return Err(ImageError::SourceNotVerified);
    }
    Ok(file_identity_from_metadata(path, &metadata))
}

fn opened_file_identity_allow_links(
    path: &Path,
    file: &File,
) -> Result<VerifiedFileIdentity, ImageError> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(ImageError::SourceNotVerified);
    }
    Ok(file_identity_from_metadata(path, &metadata))
}

fn verify_file_bytes(
    path: &Path,
    expected: &str,
    operation: FullReadOperation,
) -> Result<LifecycleVerifiedFile, ImageError> {
    let before = verified_file_identity(path)?;
    let file = File::open(path)?;
    if opened_file_identity(path, &file)? != before {
        return Err(ImageError::SourceNotVerified);
    }
    let digest = sha256_open_file(file.try_clone()?, path, operation)?;
    let after = verified_file_identity(path)?;
    if before != after || opened_file_identity(path, &file)? != after || digest != expected {
        return Err(ImageError::SourceNotVerified);
    }
    Ok(LifecycleVerifiedFile {
        file,
        identity: after,
        sha256: digest,
    })
}

fn bind_file_identity(path: &Path) -> Result<LifecycleVerifiedFile, ImageError> {
    let before = verified_file_identity(path)?;
    let file = File::open(path)?;
    if opened_file_identity(path, &file)? != before || verified_file_identity(path)? != before {
        return Err(ImageError::SourceNotVerified);
    }
    Ok(LifecycleVerifiedFile {
        file,
        identity: before,
        sha256: String::new(),
    })
}

fn inheritable_fd_path(file: &File) -> Result<(OwnedFd, PathBuf), ImageError> {
    let owned = rustix::io::dup(file)
        .map_err(|error| io::Error::from_raw_os_error(error.raw_os_error()))?;
    let path = PathBuf::from(format!("/proc/self/fd/{}", owned.as_raw_fd()));
    Ok((owned, path))
}

fn revalidate_lifecycle_file(evidence: &LifecycleVerifiedFile) -> Result<(), ImageError> {
    if verified_file_identity(&evidence.identity.path)? != evidence.identity
        || opened_file_identity(&evidence.identity.path, &evidence.file)? != evidence.identity
    {
        return Err(ImageError::SourceNotVerified);
    }
    Ok(())
}

fn capture_whonix_execute_inputs(
    directories: &ImageDirectories,
) -> Result<Vec<VerifiedFileIdentity>, ImageError> {
    whonix_execute_input_paths(directories)
        .iter()
        .map(|path| verified_file_identity(path))
        .collect()
}

/// Performs full cryptographic and byte validation and binds its result to the
/// exact local files seen both before and after that validation.
///
/// # Errors
/// Refuses concurrent input drift and every condition refused by the normal
/// execute-time Workstation validation.
pub fn prove_whonix_workstation_for_execute<F: ArtifactFetcher>(
    directories: &ImageDirectories,
    fetcher: &mut F,
) -> Result<WhonixWorkstationExecuteProof, ImageError> {
    let before = capture_whonix_execute_inputs(directories)?;
    let metadata = revalidate_whonix_workstation(directories, fetcher)?;
    let after = capture_whonix_execute_inputs(directories)?;
    if before != after {
        return Err(ImageError::SourceNotVerified);
    }
    Ok(WhonixWorkstationExecuteProof {
        metadata,
        files: after,
    })
}

/// Prepares or fully revalidates Workstation once and returns the proof needed
/// for the immediately following mutation boundary.
///
/// # Errors
/// Refuses preparation/verification failure or concurrent drift of any input.
pub fn prepare_whonix_workstation_for_execute<F: ArtifactFetcher>(
    directories: &ImageDirectories,
    fetcher: &mut F,
) -> Result<(WhonixGatewayImageMetadata, WhonixWorkstationExecuteProof), ImageError> {
    prepare_whonix_workstation_for_execute_with_hook(directories, fetcher, || Ok(()))
}

fn prepare_whonix_workstation_for_execute_with_hook<F: ArtifactFetcher>(
    directories: &ImageDirectories,
    fetcher: &mut F,
    before_proof: impl FnOnce() -> Result<(), ImageError>,
) -> Result<(WhonixGatewayImageMetadata, WhonixWorkstationExecuteProof), ImageError> {
    let preparation_started = Instant::now();
    eprintln!("[forge] phase start: total Workstation preparation");
    // A missing member is expected on first preparation. Existing complete
    // state is captured before the byte-backed validation performed below.
    let before = capture_whonix_execute_inputs(directories).ok();
    let (metadata, verified_files) = if let Some(before) = before {
        // Complete existing state: go straight to the one full execute proof.
        // The revalidator still classifies and refuses every inconsistent bit.
        let metadata = revalidate_whonix_workstation(directories, fetcher)?;
        let after = capture_whonix_execute_inputs(directories)?;
        if before != after {
            return Err(ImageError::SourceNotVerified);
        }
        (metadata, after)
    } else {
        prepare_whonix_workstation_with_evidence(directories, fetcher)?
    };
    let proof = WhonixWorkstationExecuteProof {
        metadata: metadata.clone(),
        files: verified_files,
    };
    before_proof()?;
    revalidate_whonix_workstation_execute_proof(directories, &proof)?;
    eprintln!(
        "[forge] phase done: total Workstation preparation elapsed={:.1}s",
        preparation_started.elapsed().as_secs_f64()
    );
    Ok((metadata, proof))
}

/// Reuses a byte-backed proof only across an unchanged local filesystem
/// identity. This closes the plan-to-mutation TOCTOU boundary without a second
/// read of the same 100 GiB sparse files.
///
/// # Errors
/// Refuses any file replacement, write, chmod, link-count, size, timestamp, or
/// durable metadata change since the full proof was produced.
pub fn revalidate_whonix_workstation_execute_proof(
    directories: &ImageDirectories,
    proof: &WhonixWorkstationExecuteProof,
) -> Result<WhonixGatewayImageMetadata, ImageError> {
    let current = capture_whonix_execute_inputs(directories)?;
    if current != proof.files {
        return Err(ImageError::SourceNotVerified);
    }
    let metadata_path = directories.images.join("whonix-workstation.metadata.json");
    let current_metadata: WhonixGatewayImageMetadata =
        serde_json::from_slice(&fs::read(metadata_path)?)
            .map_err(|error| ImageError::Metadata(error.to_string()))?;
    if current_metadata != proof.metadata {
        return Err(ImageError::SourceNotVerified);
    }
    Ok(current_metadata)
}

/// Opens the exact verified Workstation inode at the consumption boundary.
/// The returned descriptor remains bound to that inode even if the pathname is
/// replaced after this function returns.
///
/// # Errors
/// Refuses proof drift or an opened descriptor whose identity differs from the
/// byte-backed snapshot.
pub fn open_whonix_workstation_execute_source(
    directories: &ImageDirectories,
    proof: &WhonixWorkstationExecuteProof,
) -> Result<File, ImageError> {
    revalidate_whonix_workstation_execute_proof(directories, proof)?;
    let path = directories.images.join(WHONIX_WORKSTATION_DISK_FILENAME);
    let file = File::open(&path)?;
    let opened = opened_file_identity(&path, &file)?;
    let expected = proof
        .files
        .iter()
        .find(|identity| identity.path == path)
        .ok_or(ImageError::SourceNotVerified)?;
    if &opened != expected {
        return Err(ImageError::SourceNotVerified);
    }
    Ok(file)
}

/// Classifies the independently published Workstation base without granting
/// execute authorization from metadata alone.
///
/// # Errors
/// Returns filesystem or metadata inspection errors.
pub fn inspect_whonix_workstation_preparation(
    directories: &ImageDirectories,
) -> Result<WhonixWorkstationPreparationState, ImageError> {
    let intent = directories.images.join("whonix-workstation.intent.json");
    let intent_temp = directories
        .images
        .join("whonix-workstation.intent.json.tmp");
    let metadata_temp = directories
        .images
        .join("whonix-workstation.metadata.json.tmp");
    let metadata_path = directories.images.join("whonix-workstation.metadata.json");
    let prepared = directories.images.join(WHONIX_WORKSTATION_DISK_FILENAME);
    if intent.exists() || intent_temp.exists() || metadata_temp.exists() {
        return Ok(WhonixPreparationState::Preparing);
    }
    if !metadata_path.exists() {
        return Ok(if prepared.exists() {
            WhonixPreparationState::OrphanedPreparedImage
        } else {
            WhonixPreparationState::Missing
        });
    }
    if !prepared.exists() {
        return Ok(WhonixPreparationState::Preparing);
    }
    let metadata: WhonixGatewayImageMetadata =
        match serde_json::from_slice(&fs::read(metadata_path)?) {
            Ok(metadata) => metadata,
            Err(error) => {
                return Ok(WhonixPreparationState::Conflict(format!(
                    "Whonix Workstation metadata cannot be parsed: {error}"
                )));
            }
        };
    let gateway = match inspect_whonix_preparation(directories)? {
        WhonixPreparationState::Verified(metadata) => *metadata,
        state => {
            return Ok(WhonixPreparationState::Conflict(format!(
                "Gateway provenance is not fully verified: {state:?}"
            )));
        }
    };
    let file_metadata = fs::symlink_metadata(&prepared)?;
    let expected_digest =
        whonix_artifact_digest(&gateway.provenance, BundleArtifactRole::WorkstationDisk)?;
    if metadata.status != ImageStatus::Verified
        || metadata.prepared_qcow2_path != prepared
        || !is_single_regular_file(&prepared)
        || file_metadata.permissions().mode() & 0o777 != 0o600
        || metadata.prepared_qcow2_checksum != expected_digest
        || sha256_file(&prepared)? != expected_digest
        || file_metadata.len() != metadata.prepared_logical_bytes
        || metadata.prepared_virtual_bytes != WHONIX_WORKSTATION_VIRTUAL_BYTES
        || qcow2_virtual_size(&prepared)? != WHONIX_WORKSTATION_VIRTUAL_BYTES
        || metadata.provenance != gateway.provenance
    {
        return Ok(WhonixPreparationState::Conflict(
            "prepared Workstation base differs from authenticated provenance".to_owned(),
        ));
    }
    Ok(WhonixPreparationState::Verified(Box::new(metadata)))
}

/// Returns the exact digest bound to one typed Whonix bundle role.
///
/// # Errors
/// Refuses provenance without the requested role.
pub fn whonix_artifact_digest(
    provenance: &WhonixBundleProvenance,
    expected_role: BundleArtifactRole,
) -> Result<String, ImageError> {
    provenance
        .artifact_sha256
        .iter()
        .find_map(|(role, digest)| (*role == expected_role).then(|| digest.clone()))
        .ok_or(ImageError::IncompleteVerificationData)
}

fn clear_whonix_workstation_intent(directories: &ImageDirectories) -> Result<(), ImageError> {
    let path = directories.images.join("whonix-workstation.intent.json");
    match fs::remove_file(path) {
        Ok(()) => sync_directory(&directories.images),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn whonix_extraction_roots(downloads: &Path) -> Result<Vec<PathBuf>, ImageError> {
    let mut roots = Vec::new();
    for entry in fs::read_dir(downloads)? {
        let entry = entry?;
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(".whonix-extract-"))
        {
            roots.push(entry.path());
        }
    }
    roots.sort();
    Ok(roots)
}

fn verified_directory_identity(path: &Path) -> Result<VerifiedFileIdentity, ImageError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() {
        return Err(ImageError::SourceNotVerified);
    }
    Ok(VerifiedFileIdentity {
        path: path.to_owned(),
        device: metadata.dev(),
        inode: metadata.ino(),
        bytes: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
        mode: metadata.mode(),
        links: metadata.nlink(),
    })
}

fn opened_directory_identity(
    logical_path: &Path,
    directory: &File,
) -> Result<VerifiedFileIdentity, ImageError> {
    let metadata = directory.metadata()?;
    if !metadata.file_type().is_dir() {
        return Err(ImageError::SourceNotVerified);
    }
    Ok(VerifiedFileIdentity {
        path: logical_path.to_owned(),
        device: metadata.dev(),
        inode: metadata.ino(),
        bytes: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
        mode: metadata.mode(),
        links: metadata.nlink(),
    })
}

fn verified_file_identity_at(
    descriptor_path: &Path,
    logical_path: &Path,
) -> Result<VerifiedFileIdentity, ImageError> {
    let mut identity = verified_file_identity(descriptor_path)?;
    logical_path.clone_into(&mut identity.path);
    Ok(identity)
}

fn verified_directory_identity_at(
    descriptor_path: &Path,
    logical_path: &Path,
) -> Result<VerifiedFileIdentity, ImageError> {
    let mut identity = verified_directory_identity(descriptor_path)?;
    logical_path.clone_into(&mut identity.path);
    Ok(identity)
}

fn descriptor_path(directory: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()))
}

fn same_directory_object(left: &VerifiedFileIdentity, right: &VerifiedFileIdentity) -> bool {
    left.device == right.device
        && left.inode == right.inode
        && left.mode == right.mode
        && left.links == right.links
}

/// Builds an immutable confirmation plan for the exact pre-publication
/// Workstation preparation currently owned by Forge.
///
/// Legacy intents did not record the extraction root. They are recoverable
/// only when exactly one controlled root exists and it contains the complete,
/// flat official allowlist as single-link regular files. The returned plan
/// binds every inode and timestamp; no ownership is inferred from a qcow2 name.
///
/// # Errors
/// Refuses published output, ambiguous roots, unexpected entries, links,
/// malformed intent, or any state other than pre-publication `Preparing`.
pub fn plan_whonix_workstation_recovery(
    directories: &ImageDirectories,
) -> Result<WhonixWorkstationRecoveryPlan, ImageError> {
    let intent_path = directories.images.join("whonix-workstation.intent.json");
    let intent_temp = directories
        .images
        .join("whonix-workstation.intent.json.tmp");
    let metadata = directories.images.join("whonix-workstation.metadata.json");
    let metadata_temp = directories
        .images
        .join("whonix-workstation.metadata.json.tmp");
    let prepared = directories.images.join(WHONIX_WORKSTATION_DISK_FILENAME);
    if intent_temp.exists() || metadata.exists() || metadata_temp.exists() || prepared.exists() {
        return Err(ImageError::Metadata(
            "recovery requires exact pre-publication Workstation Preparing state".to_owned(),
        ));
    }
    let intent: WhonixPreparationIntent = serde_json::from_slice(&fs::read(&intent_path)?)
        .map_err(|error| ImageError::Metadata(error.to_string()))?;
    if intent.status != "Preparing"
        || intent.archive_path != directories.downloads.join(WHONIX_ARCHIVE_FILENAME)
        || intent.prepared_qcow2_path != prepared
    {
        return Err(ImageError::Metadata(
            "Workstation recovery intent identity is incoherent".to_owned(),
        ));
    }
    let roots = whonix_extraction_roots(&directories.downloads)?;
    let extraction_root = match (intent.extraction_root.as_ref(), roots.as_slice()) {
        (Some(expected), [only]) if expected == only => only.clone(),
        (None, [only]) => only.clone(),
        _ => {
            return Err(ImageError::Metadata(
                "Workstation recovery extraction-root ownership is ambiguous".to_owned(),
            ));
        }
    };
    if extraction_root.parent() != Some(directories.downloads.as_path()) {
        return Err(ImageError::Metadata(
            "Workstation recovery root escaped the controlled downloads directory".to_owned(),
        ));
    }
    let mut actual_names = Vec::new();
    let intent_identity = verified_file_identity(&intent_path)?;
    let downloads_identity = verified_directory_identity(&directories.downloads)?;
    let root_identity = verified_directory_identity(&extraction_root)?;
    let mut entry_identities = Vec::new();
    for entry in fs::read_dir(&extraction_root)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| ImageError::SourceNotVerified)?;
        entry_identities.push(verified_file_identity(&entry.path())?);
        actual_names.push(name);
    }
    actual_names.sort();
    let mut expected_names = whonix_bundle_layout()
        .into_iter()
        .map(|entry| entry.path.to_owned())
        .collect::<Vec<_>>();
    expected_names.sort();
    if actual_names != expected_names {
        return Err(ImageError::Metadata(
            "Workstation recovery root differs from the exact bundle allowlist".to_owned(),
        ));
    }
    entry_identities.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(WhonixWorkstationRecoveryPlan {
        intent_path,
        extracted_workstation_path: extraction_root.join(WHONIX_WORKSTATION_DISK_FILENAME),
        extraction_root,
        intent,
        intent_identity,
        downloads_identity,
        root_identity,
        entry_identities,
    })
}

/// Executes only an unchanged, explicitly confirmed pre-publication recovery
/// plan. No archive, prepared image, metadata, durable VM state, or libvirt
/// resource is touched.
///
/// # Errors
/// Refuses plan drift and incomplete cleanup. The intent is removed only after
/// the controlled root is absent and its parent directory has been synced.
pub fn execute_whonix_workstation_recovery(
    directories: &ImageDirectories,
    plan: &WhonixWorkstationRecoveryPlan,
) -> Result<(), ImageError> {
    if &plan_whonix_workstation_recovery(directories)? != plan {
        return Err(ImageError::SourceNotVerified);
    }
    cleanup_whonix_recovery_tree_with_hook(directories, plan, || Ok(()))?;
    if plan.extraction_root.exists() {
        return Err(ImageError::Metadata(
            "controlled Workstation extraction root remains after cleanup".to_owned(),
        ));
    }
    clear_whonix_workstation_intent(directories)?;
    if !matches!(
        inspect_whonix_workstation_preparation(directories)?,
        WhonixPreparationState::Missing
    ) {
        return Err(ImageError::Metadata(
            "Workstation preparation did not return to Missing".to_owned(),
        ));
    }
    Ok(())
}

fn cleanup_whonix_recovery_tree_with_hook(
    directories: &ImageDirectories,
    plan: &WhonixWorkstationRecoveryPlan,
    after_bind: impl FnOnce() -> Result<(), ImageError>,
) -> Result<(), ImageError> {
    let root_name = plan
        .extraction_root
        .file_name()
        .ok_or(ImageError::SourceNotVerified)?;
    let downloads = File::open(&directories.downloads)?;
    if opened_directory_identity(&directories.downloads, &downloads)? != plan.downloads_identity {
        return Err(ImageError::SourceNotVerified);
    }
    let downloads_fd_path = descriptor_path(&downloads);
    let root_entry = downloads_fd_path.join(root_name);
    if verified_directory_identity_at(&root_entry, &plan.extraction_root)? != plan.root_identity {
        return Err(ImageError::SourceNotVerified);
    }
    let root = File::open(&root_entry)?;
    if opened_directory_identity(&plan.extraction_root, &root)? != plan.root_identity {
        return Err(ImageError::SourceNotVerified);
    }

    after_bind()?;

    // Refuse parent/root pathname replacement after the descriptors were
    // bound. All deletion below is rooted at those already-open descriptors.
    if verified_directory_identity(&directories.downloads)? != plan.downloads_identity
        || opened_directory_identity(&directories.downloads, &downloads)? != plan.downloads_identity
        || verified_directory_identity_at(&root_entry, &plan.extraction_root)? != plan.root_identity
        || opened_directory_identity(&plan.extraction_root, &root)? != plan.root_identity
    {
        return Err(ImageError::SourceNotVerified);
    }

    let root_fd_path = descriptor_path(&root);
    let mut actual = Vec::new();
    for entry in fs::read_dir(&root_fd_path)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| ImageError::SourceNotVerified)?;
        let logical_path = plan.extraction_root.join(&name);
        actual.push(verified_file_identity_at(&entry.path(), &logical_path)?);
    }
    actual.sort_by(|left, right| left.path.cmp(&right.path));
    if actual != plan.entry_identities {
        return Err(ImageError::SourceNotVerified);
    }

    for expected in &plan.entry_identities {
        let name = expected
            .path
            .file_name()
            .ok_or(ImageError::SourceNotVerified)?;
        let entry = root_fd_path.join(name);
        if verified_file_identity_at(&entry, &expected.path)? != *expected {
            return Err(ImageError::SourceNotVerified);
        }
        fs::remove_file(entry)?;
    }
    root.sync_all()?;

    if !same_directory_object(
        &verified_directory_identity_at(&root_entry, &plan.extraction_root)?,
        &plan.root_identity,
    ) {
        return Err(ImageError::SourceNotVerified);
    }
    fs::remove_dir(&root_entry)?;
    downloads.sync_all()?;
    if fs::symlink_metadata(&root_entry).is_ok() {
        return Err(ImageError::SourceNotVerified);
    }
    Ok(())
}

/// Reads the immutable Whonix provenance for planning without rehashing the
/// large prepared image. Real creation must use `verified_whonix_gateway`.
///
/// # Errors
/// Refuses missing/incomplete metadata, intent files, wrong release identity,
/// or malformed bundle provenance.
pub fn read_whonix_verified_metadata(
    directories: &ImageDirectories,
) -> Result<WhonixGatewayImageMetadata, ImageError> {
    let metadata_path = directories.images.join("whonix.metadata.json");
    let metadata_temp = directories.images.join("whonix.metadata.json.tmp");
    let intent = directories.images.join("whonix.intent.json");
    if intent.exists() || metadata_temp.exists() {
        return Err(ImageError::SourceNotVerified);
    }
    let metadata: WhonixGatewayImageMetadata = serde_json::from_slice(&fs::read(metadata_path)?)
        .map_err(|error| ImageError::Metadata(error.to_string()))?;
    let prepared = directories.images.join(WHONIX_GATEWAY_DISK_FILENAME);
    let archive = directories.downloads.join(WHONIX_ARCHIVE_FILENAME);
    if metadata.status != ImageStatus::Verified
        || metadata.prepared_qcow2_path != prepared
        || !is_single_regular_file(&prepared)
        || !is_single_regular_file(&archive)
    {
        return Err(ImageError::SourceNotVerified);
    }
    let rebuilt = whonix_bundle_provenance(
        &WhonixSignatureEvidence {
            signature_valid: true,
            primary_signer_fingerprint: metadata.provenance.signer_fingerprint.clone(),
            notation: metadata.provenance.signature_notation.clone(),
            signature_unix_seconds: metadata.provenance.signature_unix_seconds,
        },
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| ImageError::Metadata(error.to_string()))?
            .as_secs(),
        metadata.provenance.archive_sha256.clone(),
        metadata.provenance.artifact_sha256.clone(),
    )
    .map_err(|_| ImageError::SourceNotVerified)?;
    if rebuilt != metadata.provenance
        || metadata.provenance.release != WHONIX_RELEASE
        || metadata.provenance.archive_filename != WHONIX_ARCHIVE_FILENAME
        || metadata.provenance.source_url != WHONIX_SOURCE_URL
        || metadata.provenance.signer_fingerprint != WHONIX_SIGNING_KEY_FINGERPRINT
        || metadata.provenance.signature_notation != WHONIX_SIGNATURE_NOTATION
    {
        return Err(ImageError::SourceNotVerified);
    }
    Ok(metadata)
}

/// Classifies Whonix prepared-image state without trusting a file by name.
///
/// # Errors
/// Returns an error when filesystem or metadata evidence cannot be read.
pub fn inspect_whonix_preparation(
    directories: &ImageDirectories,
) -> Result<WhonixPreparationState, ImageError> {
    let metadata_path = directories.images.join("whonix.metadata.json");
    let metadata_temp = directories.images.join("whonix.metadata.json.tmp");
    let intent = directories.images.join("whonix.intent.json");
    let prepared = directories.images.join(WHONIX_GATEWAY_DISK_FILENAME);
    if intent.exists() || metadata_temp.exists() {
        return Ok(WhonixPreparationState::Preparing);
    }
    if !metadata_path.exists() {
        return Ok(if prepared.exists() {
            WhonixPreparationState::OrphanedPreparedImage
        } else {
            WhonixPreparationState::Missing
        });
    }
    if !prepared.exists() {
        return Ok(WhonixPreparationState::Preparing);
    }
    let metadata: WhonixGatewayImageMetadata =
        match serde_json::from_slice(&fs::read(&metadata_path)?) {
            Ok(metadata) => metadata,
            Err(error) => {
                return Ok(WhonixPreparationState::Conflict(format!(
                    "Whonix metadata cannot be parsed: {error}"
                )));
            }
        };
    let archive = directories.downloads.join(WHONIX_ARCHIVE_FILENAME);
    let rebuilt_provenance = whonix_bundle_provenance(
        &WhonixSignatureEvidence {
            signature_valid: true,
            primary_signer_fingerprint: metadata.provenance.signer_fingerprint.clone(),
            notation: metadata.provenance.signature_notation.clone(),
            signature_unix_seconds: metadata.provenance.signature_unix_seconds,
        },
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| ImageError::Metadata(error.to_string()))?
            .as_secs(),
        metadata.provenance.archive_sha256.clone(),
        metadata.provenance.artifact_sha256.clone(),
    )
    .ok();
    let prepared_metadata = fs::metadata(&prepared).ok();
    if metadata.status != ImageStatus::Verified
        || metadata.prepared_qcow2_path != prepared
        || !is_single_regular_file(&prepared)
        || !is_single_regular_file(&archive)
        || sha256_file(&prepared)? != metadata.prepared_qcow2_checksum
        || prepared_metadata.as_ref().map(fs::Metadata::len)
            != Some(metadata.prepared_logical_bytes)
        || qcow2_virtual_size(&prepared)? != metadata.prepared_virtual_bytes
        || sha256_file(&archive)? != metadata.provenance.archive_sha256
        || rebuilt_provenance.as_ref() != Some(&metadata.provenance)
        || metadata.provenance.release != WHONIX_RELEASE
        || metadata.provenance.archive_filename != WHONIX_ARCHIVE_FILENAME
        || metadata.provenance.source_url != WHONIX_SOURCE_URL
        || metadata.provenance.signer_fingerprint != WHONIX_SIGNING_KEY_FINGERPRINT
        || metadata.provenance.signature_notation != WHONIX_SIGNATURE_NOTATION
    {
        return Ok(WhonixPreparationState::Conflict(
            "prepared Gateway base differs from authenticated provenance".to_owned(),
        ));
    }
    Ok(WhonixPreparationState::Verified(Box::new(metadata)))
}

fn clear_whonix_intent(directories: &ImageDirectories) -> Result<(), ImageError> {
    let path = directories.images.join("whonix.intent.json");
    if path.exists() {
        fs::remove_file(path)?;
        sync_directory(&directories.images)?;
    }
    Ok(())
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
    create_extraction_root_for(downloads, ".kali-extract-")
}

fn create_extraction_root_for(downloads: &Path, prefix: &str) -> Result<PathBuf, ImageError> {
    let root = extraction_root_path_for(downloads, prefix)?;
    create_extraction_root_at(downloads, &root)?;
    Ok(root)
}

fn extraction_root_path_for(downloads: &Path, prefix: &str) -> Result<PathBuf, ImageError> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| ImageError::Metadata(error.to_string()))?
        .as_nanos();
    Ok(downloads.join(format!("{prefix}{}-{nonce}", std::process::id())))
}

fn create_extraction_root_at(downloads: &Path, root: &Path) -> Result<(), ImageError> {
    fs::create_dir(root)?;
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    sync_directory(root)?;
    sync_directory(downloads)?;
    Ok(())
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
    cleanup_extraction_root_for(downloads, root, ".kali-extract-")
}

fn cleanup_extraction_root_for(
    downloads: &Path,
    root: &Path,
    prefix: &str,
) -> Result<(), ImageError> {
    let controlled_name = root
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with(prefix));
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
            "extracted artifact is not one regular file inside the controlled root".to_owned(),
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
        ImageError::Metadata("prepared image destination has no parent".to_owned())
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
        .ok_or_else(|| ImageError::Metadata("extracted image source has no parent".to_owned()))?;
    sync_directory(source_parent)?;
    if !is_single_regular_file(destination) {
        return Err(ImageError::UnsupportedImage(
            "promoted prepared image is not one regular file".to_owned(),
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

fn promote_verified_without_overwrite(
    source: &Path,
    destination: &Path,
    evidence: &LifecycleVerifiedFile,
) -> Result<VerifiedFileIdentity, ImageError> {
    revalidate_lifecycle_file(evidence)?;
    if evidence.identity.path != source {
        return Err(ImageError::SourceNotVerified);
    }
    let destination_parent = destination.parent().ok_or_else(|| {
        ImageError::Metadata("prepared image destination has no parent".to_owned())
    })?;
    let parent = fs::symlink_metadata(destination_parent)?;
    if !parent.file_type().is_dir() || parent.dev() != evidence.identity.device {
        return Err(ImageError::SourceNotVerified);
    }
    File::open(source)?.sync_all()?;
    fs::hard_link(source, destination).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            ImageError::VerifiedImageExists(destination.to_owned())
        } else {
            error.into()
        }
    })?;
    let linked = opened_file_identity_allow_links(destination, &evidence.file)?;
    let destination_link = file_identity_allow_links(destination)?;
    if linked != destination_link
        || linked.device != evidence.identity.device
        || linked.inode != evidence.identity.inode
        || linked.bytes != evidence.identity.bytes
        || linked.modified_seconds != evidence.identity.modified_seconds
        || linked.modified_nanoseconds != evidence.identity.modified_nanoseconds
        || linked.mode != evidence.identity.mode
        || linked.links != 2
    {
        return Err(ImageError::SourceNotVerified);
    }
    sync_directory(destination_parent)?;
    if file_identity_allow_links(source)?.inode != evidence.identity.inode {
        return Err(ImageError::SourceNotVerified);
    }
    fs::remove_file(source)?;
    let source_parent = source
        .parent()
        .ok_or_else(|| ImageError::Metadata("extracted image source has no parent".to_owned()))?;
    sync_directory(source_parent)?;
    sync_directory(destination_parent)?;
    let published = verified_file_identity(destination)?;
    let opened = opened_file_identity(destination, &evidence.file)?;
    if published != opened
        || published.device != evidence.identity.device
        || published.inode != evidence.identity.inode
        || published.bytes != evidence.identity.bytes
        || published.modified_seconds != evidence.identity.modified_seconds
        || published.modified_nanoseconds != evidence.identity.modified_nanoseconds
        || published.mode != evidence.identity.mode
        || published.links != 1
    {
        return Err(ImageError::SourceNotVerified);
    }
    Ok(published)
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
    let operation = match path.file_name().and_then(|name| name.to_str()) {
        Some(WHONIX_ARCHIVE_FILENAME) => FullReadOperation::ArchiveHash,
        Some(WHONIX_GATEWAY_DISK_FILENAME) => FullReadOperation::GatewayHash,
        Some(WHONIX_WORKSTATION_DISK_FILENAME) => FullReadOperation::WorkstationHash,
        _ => FullReadOperation::OtherHash,
    };
    let file = File::open(path)?;
    sha256_open_file(file, path, operation)
}

fn sha256_open_file(
    mut file: File,
    path: &Path,
    operation: FullReadOperation,
) -> Result<String, ImageError> {
    const PROGRESS_BYTES: u64 = 4 * 1024 * 1024 * 1024;
    record_full_read(operation);
    let label = match operation {
        FullReadOperation::ArchiveHash => "archive hashing",
        FullReadOperation::ArchiveOpenPgpVerification => "OpenPGP archive verification",
        FullReadOperation::ArchiveListing => "archive listing",
        FullReadOperation::ArchiveExtraction => "archive extraction",
        FullReadOperation::GatewayHash => "Gateway hash",
        FullReadOperation::WorkstationHash => "Workstation hash",
        FullReadOperation::ExtractedBundleArtifactHash(_) => "extracted bundle artifact hash",
        FullReadOperation::WorkstationImport => "Workstation import",
        FullReadOperation::OtherHash => "file hashing",
    };
    let expected_bytes = file.metadata()?.len();
    let started = Instant::now();
    eprintln!(
        "[forge] phase start: {label} path={} logical-bytes={expected_bytes}",
        path.display()
    );
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut total = 0_u64;
    let mut next_progress = PROGRESS_BYTES;
    let mut last_progress = Instant::now();
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        total = total.saturating_add(read as u64);
        if total >= next_progress || last_progress.elapsed() >= Duration::from_secs(10) {
            let percent_tenths = total
                .saturating_mul(1_000)
                .checked_div(expected_bytes)
                .unwrap_or(1_000);
            eprintln!(
                "[forge] progress: {label} path={} read-bytes={total}/{expected_bytes} ({}.{:01}%) elapsed={:.1}s",
                path.display(),
                percent_tenths / 10,
                percent_tenths % 10,
                started.elapsed().as_secs_f64()
            );
            next_progress = total.saturating_add(PROGRESS_BYTES);
            last_progress = Instant::now();
        }
    }
    let digest = format!("{:x}", hasher.finalize());
    eprintln!(
        "[forge] phase done: {label} path={} read-bytes={total} elapsed={:.1}s",
        path.display(),
        started.elapsed().as_secs_f64()
    );
    Ok(digest)
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
        workstation_extracted: Vec<u8>,
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
                workstation_extracted: image.to_vec(),
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
            if matches!(url, FEDORA_SOURCE_URL | KALI_SOURCE_URL | WHONIX_SOURCE_URL) {
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

        fn verify_whonix_signature(
            &mut self,
            _: &Path,
            _: &Path,
            _: &Path,
        ) -> Result<WhonixSignatureEvidence, ImageError> {
            if self.signature_valid {
                Ok(whonix_signature())
            } else {
                Err(ImageError::SignatureVerification(
                    "bad Whonix signature".to_owned(),
                ))
            }
        }

        fn extract_whonix_bundle(
            &mut self,
            _: &Path,
            destination: &Path,
        ) -> Result<Vec<ArchiveEntry>, ImageError> {
            record_full_read(FullReadOperation::ArchiveListing);
            record_full_read(FullReadOperation::ArchiveExtraction);
            if self.partial_extraction_failure {
                fs::write(destination.join(WHONIX_GATEWAY_DISK_FILENAME), b"partial")?;
                return Err(ImageError::Download(
                    "simulated interrupted Whonix extraction".to_owned(),
                ));
            }
            for entry in whonix_bundle_layout() {
                let bytes = match entry.role {
                    BundleArtifactRole::GatewayDisk => self.extracted.as_slice(),
                    BundleArtifactRole::WorkstationDisk => self.workstation_extracted.as_slice(),
                    _ => entry.path.as_bytes(),
                };
                fs::write(destination.join(entry.path), bytes)?;
            }
            Ok(whonix_entries())
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

    fn whonix_entries() -> Vec<ArchiveEntry> {
        whonix_bundle_layout()
            .into_iter()
            .map(|entry| ArchiveEntry {
                path: entry.path.to_owned(),
                kind: ArchiveEntryKind::RegularFile,
            })
            .collect()
    }

    fn whonix_signature() -> WhonixSignatureEvidence {
        WhonixSignatureEvidence {
            signature_valid: true,
            primary_signer_fingerprint: WHONIX_SIGNING_KEY_FINGERPRINT.to_owned(),
            notation: WHONIX_SIGNATURE_NOTATION.to_owned(),
            signature_unix_seconds: 1_784_091_820,
        }
    }

    fn qcow2_header(virtual_bytes: u64) -> Vec<u8> {
        let mut header = vec![0_u8; 32];
        header[..4].copy_from_slice(b"QFI\xfb");
        header[4..8].copy_from_slice(&3_u32.to_be_bytes());
        header[24..32].copy_from_slice(&virtual_bytes.to_be_bytes());
        header
    }

    #[test]
    fn whonix_gpg_status_parser_uses_primary_fingerprint_not_signing_subkey() {
        let status = format!(
            "[GNUPG:] VALIDSIG SUBKEY 2026-07-15 1784091820 0 4 0 1 10 00 {WHONIX_SIGNING_KEY_FINGERPRINT}\n[GNUPG:] NOTATION_NAME file@name\n[GNUPG:] NOTATION_DATA {WHONIX_ARCHIVE_FILENAME}\n"
        );
        assert_eq!(
            parse_whonix_gpg_status(&status).unwrap(),
            whonix_signature()
        );
    }

    #[test]
    fn whonix_gateway_preparation_publishes_only_the_typed_gateway_base() {
        let test = TestDirectories::new();
        let image = qcow2_header(100 * 1024 * 1024);
        let mut fetcher = FixtureFetcher::valid(&image);
        let metadata = fetch_whonix_gateway(&test.directories, &mut fetcher).unwrap();
        assert_eq!(fs::read(&metadata.prepared_qcow2_path).unwrap(), image);
        assert!(
            !test
                .directories
                .images
                .join(WHONIX_WORKSTATION_DISK_FILENAME)
                .exists()
        );
        assert_eq!(metadata.provenance.artifact_sha256.len(), 6);
        assert!(
            metadata
                .provenance
                .artifact_sha256
                .iter()
                .any(|(role, _)| *role == BundleArtifactRole::WorkstationDisk)
        );
        assert_eq!(
            verified_whonix_gateway(&test.directories).unwrap(),
            metadata
        );
    }

    #[test]
    fn whonix_workstation_publication_selects_exact_role_without_download() {
        let test = TestDirectories::new();
        let gateway_image = qcow2_header(WHONIX_WORKSTATION_VIRTUAL_BYTES);
        let mut workstation_image = gateway_image.clone();
        workstation_image.push(0x17);
        let mut fetcher = FixtureFetcher::valid(&gateway_image);
        fetcher.workstation_extracted = workstation_image.clone();
        let gateway = fetch_whonix_gateway(&test.directories, &mut fetcher).unwrap();
        let downloads = fetcher.downloads;

        let workstation = prepare_whonix_workstation(&test.directories, &mut fetcher).unwrap();
        assert_eq!(fetcher.downloads, downloads);
        assert_eq!(
            fs::read(&workstation.prepared_qcow2_path).unwrap(),
            workstation_image
        );
        assert_ne!(
            workstation.prepared_qcow2_checksum,
            gateway.prepared_qcow2_checksum
        );
        assert_eq!(workstation.provenance, gateway.provenance);
        assert_eq!(
            fs::symlink_metadata(&workstation.prepared_qcow2_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(matches!(
            inspect_whonix_workstation_preparation(&test.directories).unwrap(),
            WhonixPreparationState::Verified(_)
        ));
    }

    #[test]
    fn whonix_workstation_execute_revalidation_is_not_metadata_authorized() {
        let test = TestDirectories::new();
        let image = qcow2_header(WHONIX_WORKSTATION_VIRTUAL_BYTES);
        let mut fetcher = FixtureFetcher::valid(&image);
        fetch_whonix_gateway(&test.directories, &mut fetcher).unwrap();
        prepare_whonix_workstation(&test.directories, &mut fetcher).unwrap();
        assert!(read_whonix_verified_metadata(&test.directories).is_ok());

        fetcher.signature_valid = false;
        assert!(matches!(
            revalidate_whonix_workstation(&test.directories, &mut fetcher),
            Err(ImageError::SignatureVerification(_))
        ));
    }

    #[test]
    fn workstation_execute_proof_reuses_only_unchanged_byte_backed_identity() {
        let test = TestDirectories::new();
        let image = qcow2_header(WHONIX_WORKSTATION_VIRTUAL_BYTES);
        let mut fetcher = FixtureFetcher::valid(&image);
        fetch_whonix_gateway(&test.directories, &mut fetcher).unwrap();
        prepare_whonix_workstation(&test.directories, &mut fetcher).unwrap();

        let (_, proof) =
            prepare_whonix_workstation_for_execute(&test.directories, &mut fetcher).unwrap();
        assert!(revalidate_whonix_workstation_execute_proof(&test.directories, &proof).is_ok());

        let workstation = test
            .directories
            .images
            .join(WHONIX_WORKSTATION_DISK_FILENAME);
        let mut changed = fs::read(&workstation).unwrap();
        changed.push(0x42);
        fs::write(workstation, changed).unwrap();
        assert!(matches!(
            revalidate_whonix_workstation_execute_proof(&test.directories, &proof),
            Err(ImageError::SourceNotVerified)
        ));
    }

    #[test]
    fn verified_workstation_execute_has_one_hash_per_large_artifact() {
        let test = TestDirectories::new();
        let image = qcow2_header(WHONIX_WORKSTATION_VIRTUAL_BYTES);
        let mut fetcher = FixtureFetcher::valid(&image);
        fetch_whonix_gateway(&test.directories, &mut fetcher).unwrap();
        prepare_whonix_workstation(&test.directories, &mut fetcher).unwrap();

        let (result, reads) = audit_full_reads(|| {
            prepare_whonix_workstation_for_execute(&test.directories, &mut fetcher)
        });
        result.unwrap();
        assert_eq!(
            reads,
            vec![
                FullReadOperation::GatewayHash,
                FullReadOperation::ArchiveHash,
                FullReadOperation::WorkstationHash,
                FullReadOperation::ArchiveOpenPgpVerification,
            ]
        );
    }

    #[test]
    fn missing_workstation_execute_has_one_existing_input_hash_each() {
        let test = TestDirectories::new();
        let image = qcow2_header(WHONIX_WORKSTATION_VIRTUAL_BYTES);
        let mut fetcher = FixtureFetcher::valid(&image);
        fetch_whonix_gateway(&test.directories, &mut fetcher).unwrap();

        let (result, reads) = audit_full_reads(|| {
            prepare_whonix_workstation_for_execute(&test.directories, &mut fetcher)
        });
        result.unwrap();
        assert_eq!(
            reads,
            vec![
                FullReadOperation::ArchiveHash,
                FullReadOperation::GatewayHash,
                FullReadOperation::ArchiveOpenPgpVerification,
                FullReadOperation::ArchiveListing,
                FullReadOperation::ArchiveExtraction,
                FullReadOperation::ExtractedBundleArtifactHash(BundleArtifactRole::GatewayDisk,),
                FullReadOperation::ExtractedBundleArtifactHash(BundleArtifactRole::GatewayXml),
                FullReadOperation::WorkstationHash,
                FullReadOperation::ExtractedBundleArtifactHash(BundleArtifactRole::WorkstationXml,),
                FullReadOperation::ExtractedBundleArtifactHash(BundleArtifactRole::License),
                FullReadOperation::ExtractedBundleArtifactHash(BundleArtifactRole::Disclaimer),
            ]
        );
        assert_eq!(
            reads
                .iter()
                .filter(|operation| **operation == FullReadOperation::ArchiveHash)
                .count(),
            1
        );
        assert_eq!(
            reads
                .iter()
                .filter(|operation| **operation == FullReadOperation::GatewayHash)
                .count(),
            1
        );
        assert_eq!(
            reads
                .iter()
                .filter(|operation| **operation == FullReadOperation::WorkstationHash)
                .count(),
            1
        );
        assert_eq!(
            reads
                .iter()
                .filter(|operation| {
                    matches!(operation, FullReadOperation::ExtractedBundleArtifactHash(_))
                })
                .count(),
            5
        );
    }

    #[test]
    fn workstation_execute_proof_refuses_inode_replacement() {
        let test = TestDirectories::new();
        let image = qcow2_header(WHONIX_WORKSTATION_VIRTUAL_BYTES);
        let mut fetcher = FixtureFetcher::valid(&image);
        fetch_whonix_gateway(&test.directories, &mut fetcher).unwrap();
        prepare_whonix_workstation(&test.directories, &mut fetcher).unwrap();
        let (_, proof) =
            prepare_whonix_workstation_for_execute(&test.directories, &mut fetcher).unwrap();
        let workstation = test
            .directories
            .images
            .join(WHONIX_WORKSTATION_DISK_FILENAME);
        let replacement = test.directories.images.join("replacement.qcow2");
        fs::write(&replacement, fs::read(&workstation).unwrap()).unwrap();
        fs::rename(replacement, workstation).unwrap();
        assert!(matches!(
            open_whonix_workstation_execute_source(&test.directories, &proof),
            Err(ImageError::SourceNotVerified)
        ));
    }

    #[test]
    fn lifecycle_evidence_refuses_archive_drift_before_extraction() {
        let test = TestDirectories::new();
        fs::create_dir_all(&test.directories.downloads).unwrap();
        let archive = test.directories.downloads.join(WHONIX_ARCHIVE_FILENAME);
        fs::write(&archive, b"authenticated archive").unwrap();
        let digest = format!("{:x}", Sha256::digest(b"authenticated archive"));
        let evidence =
            verify_file_bytes(&archive, &digest, FullReadOperation::ArchiveHash).unwrap();
        let replacement = test.directories.downloads.join("archive-replacement");
        fs::write(&replacement, b"authenticated archive").unwrap();
        fs::rename(replacement, archive).unwrap();
        assert!(matches!(
            revalidate_lifecycle_file(&evidence),
            Err(ImageError::SourceNotVerified)
        ));
    }

    #[test]
    fn lifecycle_evidence_refuses_extracted_file_drift_before_publication() {
        let test = TestDirectories::new();
        fs::create_dir_all(&test.directories.downloads).unwrap();
        fs::create_dir_all(&test.directories.images).unwrap();
        let source = test
            .directories
            .downloads
            .join(WHONIX_WORKSTATION_DISK_FILENAME);
        let destination = test
            .directories
            .images
            .join(WHONIX_WORKSTATION_DISK_FILENAME);
        fs::write(&source, b"verified workstation").unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
        let digest = format!("{:x}", Sha256::digest(b"verified workstation"));
        let evidence =
            verify_file_bytes(&source, &digest, FullReadOperation::WorkstationHash).unwrap();
        let replacement = test.directories.downloads.join("replacement");
        fs::write(&replacement, b"verified workstation").unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(replacement, &source).unwrap();
        assert!(matches!(
            promote_verified_without_overwrite(&source, &destination, &evidence),
            Err(ImageError::SourceNotVerified)
        ));
        assert!(!destination.exists());
    }

    #[test]
    fn lifecycle_evidence_refuses_identical_inode_replacement_after_publication() {
        let test = TestDirectories::new();
        let image = qcow2_header(WHONIX_WORKSTATION_VIRTUAL_BYTES);
        let mut fetcher = FixtureFetcher::valid(&image);
        fetch_whonix_gateway(&test.directories, &mut fetcher).unwrap();
        let workstation = test
            .directories
            .images
            .join(WHONIX_WORKSTATION_DISK_FILENAME);
        let replacement = test.directories.images.join("published-replacement");
        let replacement_bytes = image.clone();

        let result = prepare_whonix_workstation_for_execute_with_hook(
            &test.directories,
            &mut fetcher,
            || {
                fs::write(&replacement, replacement_bytes)?;
                fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600))?;
                fs::rename(&replacement, &workstation)?;
                Ok(())
            },
        );
        assert!(matches!(result, Err(ImageError::SourceNotVerified)));
    }

    #[test]
    fn opened_execute_source_stays_bound_to_verified_inode() {
        let test = TestDirectories::new();
        let image = qcow2_header(WHONIX_WORKSTATION_VIRTUAL_BYTES);
        let mut fetcher = FixtureFetcher::valid(&image);
        fetch_whonix_gateway(&test.directories, &mut fetcher).unwrap();
        prepare_whonix_workstation(&test.directories, &mut fetcher).unwrap();
        let (_, proof) =
            prepare_whonix_workstation_for_execute(&test.directories, &mut fetcher).unwrap();
        let mut source = open_whonix_workstation_execute_source(&test.directories, &proof).unwrap();
        let path = test
            .directories
            .images
            .join(WHONIX_WORKSTATION_DISK_FILENAME);
        let replacement = test.directories.images.join("replacement-after-open");
        fs::write(&replacement, b"attacker bytes").unwrap();
        fs::rename(replacement, path).unwrap();
        let mut consumed = Vec::new();
        source.read_to_end(&mut consumed).unwrap();
        assert_eq!(consumed, image);
    }

    fn interrupted_workstation_fixture(test: &TestDirectories) -> WhonixWorkstationRecoveryPlan {
        fs::create_dir_all(&test.directories.downloads).unwrap();
        fs::create_dir_all(&test.directories.images).unwrap();
        fs::write(
            test.directories.downloads.join(WHONIX_ARCHIVE_FILENAME),
            b"verified archive remains out of recovery scope",
        )
        .unwrap();
        fs::write(
            test.directories.images.join(WHONIX_GATEWAY_DISK_FILENAME),
            b"verified Gateway cache remains out of recovery scope",
        )
        .unwrap();
        let root = test.directories.downloads.join(".whonix-extract-test");
        fs::create_dir(&root).unwrap();
        for entry in whonix_bundle_layout() {
            fs::write(root.join(entry.path), b"controlled temporary artifact").unwrap();
        }
        write_json_atomic(
            &test.directories.images,
            "whonix-workstation.intent.json.tmp",
            "whonix-workstation.intent.json",
            &WhonixPreparationIntent {
                status: "Preparing".to_owned(),
                archive_path: test.directories.downloads.join(WHONIX_ARCHIVE_FILENAME),
                prepared_qcow2_path: test
                    .directories
                    .images
                    .join(WHONIX_WORKSTATION_DISK_FILENAME),
                extraction_root: Some(root),
            },
        )
        .unwrap();
        plan_whonix_workstation_recovery(&test.directories).unwrap()
    }

    #[test]
    fn explicit_workstation_recovery_returns_prepublication_state_to_missing() {
        let test = TestDirectories::new();
        let plan = interrupted_workstation_fixture(&test);
        assert!(plan.extracted_workstation_path.exists());
        execute_whonix_workstation_recovery(&test.directories, &plan).unwrap();
        assert!(!plan.extraction_root.exists());
        assert!(!plan.intent_path.exists());
        assert!(
            test.directories
                .downloads
                .join(WHONIX_ARCHIVE_FILENAME)
                .exists()
        );
        assert!(
            test.directories
                .images
                .join(WHONIX_GATEWAY_DISK_FILENAME)
                .exists()
        );
        assert!(matches!(
            inspect_whonix_workstation_preparation(&test.directories).unwrap(),
            WhonixPreparationState::Missing
        ));
    }

    #[test]
    fn explicit_workstation_recovery_refuses_plan_drift() {
        let test = TestDirectories::new();
        let plan = interrupted_workstation_fixture(&test);
        fs::write(plan.extraction_root.join("unexpected"), b"drift").unwrap();
        assert!(execute_whonix_workstation_recovery(&test.directories, &plan).is_err());
        assert!(plan.extraction_root.exists());
        assert!(plan.intent_path.exists());
    }

    #[test]
    fn recovery_refuses_root_replacement_in_consumption_window() {
        let test = TestDirectories::new();
        let plan = interrupted_workstation_fixture(&test);
        let displaced = test.directories.downloads.join("approved-root-displaced");
        let replacement = plan.extraction_root.clone();
        let result = cleanup_whonix_recovery_tree_with_hook(&test.directories, &plan, || {
            fs::rename(&replacement, &displaced)?;
            fs::create_dir(&replacement)?;
            fs::write(replacement.join("replacement-sentinel"), b"do not delete")?;
            Ok(())
        });
        assert!(matches!(result, Err(ImageError::SourceNotVerified)));
        assert!(displaced.join(WHONIX_WORKSTATION_DISK_FILENAME).exists());
        assert!(replacement.join("replacement-sentinel").exists());
    }

    #[test]
    fn recovery_refuses_parent_replacement_in_consumption_window() {
        let test = TestDirectories::new();
        let plan = interrupted_workstation_fixture(&test);
        let downloads = test.directories.downloads.clone();
        let displaced = test.root.join("downloads-displaced");
        let result = cleanup_whonix_recovery_tree_with_hook(&test.directories, &plan, || {
            fs::rename(&downloads, &displaced)?;
            fs::create_dir(&downloads)?;
            fs::write(
                downloads.join("replacement-parent-sentinel"),
                b"do not delete",
            )?;
            Ok(())
        });
        assert!(matches!(result, Err(ImageError::SourceNotVerified)));
        assert!(
            displaced
                .join(plan.extraction_root.file_name().unwrap())
                .join(WHONIX_WORKSTATION_DISK_FILENAME)
                .exists()
        );
        assert!(downloads.join("replacement-parent-sentinel").exists());
    }

    #[test]
    fn recovery_refuses_expected_file_replacement_in_consumption_window() {
        let test = TestDirectories::new();
        let plan = interrupted_workstation_fixture(&test);
        let workstation = plan.extracted_workstation_path.clone();
        let result = cleanup_whonix_recovery_tree_with_hook(&test.directories, &plan, || {
            let replacement = plan.extraction_root.join("replacement");
            fs::write(&replacement, b"different inode")?;
            fs::rename(replacement, &workstation)?;
            Ok(())
        });
        assert!(matches!(result, Err(ImageError::SourceNotVerified)));
        assert!(workstation.exists());
    }

    #[test]
    fn recovery_refuses_unexpected_or_symlink_entry_in_consumption_window() {
        for symlink in [false, true] {
            let test = TestDirectories::new();
            let plan = interrupted_workstation_fixture(&test);
            let result = cleanup_whonix_recovery_tree_with_hook(&test.directories, &plan, || {
                let unexpected = plan.extraction_root.join("unexpected");
                if symlink {
                    std::os::unix::fs::symlink(
                        test.directories.downloads.join(WHONIX_ARCHIVE_FILENAME),
                        unexpected,
                    )?;
                } else {
                    fs::write(unexpected, b"unexpected")?;
                }
                Ok(())
            });
            assert!(result.is_err());
            assert!(plan.extracted_workstation_path.exists());
        }
    }

    #[test]
    fn recovery_fd_cleanup_removes_only_the_approved_tree() {
        let test = TestDirectories::new();
        fs::create_dir_all(&test.directories.downloads).unwrap();
        let unrelated = test.directories.downloads.join("unrelated-tree");
        fs::create_dir(&unrelated).unwrap();
        fs::write(unrelated.join("sentinel"), b"preserve").unwrap();
        let plan = interrupted_workstation_fixture(&test);
        cleanup_whonix_recovery_tree_with_hook(&test.directories, &plan, || Ok(())).unwrap();
        assert!(!plan.extraction_root.exists());
        assert_eq!(fs::read(unrelated.join("sentinel")).unwrap(), b"preserve");
    }

    #[test]
    fn whonix_workstation_refuses_gateway_disk_substitution_and_corruption() {
        let test = TestDirectories::new();
        let gateway_image = qcow2_header(WHONIX_WORKSTATION_VIRTUAL_BYTES);
        let mut workstation_image = gateway_image.clone();
        workstation_image.push(0x17);
        let mut fetcher = FixtureFetcher::valid(&gateway_image);
        fetcher.workstation_extracted = workstation_image;
        fetch_whonix_gateway(&test.directories, &mut fetcher).unwrap();
        let workstation = prepare_whonix_workstation(&test.directories, &mut fetcher).unwrap();
        fs::write(&workstation.prepared_qcow2_path, gateway_image).unwrap();
        assert!(matches!(
            inspect_whonix_workstation_preparation(&test.directories).unwrap(),
            WhonixPreparationState::Conflict(_)
        ));
        fs::remove_file(&workstation.prepared_qcow2_path).unwrap();
        assert!(matches!(
            inspect_whonix_workstation_preparation(&test.directories).unwrap(),
            WhonixPreparationState::Preparing
        ));
        assert!(matches!(
            revalidate_whonix_workstation(&test.directories, &mut fetcher),
            Err(ImageError::SourceNotVerified)
        ));
    }

    #[test]
    fn whonix_workstation_preparation_failure_publishes_no_state_or_base() {
        let test = TestDirectories::new();
        let image = qcow2_header(WHONIX_WORKSTATION_VIRTUAL_BYTES);
        let mut fetcher = FixtureFetcher::valid(&image);
        fetch_whonix_gateway(&test.directories, &mut fetcher).unwrap();
        fetcher.partial_extraction_failure = true;
        assert!(prepare_whonix_workstation(&test.directories, &mut fetcher).is_err());
        assert!(
            !test
                .directories
                .images
                .join(WHONIX_WORKSTATION_DISK_FILENAME)
                .exists()
        );
        assert!(
            !test
                .directories
                .images
                .join("whonix-workstation.metadata.json")
                .exists()
        );
        assert!(matches!(
            inspect_whonix_workstation_preparation(&test.directories).unwrap(),
            WhonixPreparationState::Missing
        ));
    }

    #[test]
    fn whonix_verification_failure_has_zero_prepared_image_mutation() {
        let test = TestDirectories::new();
        let image = qcow2_header(100 * 1024 * 1024);
        let mut fetcher = FixtureFetcher::valid(&image);
        fetcher.signature_valid = false;
        assert!(matches!(
            fetch_whonix_gateway(&test.directories, &mut fetcher),
            Err(ImageError::SignatureVerification(_))
        ));
        assert!(
            !test
                .directories
                .images
                .join(WHONIX_GATEWAY_DISK_FILENAME)
                .exists()
        );
        assert!(!test.directories.images.join("whonix.intent.json").exists());
        assert!(
            !test
                .directories
                .images
                .join("whonix.metadata.json")
                .exists()
        );
    }

    #[test]
    fn whonix_preparation_failure_before_ownership_publishes_no_base() {
        let test = TestDirectories::new();
        let image = qcow2_header(100 * 1024 * 1024);
        let mut fetcher = FixtureFetcher::valid(&image);
        fetcher.partial_extraction_failure = true;
        assert!(matches!(
            fetch_whonix_gateway(&test.directories, &mut fetcher),
            Err(ImageError::Download(_))
        ));
        assert!(
            !test
                .directories
                .images
                .join(WHONIX_GATEWAY_DISK_FILENAME)
                .exists()
        );
        assert_eq!(
            inspect_whonix_preparation(&test.directories).unwrap(),
            WhonixPreparationState::Missing
        );
    }

    #[test]
    fn sparse_gateway_publication_preserves_holes_and_logical_checksum() {
        let test = TestDirectories::new();
        fs::create_dir_all(&test.directories.images).unwrap();
        let source = test.directories.images.join("sparse-source.qcow2");
        let destination = test.directories.images.join("sparse-final.qcow2");
        fs::write(&source, qcow2_header(16 * 1024 * 1024)).unwrap();
        File::options()
            .write(true)
            .open(&source)
            .unwrap()
            .set_len(16 * 1024 * 1024)
            .unwrap();
        let before = fs::metadata(&source).unwrap();
        assert!(before.blocks() * 512 < before.len());
        let checksum = sha256_file(&source).unwrap();
        promote_without_overwrite(&source, &destination, &checksum).unwrap();
        let after = fs::metadata(&destination).unwrap();
        assert_eq!(after.len(), before.len());
        assert!(after.blocks() * 512 < after.len());
        assert_eq!(sha256_file(&destination).unwrap(), checksum);
    }

    #[test]
    fn whonix_preparation_states_refuse_orphan_and_incomplete_publication() {
        let orphan = TestDirectories::new();
        fs::create_dir_all(&orphan.directories.images).unwrap();
        fs::write(
            orphan.directories.images.join(WHONIX_GATEWAY_DISK_FILENAME),
            qcow2_header(100 * 1024 * 1024),
        )
        .unwrap();
        assert_eq!(
            inspect_whonix_preparation(&orphan.directories).unwrap(),
            WhonixPreparationState::OrphanedPreparedImage
        );

        let incomplete = TestDirectories::new();
        let image = qcow2_header(100 * 1024 * 1024);
        let mut fetcher = FixtureFetcher::valid(&image);
        fetch_whonix_gateway(&incomplete.directories, &mut fetcher).unwrap();
        fs::remove_file(
            incomplete
                .directories
                .images
                .join(WHONIX_GATEWAY_DISK_FILENAME),
        )
        .unwrap();
        assert_eq!(
            inspect_whonix_preparation(&incomplete.directories).unwrap(),
            WhonixPreparationState::Preparing
        );
    }

    #[test]
    fn whonix_provenance_refuses_mixed_bundle_or_changed_release_identity() {
        let test = TestDirectories::new();
        let image = qcow2_header(100 * 1024 * 1024);
        let mut fetcher = FixtureFetcher::valid(&image);
        let metadata = fetch_whonix_gateway(&test.directories, &mut fetcher).unwrap();
        let metadata_path = test.directories.images.join("whonix.metadata.json");

        let mut mixed = metadata.clone();
        mixed
            .provenance
            .artifact_sha256
            .iter_mut()
            .find(|(role, _)| *role == BundleArtifactRole::WorkstationDisk)
            .unwrap()
            .1 = "f".repeat(64);
        fs::write(&metadata_path, serde_json::to_vec(&mixed).unwrap()).unwrap();
        assert!(matches!(
            inspect_whonix_preparation(&test.directories).unwrap(),
            WhonixPreparationState::Conflict(_)
        ));

        let mut wrong_release = metadata;
        wrong_release.provenance.release = "different-release".to_owned();
        fs::write(&metadata_path, serde_json::to_vec(&wrong_release).unwrap()).unwrap();
        assert!(matches!(
            inspect_whonix_preparation(&test.directories).unwrap(),
            WhonixPreparationState::Conflict(_)
        ));
    }

    #[test]
    fn exact_whonix_prepared_base_is_idempotently_reused_without_download() {
        let test = TestDirectories::new();
        let image = qcow2_header(100 * 1024 * 1024);
        let mut fetcher = FixtureFetcher::valid(&image);
        let first = fetch_whonix_gateway(&test.directories, &mut fetcher).unwrap();
        let downloads = fetcher.downloads;
        let second = fetch_whonix_gateway(&test.directories, &mut fetcher).unwrap();
        assert_eq!(first, second);
        assert_eq!(fetcher.downloads, downloads);
    }

    #[test]
    fn whonix_bundle_layout_identifies_every_exact_role() {
        let roles = validate_whonix_bundle_entries(&whonix_entries()).unwrap();
        assert_eq!(roles.len(), 6);
        assert!(roles.contains(&(
            BundleArtifactRole::GatewayDisk,
            WHONIX_GATEWAY_DISK_FILENAME.to_owned()
        )));
        assert!(roles.contains(&(
            BundleArtifactRole::WorkstationDisk,
            WHONIX_WORKSTATION_DISK_FILENAME.to_owned()
        )));
        assert!(roles.contains(&(
            BundleArtifactRole::GatewayXml,
            WHONIX_GATEWAY_XML_FILENAME.to_owned()
        )));
        assert!(roles.contains(&(
            BundleArtifactRole::WorkstationXml,
            WHONIX_WORKSTATION_XML_FILENAME.to_owned()
        )));
    }

    #[test]
    fn whonix_tar_execution_disables_unneeded_metadata_and_overwrite_semantics() {
        for required in [
            "--no-same-owner",
            "--no-same-permissions",
            "--no-xattrs",
            "--no-acls",
            "--no-selinux",
            "--touch",
            "--keep-old-files",
            "--no-wildcards",
            "--no-unquote",
        ] {
            assert!(WHONIX_TAR_EXTRACTION_OPTIONS.contains(&required));
        }
        assert!(!WHONIX_TAR_EXTRACTION_OPTIONS.contains(&"--absolute-names"));
    }

    #[test]
    fn system_tar_boundary_extracts_exact_allowlist_and_preserves_sparse_gateway() {
        let test = TestDirectories::new();
        let source = test.root.join("bundle-source");
        let destination = test.root.join("bundle-output");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&destination).unwrap();
        for entry in whonix_bundle_layout() {
            let path = source.join(entry.path);
            if entry.role == BundleArtifactRole::GatewayDisk {
                fs::write(&path, qcow2_header(8 * 1024 * 1024)).unwrap();
                File::options()
                    .write(true)
                    .open(&path)
                    .unwrap()
                    .set_len(8 * 1024 * 1024)
                    .unwrap();
            } else {
                fs::write(&path, entry.path.as_bytes()).unwrap();
            }
        }
        let archive = test.root.join("fixture.tar.xz");
        let output = Command::new("tar")
            .args(["--create", "--xz", "--sparse", "--file"])
            .arg(&archive)
            .arg("--directory")
            .arg(&source)
            .arg("--")
            .args(whonix_bundle_layout().into_iter().map(|entry| entry.path))
            .output()
            .unwrap();
        assert!(output.status.success());

        let archive_file = File::open(&archive).unwrap();
        let (_inherited, bound_archive) = inheritable_fd_path(&archive_file).unwrap();
        let entries = SystemArtifactFetcher
            .extract_whonix_bundle(&bound_archive, &destination)
            .unwrap();
        assert_eq!(validate_whonix_bundle_entries(&entries).unwrap().len(), 6);
        let gateway = destination.join(WHONIX_GATEWAY_DISK_FILENAME);
        let metadata = fs::metadata(&gateway).unwrap();
        assert!(metadata.blocks() * 512 < metadata.len());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(qcow2_virtual_size(&gateway).unwrap(), 8 * 1024 * 1024);
    }

    #[test]
    fn tar_listing_parser_preserves_the_complete_member_name_for_refusal() {
        let listing = "-rw------- 0/0 1 2026-08-28 12:00:00 Whonix-Gateway.xml\n-rw------- 0/0 1 2026-08-28 12:00:00 nested path.xml\n";
        let entries = parse_tar_verbose_listing(listing).unwrap();
        assert_eq!(entries[0].path, WHONIX_GATEWAY_XML_FILENAME);
        assert_eq!(entries[1].path, "nested path.xml");
        assert!(validate_whonix_bundle_entries(&entries).is_err());
    }

    #[test]
    fn whonix_bundle_refuses_missing_duplicate_and_unexpected_entries() {
        let mut missing = whonix_entries();
        missing.pop();
        assert!(validate_whonix_bundle_entries(&missing).is_err());

        let mut duplicate = whonix_entries();
        duplicate[1] = duplicate[0].clone();
        assert!(validate_whonix_bundle_entries(&duplicate).is_err());

        let mut unexpected = whonix_entries();
        unexpected[0].path = "extra.qcow2".to_owned();
        assert!(validate_whonix_bundle_entries(&unexpected).is_err());
    }

    #[test]
    fn whonix_bundle_refuses_unsafe_paths_and_links() {
        for path in [
            "../Whonix-Gateway.xml",
            "/Whonix-Gateway.xml",
            "nested/Whonix-Gateway.xml",
            "C:\\Whonix-Gateway.xml",
            ".\\Whonix-Gateway.xml",
            "nested//Whonix-Gateway.xml",
        ] {
            let mut entries = whonix_entries();
            entries[1].path = path.to_owned();
            assert!(validate_whonix_bundle_entries(&entries).is_err());
        }
        for kind in [
            ArchiveEntryKind::SymbolicLink,
            ArchiveEntryKind::HardLink,
            ArchiveEntryKind::Directory,
            ArchiveEntryKind::Other,
        ] {
            let mut entries = whonix_entries();
            entries[0].kind = kind;
            assert!(validate_whonix_bundle_entries(&entries).is_err());
        }
    }

    #[test]
    fn whonix_signature_requires_pinned_signer_notation_and_monotonic_time() {
        let valid = whonix_signature();
        assert!(validate_whonix_signature_evidence(&valid, 1_800_000_000, None).is_ok());

        let mut wrong_signer = valid.clone();
        wrong_signer.primary_signer_fingerprint = "0".repeat(40);
        assert!(validate_whonix_signature_evidence(&wrong_signer, 1_800_000_000, None).is_err());

        let mut wrong_notation = valid.clone();
        wrong_notation.notation = "file@name=other.libvirt.xz".to_owned();
        assert!(validate_whonix_signature_evidence(&wrong_notation, 1_800_000_000, None).is_err());

        let mut old = valid.clone();
        old.signature_unix_seconds = WHONIX_RELEASE_SIGNATURE_NOT_BEFORE - 1;
        assert!(validate_whonix_signature_evidence(&old, 1_800_000_000, None).is_err());
        assert!(
            validate_whonix_signature_evidence(&valid, 1_800_000_000, Some(1_790_000_000)).is_err()
        );
    }

    #[test]
    fn whonix_provenance_keeps_gateway_and_workstation_in_one_bundle() {
        let hashes = whonix_bundle_layout()
            .into_iter()
            .map(|entry| (entry.role, "a".repeat(64)))
            .collect();
        let provenance =
            whonix_bundle_provenance(&whonix_signature(), 1_800_000_000, "b".repeat(64), hashes)
                .unwrap();
        assert_eq!(provenance.release, WHONIX_RELEASE);
        assert!(
            provenance
                .artifact_sha256
                .iter()
                .any(|(role, _)| *role == BundleArtifactRole::GatewayDisk)
        );
        assert!(
            provenance
                .artifact_sha256
                .iter()
                .any(|(role, _)| *role == BundleArtifactRole::WorkstationDisk)
        );

        let incomplete = vec![(BundleArtifactRole::GatewayDisk, "a".repeat(64))];
        assert!(
            whonix_bundle_provenance(
                &whonix_signature(),
                1_800_000_000,
                "b".repeat(64),
                incomplete
            )
            .is_err()
        );
    }
}
