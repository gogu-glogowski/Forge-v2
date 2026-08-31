//! Pure Fedora Workstation canonical-base preparation and promotion model.
//! No function in this module performs host, libvirt, or storage mutation.

use super::{
    FedoraIsoArchitecture, FedoraWorkstationIsoMetadata, ImageError, VerifiedFedoraWorkstationIso,
    revalidate_fedora_workstation_iso_proof,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

pub const FEDORA_WORKSTATION_STAGING_CAPACITY_BYTES: u64 = 80 * 1024 * 1024 * 1024;
pub const FEDORA_WORKSTATION_NORMALIZATION_RECIPE: &str = "FedoraWorkstationNormalizationV1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FedoraWorkstationArtifactRole {
    VerifiedInstallationSource,
    PreparationStagingDisk,
    CanonicalSharedBase,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FedoraWorkstationPreparationId(String);

impl FedoraWorkstationPreparationId {
    /// Creates a stable preparation transaction identity.
    ///
    /// # Errors
    /// Refuses empty or non-lowercase hexadecimal identifiers.
    pub fn new(value: impl Into<String>) -> Result<Self, PreparationError> {
        let value = value.into();
        if value.len() < 8
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(PreparationError::InvalidPreparationIdentity);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FedoraWorkstationPreparationStatus {
    Planned,
    InstallerReady,
    Installing,
    InstalledPendingProof,
    InstalledValidated,
    NormalizationRequired,
    Normalized,
    PromotionReady,
    Promoted,
    Cancelled,
    RecoveryRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparationSourceBinding {
    pub release: String,
    pub compose: String,
    pub architecture: FedoraIsoArchitecture,
    pub filename: String,
    pub iso_path: PathBuf,
    pub iso_sha256: String,
    pub iso_bytes: u64,
    pub signing_key_fingerprint: String,
}

impl From<&FedoraWorkstationIsoMetadata> for PreparationSourceBinding {
    fn from(metadata: &FedoraWorkstationIsoMetadata) -> Self {
        Self {
            release: metadata.release.clone(),
            compose: metadata.compose.clone(),
            architecture: metadata.architecture,
            filename: metadata.filename.clone(),
            iso_path: metadata.local_path.clone(),
            iso_sha256: metadata.sha256.clone(),
            iso_bytes: metadata.byte_size,
            signing_key_fingerprint: metadata.signing_key_fingerprint.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparationOwnedStagingDisk {
    pub preparation_id: FedoraWorkstationPreparationId,
    pub volume_name: String,
    pub path: PathBuf,
    pub format: String,
    pub capacity_bytes: u64,
    pub sparse: bool,
    pub backing_path: Option<PathBuf>,
    pub role: FedoraWorkstationArtifactRole,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct PreparationOwnedInstallerDomain {
    pub preparation_id: FedoraWorkstationPreparationId,
    pub name: String,
    pub uuid: String,
    pub machine: String,
    pub firmware: String,
    pub disk_path: PathBuf,
    pub iso_path: PathBuf,
    pub network: String,
    pub graphics: String,
    pub video: String,
    pub input: Vec<String>,
    pub audio: bool,
    pub seed: Option<PathBuf>,
    pub cloud_init: bool,
    pub ssh_required: bool,
    pub qga_required: bool,
    pub hostdev: bool,
    pub filesystem_passthrough: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalWorkstationBasePlan {
    pub volume_name: String,
    pub path: PathBuf,
    pub format: String,
    pub capacity_bytes: u64,
    pub backing_path: Option<PathBuf>,
    pub role: FedoraWorkstationArtifactRole,
    pub logical_read_only: bool,
    pub direct_writable_attachment_allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FedoraWorkstationPreparationPlan {
    pub preparation_id: FedoraWorkstationPreparationId,
    pub source: PreparationSourceBinding,
    pub staging: PreparationOwnedStagingDisk,
    pub installer: PreparationOwnedInstallerDomain,
    pub canonical: CanonicalWorkstationBasePlan,
    pub normalization_recipe: String,
    pub interactive_installation: bool,
    pub mutation: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct PreparationCollisions {
    pub active_transaction: bool,
    pub staging_disk: bool,
    pub installer_domain: bool,
    pub canonical_base: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FedoraWorkstationPreparation {
    pub schema_version: u32,
    pub preparation_id: FedoraWorkstationPreparationId,
    pub status: FedoraWorkstationPreparationStatus,
    pub source: PreparationSourceBinding,
    pub staging: PreparationOwnedStagingDisk,
    pub installer: PreparationOwnedInstallerDomain,
    pub canonical: CanonicalWorkstationBasePlan,
    pub normalization_recipe: String,
    pub operator_confirmation_recorded: bool,
    pub recovery_detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorContinuation {
    InstallationCompleteAndGraphicalBootConfirmed,
    Cancel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct InstallationCompletionObservation {
    pub domain_shutoff: bool,
    pub exact_domain_identity: bool,
    pub exact_staging_identity: bool,
    pub iso_topology_expected: bool,
    pub staging_has_partition_table: bool,
    pub staging_has_bootable_installed_system: bool,
    pub unexpected_devices: bool,
    pub controlled_disk_boot_reached_running: bool,
    pub clean_shutdown_after_validation: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FedoraWorkstationNormalizationRecipe {
    V1,
}

impl fmt::Display for FedoraWorkstationNormalizationRecipe {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(FEDORA_WORKSTATION_NORMALIZATION_RECIPE)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct NormalizationObservation {
    pub installed_product: String,
    pub installed_release: String,
    pub clean_shutdown: bool,
    pub machine_id_empty: bool,
    pub dbus_machine_id_absent_or_symlink: bool,
    pub ssh_host_keys_absent_or_server_not_installed: bool,
    pub hostname_generic: bool,
    pub network_connections_generic: bool,
    pub dhcp_identity_absent: bool,
    pub random_seed_removed: bool,
    pub installer_residue_absent: bool,
    pub logs_crash_and_temporary_files_clean: bool,
    pub no_normal_users: bool,
    pub root_locked: bool,
    pub gnome_initial_setup_enabled: bool,
    pub accounts_service_clean: bool,
    pub package_transactions_clean: bool,
    pub selinux_enabled: bool,
    pub selinux_enforcing: bool,
    pub relabel_not_pending: bool,
    pub filesystem_clean: bool,
    pub spice_vdagent_policy_recorded: bool,
    pub qga_presence_recorded: bool,
    pub disk_sha256: String,
    pub disk_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedFedoraWorkstationDisk {
    source: PreparationSourceBinding,
    preparation_id: FedoraWorkstationPreparationId,
    staging_volume_name: String,
    staging_path: PathBuf,
    recipe: FedoraWorkstationNormalizationRecipe,
    disk_sha256: String,
    disk_bytes: u64,
    installed_product: String,
    release: String,
    architecture: FedoraIsoArchitecture,
    checks: Vec<&'static str>,
    clean_shutdown: bool,
}

impl NormalizedFedoraWorkstationDisk {
    #[must_use]
    pub fn disk_sha256(&self) -> &str {
        &self.disk_sha256
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CanonicalBaseOwnership {
    ImageStoreSharedBase,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalFedoraWorkstationProvenance {
    pub release: String,
    pub compose: String,
    pub architecture: FedoraIsoArchitecture,
    pub source_iso_sha256: String,
    pub source_signing_key_fingerprint: String,
    pub preparation_id: FedoraWorkstationPreparationId,
    pub normalization_recipe: FedoraWorkstationNormalizationRecipe,
    pub canonical_volume_name: String,
    pub canonical_path: PathBuf,
    pub canonical_sha256: String,
    pub capacity_bytes: u64,
    pub backing_path: Option<PathBuf>,
    pub ownership: CanonicalBaseOwnership,
    pub protected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreparationError {
    MissingVerifiedSource,
    SourceIdentityDrift,
    InvalidPreparationIdentity,
    ActivePreparationCollision,
    StagingCollision,
    InstallerDomainCollision,
    CanonicalBaseCollision,
    InvalidStateTransition,
    ExplicitContinuationRequired,
    InstallationProofFailed,
    NormalizationCheckFailed(&'static str),
    PromotionProofFailed,
    Backend(String),
}

impl fmt::Display for PreparationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingVerifiedSource => formatter.write_str("verified Workstation ISO required"),
            Self::SourceIdentityDrift => formatter.write_str("verified ISO identity drifted"),
            Self::InvalidPreparationIdentity => formatter.write_str("invalid preparation identity"),
            Self::ActivePreparationCollision => {
                formatter.write_str("active preparation already exists")
            }
            Self::StagingCollision => formatter.write_str("staging disk already exists"),
            Self::InstallerDomainCollision => {
                formatter.write_str("installer domain already exists")
            }
            Self::CanonicalBaseCollision => formatter.write_str("canonical base already exists"),
            Self::InvalidStateTransition => {
                formatter.write_str("invalid preparation state transition")
            }
            Self::ExplicitContinuationRequired => {
                formatter.write_str("explicit operator continuation required")
            }
            Self::InstallationProofFailed => formatter.write_str("installed-system proof failed"),
            Self::NormalizationCheckFailed(check) => {
                write!(formatter, "normalization check failed: {check}")
            }
            Self::PromotionProofFailed => formatter.write_str("canonical-base proof failed"),
            Self::Backend(error) => write!(formatter, "preparation backend failed: {error}"),
        }
    }
}

impl std::error::Error for PreparationError {}

/// Builds a zero-mutation interactive installer and promotion plan.
///
/// # Errors
/// Requires current byte-backed ISO evidence and collision-free preparation identities.
pub fn plan_fedora_workstation_preparation(
    source: Option<&VerifiedFedoraWorkstationIso>,
    preparation_id: FedoraWorkstationPreparationId,
    installer_uuid: &str,
    downloads: &std::path::Path,
    images: &std::path::Path,
    collisions: PreparationCollisions,
) -> Result<FedoraWorkstationPreparationPlan, PreparationError> {
    let source = source.ok_or(PreparationError::MissingVerifiedSource)?;
    revalidate_fedora_workstation_iso_proof(source)
        .map_err(|_| PreparationError::SourceIdentityDrift)?;
    if collisions.active_transaction {
        return Err(PreparationError::ActivePreparationCollision);
    }
    if collisions.staging_disk {
        return Err(PreparationError::StagingCollision);
    }
    if collisions.installer_domain {
        return Err(PreparationError::InstallerDomainCollision);
    }
    if collisions.canonical_base {
        return Err(PreparationError::CanonicalBaseCollision);
    }
    let metadata = source.metadata();
    let suffix = &preparation_id.as_str()[..8];
    let staging_name = format!(
        "forge-stage-fedora-workstation-{}-{}-{suffix}.qcow2",
        metadata.release, metadata.compose
    );
    let staging_path = downloads.join(&staging_name);
    let installer_name = format!(
        "forge-prepare-fedora-workstation-{}-{}-{suffix}",
        metadata.release, metadata.compose
    );
    let canonical_name = format!(
        "forge-base-fedora-workstation-{}-{}.qcow2",
        metadata.release, metadata.compose
    );
    let staging = PreparationOwnedStagingDisk {
        preparation_id: preparation_id.clone(),
        volume_name: staging_name,
        path: staging_path.clone(),
        format: "qcow2".to_owned(),
        capacity_bytes: FEDORA_WORKSTATION_STAGING_CAPACITY_BYTES,
        sparse: true,
        backing_path: None,
        role: FedoraWorkstationArtifactRole::PreparationStagingDisk,
    };
    let installer = PreparationOwnedInstallerDomain {
        preparation_id: preparation_id.clone(),
        name: installer_name,
        uuid: installer_uuid.to_owned(),
        machine: "q35".to_owned(),
        firmware: "uefi".to_owned(),
        disk_path: staging_path,
        iso_path: metadata.local_path.clone(),
        network: "default-nat-virtio".to_owned(),
        graphics: "spice".to_owned(),
        video: "virtio-gpu".to_owned(),
        input: vec!["usb-keyboard".to_owned(), "usb-tablet".to_owned()],
        audio: true,
        seed: None,
        cloud_init: false,
        ssh_required: false,
        qga_required: false,
        hostdev: false,
        filesystem_passthrough: false,
    };
    let canonical = CanonicalWorkstationBasePlan {
        volume_name: canonical_name.clone(),
        path: images.join(canonical_name),
        format: "qcow2".to_owned(),
        capacity_bytes: FEDORA_WORKSTATION_STAGING_CAPACITY_BYTES,
        backing_path: None,
        role: FedoraWorkstationArtifactRole::CanonicalSharedBase,
        logical_read_only: true,
        direct_writable_attachment_allowed: false,
    };
    Ok(FedoraWorkstationPreparationPlan {
        preparation_id,
        source: metadata.into(),
        staging,
        installer,
        canonical,
        normalization_recipe: FEDORA_WORKSTATION_NORMALIZATION_RECIPE.to_owned(),
        interactive_installation: true,
        mutation: false,
    })
}

#[must_use]
pub fn durable_preparation(plan: FedoraWorkstationPreparationPlan) -> FedoraWorkstationPreparation {
    FedoraWorkstationPreparation {
        schema_version: 1,
        preparation_id: plan.preparation_id,
        status: FedoraWorkstationPreparationStatus::Planned,
        source: plan.source,
        staging: plan.staging,
        installer: plan.installer,
        canonical: plan.canonical,
        normalization_recipe: plan.normalization_recipe,
        operator_confirmation_recorded: false,
        recovery_detail: None,
    }
}

/// Records the explicit post-installation boundary and validates only provable facts.
///
/// # Errors
/// Refuses cancellation, implicit completion, device drift, nonbootable targets, and unclean state.
pub fn confirm_installation(
    preparation: &mut FedoraWorkstationPreparation,
    continuation: OperatorContinuation,
    observation: &InstallationCompletionObservation,
) -> Result<(), PreparationError> {
    if continuation == OperatorContinuation::Cancel {
        preparation.status = FedoraWorkstationPreparationStatus::Cancelled;
        return Err(PreparationError::ExplicitContinuationRequired);
    }
    if preparation.status != FedoraWorkstationPreparationStatus::InstalledPendingProof {
        return Err(PreparationError::InvalidStateTransition);
    }
    if !observation.domain_shutoff
        || !observation.exact_domain_identity
        || !observation.exact_staging_identity
        || !observation.iso_topology_expected
        || !observation.staging_has_partition_table
        || !observation.staging_has_bootable_installed_system
        || observation.unexpected_devices
        || !observation.controlled_disk_boot_reached_running
        || !observation.clean_shutdown_after_validation
    {
        return Err(PreparationError::InstallationProofFailed);
    }
    preparation.operator_confirmation_recorded = true;
    preparation.status = FedoraWorkstationPreparationStatus::NormalizationRequired;
    Ok(())
}

/// Produces non-forgeable typed normalized-disk evidence from the complete V1 checklist.
///
/// # Errors
/// Names the first failed normalization invariant.
pub fn prove_normalized_disk(
    preparation: &FedoraWorkstationPreparation,
    observation: &NormalizationObservation,
) -> Result<NormalizedFedoraWorkstationDisk, PreparationError> {
    if preparation.status != FedoraWorkstationPreparationStatus::NormalizationRequired
        || !preparation.operator_confirmation_recorded
    {
        return Err(PreparationError::InvalidStateTransition);
    }
    let checks = [
        (
            observation.installed_product == "Fedora Workstation",
            "installed product",
        ),
        (
            observation.installed_release == preparation.source.release,
            "installed release",
        ),
        (observation.clean_shutdown, "clean shutdown"),
        (observation.machine_id_empty, "machine-id residue"),
        (
            observation.dbus_machine_id_absent_or_symlink,
            "D-Bus machine-id residue",
        ),
        (
            observation.ssh_host_keys_absent_or_server_not_installed,
            "SSH host-key residue",
        ),
        (observation.hostname_generic, "hostname residue"),
        (
            observation.network_connections_generic,
            "NetworkManager identity residue",
        ),
        (observation.dhcp_identity_absent, "DHCP identity residue"),
        (observation.random_seed_removed, "random seed residue"),
        (observation.installer_residue_absent, "installer residue"),
        (
            observation.logs_crash_and_temporary_files_clean,
            "log or temporary residue",
        ),
        (observation.no_normal_users, "personal user residue"),
        (observation.root_locked, "root account is not locked"),
        (
            observation.gnome_initial_setup_enabled,
            "GNOME Initial Setup completed residue",
        ),
        (
            observation.accounts_service_clean,
            "AccountsService residue",
        ),
        (
            observation.package_transactions_clean,
            "package transaction state",
        ),
        (
            observation.selinux_enabled && observation.selinux_enforcing,
            "SELinux policy",
        ),
        (observation.relabel_not_pending, "SELinux relabel pending"),
        (observation.filesystem_clean, "filesystem state"),
        (
            observation.spice_vdagent_policy_recorded,
            "SPICE integration policy",
        ),
        (observation.qga_presence_recorded, "QGA presence policy"),
        (observation.disk_sha256.len() == 64, "disk digest"),
        (
            observation.disk_bytes == preparation.staging.capacity_bytes,
            "disk capacity",
        ),
    ];
    if let Some((_, name)) = checks.iter().find(|(passed, _)| !passed) {
        return Err(PreparationError::NormalizationCheckFailed(name));
    }
    Ok(NormalizedFedoraWorkstationDisk {
        source: preparation.source.clone(),
        preparation_id: preparation.preparation_id.clone(),
        staging_volume_name: preparation.staging.volume_name.clone(),
        staging_path: preparation.staging.path.clone(),
        recipe: FedoraWorkstationNormalizationRecipe::V1,
        disk_sha256: observation.disk_sha256.clone(),
        disk_bytes: observation.disk_bytes,
        installed_product: observation.installed_product.clone(),
        release: observation.installed_release.clone(),
        architecture: preparation.source.architecture,
        checks: checks.iter().map(|(_, name)| *name).collect(),
        clean_shutdown: observation.clean_shutdown,
    })
}

#[allow(clippy::missing_errors_doc)]
pub trait FedoraWorkstationPromotionBackend {
    fn create_canonical_from_staging(
        &mut self,
        normalized: &NormalizedFedoraWorkstationDisk,
        canonical: &CanonicalWorkstationBasePlan,
    ) -> Result<(), String>;
    fn prove_canonical(
        &mut self,
        canonical: &CanonicalWorkstationBasePlan,
        expected_sha256: &str,
    ) -> Result<(), String>;
    fn publish_provenance(
        &mut self,
        provenance: &CanonicalFedoraWorkstationProvenance,
    ) -> Result<(), String>;
    fn protect_canonical(&mut self, canonical: &CanonicalWorkstationBasePlan)
    -> Result<(), String>;
    fn retire_staging(&mut self, staging: &PreparationOwnedStagingDisk) -> Result<(), String>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct FedoraWorkstationPreparationTransaction {
    pub canonical_created: bool,
    pub canonical_proven: bool,
    pub provenance_published: bool,
    pub canonical_protected: bool,
    pub staging_retired: bool,
}

/// Promotes by exact copy/import, proves it, publishes trust, protects it, then retires staging.
///
/// # Errors
/// Before publication, staging remains authoritative and recoverable. After publication,
/// canonical state remains authoritative and staging retirement is separately retryable.
pub fn execute_canonical_promotion<B: FedoraWorkstationPromotionBackend>(
    backend: &mut B,
    preparation: &mut FedoraWorkstationPreparation,
    normalized: &NormalizedFedoraWorkstationDisk,
) -> Result<
    (
        FedoraWorkstationPreparationTransaction,
        CanonicalFedoraWorkstationProvenance,
    ),
    PreparationError,
> {
    if preparation.status != FedoraWorkstationPreparationStatus::PromotionReady
        || normalized.preparation_id != preparation.preparation_id
        || normalized.staging_volume_name != preparation.staging.volume_name
        || normalized.staging_path != preparation.staging.path
        || normalized.source != preparation.source
        || normalized.release != preparation.source.release
        || normalized.architecture != preparation.source.architecture
        || normalized.installed_product != "Fedora Workstation"
        || normalized.recipe != FedoraWorkstationNormalizationRecipe::V1
        || normalized.disk_bytes != preparation.canonical.capacity_bytes
        || !normalized.clean_shutdown
        || normalized.checks.is_empty()
    {
        return Err(PreparationError::PromotionProofFailed);
    }
    let mut transaction = FedoraWorkstationPreparationTransaction {
        canonical_created: false,
        canonical_proven: false,
        provenance_published: false,
        canonical_protected: false,
        staging_retired: false,
    };
    backend
        .create_canonical_from_staging(normalized, &preparation.canonical)
        .map_err(PreparationError::Backend)?;
    transaction.canonical_created = true;
    backend
        .prove_canonical(&preparation.canonical, normalized.disk_sha256())
        .map_err(PreparationError::Backend)?;
    transaction.canonical_proven = true;
    let provenance = CanonicalFedoraWorkstationProvenance {
        release: preparation.source.release.clone(),
        compose: preparation.source.compose.clone(),
        architecture: preparation.source.architecture,
        source_iso_sha256: preparation.source.iso_sha256.clone(),
        source_signing_key_fingerprint: preparation.source.signing_key_fingerprint.clone(),
        preparation_id: preparation.preparation_id.clone(),
        normalization_recipe: FedoraWorkstationNormalizationRecipe::V1,
        canonical_volume_name: preparation.canonical.volume_name.clone(),
        canonical_path: preparation.canonical.path.clone(),
        canonical_sha256: normalized.disk_sha256.clone(),
        capacity_bytes: normalized.disk_bytes,
        backing_path: None,
        ownership: CanonicalBaseOwnership::ImageStoreSharedBase,
        protected: true,
    };
    backend
        .protect_canonical(&preparation.canonical)
        .map_err(PreparationError::Backend)?;
    transaction.canonical_protected = true;
    backend
        .publish_provenance(&provenance)
        .map_err(PreparationError::Backend)?;
    transaction.provenance_published = true;
    preparation.status = FedoraWorkstationPreparationStatus::Promoted;
    backend
        .retire_staging(&preparation.staging)
        .map_err(PreparationError::Backend)?;
    transaction.staging_retired = true;
    Ok((transaction, provenance))
}

impl From<ImageError> for PreparationError {
    fn from(_: ImageError) -> Self {
        Self::SourceIdentityDrift
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ImageStatus, VerifiedFileIdentity};
    use std::fs;
    use std::os::unix::fs::MetadataExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct Fixture {
        root: PathBuf,
        proof: VerifiedFedoraWorkstationIso,
    }

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "forge-workstation-preparation-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(&root).unwrap();
            let iso = root.join("Fedora-Workstation-Live-44-1.7.x86_64.iso");
            fs::write(&iso, b"verified iso").unwrap();
            let file = fs::metadata(&iso).unwrap();
            let identity = VerifiedFileIdentity {
                path: iso.clone(),
                device: file.dev(),
                inode: file.ino(),
                bytes: file.len(),
                modified_seconds: file.mtime(),
                modified_nanoseconds: file.mtime_nsec(),
                changed_seconds: file.ctime(),
                changed_nanoseconds: file.ctime_nsec(),
                mode: file.mode(),
                links: file.nlink(),
            };
            let proof = VerifiedFedoraWorkstationIso {
                metadata: FedoraWorkstationIsoMetadata {
                    release: "44".to_owned(),
                    compose: "1.7".to_owned(),
                    architecture: FedoraIsoArchitecture::X86_64,
                    artifact_class: "Fedora Workstation Live ISO".to_owned(),
                    filename: "Fedora-Workstation-Live-44-1.7.x86_64.iso".to_owned(),
                    source_url: "https://download.fedoraproject.org/workstation.iso".to_owned(),
                    local_path: iso,
                    byte_size: file.len(),
                    sha256: "a".repeat(64),
                    signed_checksum_filename: "Fedora-Workstation-44-1.7-x86_64-CHECKSUM"
                        .to_owned(),
                    signing_key_fingerprint: "36F612DCF27F7D1A48A835E4DBFCF71C6D9F90A6".to_owned(),
                    verified_at_unix_seconds: 1,
                    status: ImageStatus::Verified,
                },
                identity,
            };
            Self { root, proof }
        }

        fn plan(&self) -> FedoraWorkstationPreparationPlan {
            plan_fedora_workstation_preparation(
                Some(&self.proof),
                FedoraWorkstationPreparationId::new("1234abcd").unwrap(),
                "00000000-0000-4000-8000-000000000001",
                &self.root.join("downloads"),
                &self.root.join("images"),
                PreparationCollisions::default(),
            )
            .unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn completion() -> InstallationCompletionObservation {
        InstallationCompletionObservation {
            domain_shutoff: true,
            exact_domain_identity: true,
            exact_staging_identity: true,
            iso_topology_expected: true,
            staging_has_partition_table: true,
            staging_has_bootable_installed_system: true,
            unexpected_devices: false,
            controlled_disk_boot_reached_running: true,
            clean_shutdown_after_validation: true,
        }
    }

    fn normalization() -> NormalizationObservation {
        NormalizationObservation {
            installed_product: "Fedora Workstation".to_owned(),
            installed_release: "44".to_owned(),
            clean_shutdown: true,
            machine_id_empty: true,
            dbus_machine_id_absent_or_symlink: true,
            ssh_host_keys_absent_or_server_not_installed: true,
            hostname_generic: true,
            network_connections_generic: true,
            dhcp_identity_absent: true,
            random_seed_removed: true,
            installer_residue_absent: true,
            logs_crash_and_temporary_files_clean: true,
            no_normal_users: true,
            root_locked: true,
            gnome_initial_setup_enabled: true,
            accounts_service_clean: true,
            package_transactions_clean: true,
            selinux_enabled: true,
            selinux_enforcing: true,
            relabel_not_pending: true,
            filesystem_clean: true,
            spice_vdagent_policy_recorded: true,
            qga_presence_recorded: true,
            disk_sha256: "b".repeat(64),
            disk_bytes: FEDORA_WORKSTATION_STAGING_CAPACITY_BYTES,
        }
    }

    fn normalization_ready(fixture: &Fixture) -> FedoraWorkstationPreparation {
        let mut preparation = durable_preparation(fixture.plan());
        preparation.status = FedoraWorkstationPreparationStatus::InstalledPendingProof;
        confirm_installation(
            &mut preparation,
            OperatorContinuation::InstallationCompleteAndGraphicalBootConfirmed,
            &completion(),
        )
        .unwrap();
        preparation
    }

    #[test]
    fn preparation_requires_typed_verified_iso_and_current_identity() {
        let fixture = Fixture::new();
        let id = FedoraWorkstationPreparationId::new("1234abcd").unwrap();
        assert_eq!(
            plan_fedora_workstation_preparation(
                None,
                id.clone(),
                "uuid",
                &fixture.root,
                &fixture.root,
                PreparationCollisions::default(),
            ),
            Err(PreparationError::MissingVerifiedSource)
        );
        fs::write(&fixture.proof.metadata().local_path, b"changed").unwrap();
        assert_eq!(
            plan_fedora_workstation_preparation(
                Some(&fixture.proof),
                id,
                "uuid",
                &fixture.root,
                &fixture.root,
                PreparationCollisions::default(),
            ),
            Err(PreparationError::SourceIdentityDrift)
        );
    }

    #[test]
    fn staging_installer_and_canonical_roles_are_distinct_and_safe() {
        let fixture = Fixture::new();
        let plan = fixture.plan();
        assert_eq!(
            plan.staging.role,
            FedoraWorkstationArtifactRole::PreparationStagingDisk
        );
        assert_eq!(
            plan.canonical.role,
            FedoraWorkstationArtifactRole::CanonicalSharedBase
        );
        assert_ne!(plan.staging.path, plan.canonical.path);
        assert!(plan.staging.sparse);
        assert!(plan.staging.backing_path.is_none());
        assert!(plan.canonical.backing_path.is_none());
        assert!(plan.installer.name.starts_with("forge-prepare-"));
        assert_ne!(plan.installer.name, "fedora-lab");
        assert!(plan.installer.seed.is_none());
        assert!(!plan.installer.cloud_init);
        assert!(!plan.installer.ssh_required);
        assert!(!plan.installer.qga_required);
        assert!(!plan.installer.hostdev);
        assert!(!plan.installer.filesystem_passthrough);
        assert!(!plan.mutation);
    }

    #[test]
    fn every_preparation_collision_refuses() {
        let fixture = Fixture::new();
        for (collisions, expected) in [
            (
                PreparationCollisions {
                    active_transaction: true,
                    ..Default::default()
                },
                PreparationError::ActivePreparationCollision,
            ),
            (
                PreparationCollisions {
                    staging_disk: true,
                    ..Default::default()
                },
                PreparationError::StagingCollision,
            ),
            (
                PreparationCollisions {
                    installer_domain: true,
                    ..Default::default()
                },
                PreparationError::InstallerDomainCollision,
            ),
            (
                PreparationCollisions {
                    canonical_base: true,
                    ..Default::default()
                },
                PreparationError::CanonicalBaseCollision,
            ),
        ] {
            assert_eq!(
                plan_fedora_workstation_preparation(
                    Some(&fixture.proof),
                    FedoraWorkstationPreparationId::new("1234abcd").unwrap(),
                    "uuid",
                    &fixture.root,
                    &fixture.root,
                    collisions,
                ),
                Err(expected)
            );
        }
    }

    #[test]
    fn durable_state_round_trip_is_deterministic_and_resume_safe() {
        let fixture = Fixture::new();
        let preparation = durable_preparation(fixture.plan());
        let bytes = serde_json::to_vec(&preparation).unwrap();
        let decoded: FedoraWorkstationPreparation = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded, preparation);
        assert_eq!(decoded.status, FedoraWorkstationPreparationStatus::Planned);
    }

    #[test]
    fn installation_requires_explicit_confirmation_and_complete_proof() {
        let fixture = Fixture::new();
        let mut preparation = durable_preparation(fixture.plan());
        preparation.status = FedoraWorkstationPreparationStatus::InstalledPendingProof;
        let mut incomplete = completion();
        incomplete.staging_has_bootable_installed_system = false;
        assert_eq!(
            confirm_installation(
                &mut preparation,
                OperatorContinuation::InstallationCompleteAndGraphicalBootConfirmed,
                &incomplete,
            ),
            Err(PreparationError::InstallationProofFailed)
        );
        assert!(!preparation.operator_confirmation_recorded);
        assert!(
            confirm_installation(
                &mut preparation,
                OperatorContinuation::InstallationCompleteAndGraphicalBootConfirmed,
                &completion(),
            )
            .is_ok()
        );
    }

    #[test]
    fn cancellation_is_durable_and_never_claims_completion() {
        let fixture = Fixture::new();
        let mut preparation = durable_preparation(fixture.plan());
        preparation.status = FedoraWorkstationPreparationStatus::InstalledPendingProof;
        assert!(
            confirm_installation(
                &mut preparation,
                OperatorContinuation::Cancel,
                &completion(),
            )
            .is_err()
        );
        assert_eq!(
            preparation.status,
            FedoraWorkstationPreparationStatus::Cancelled
        );
        assert!(!preparation.operator_confirmation_recorded);
    }

    #[test]
    fn normalization_recipe_is_typed_and_complete_observation_produces_evidence() {
        let fixture = Fixture::new();
        let preparation = normalization_ready(&fixture);
        let evidence = prove_normalized_disk(&preparation, &normalization()).unwrap();
        assert_eq!(
            FedoraWorkstationNormalizationRecipe::V1.to_string(),
            FEDORA_WORKSTATION_NORMALIZATION_RECIPE
        );
        assert_eq!(evidence.disk_sha256(), "b".repeat(64));
    }

    #[test]
    fn identity_user_gnome_ssh_network_and_security_residue_block_normalization() {
        let fixture = Fixture::new();
        let preparation = normalization_ready(&fixture);
        let mut observations = Vec::new();
        let mut value = normalization();
        value.no_normal_users = false;
        observations.push(value);
        let mut value = normalization();
        value.machine_id_empty = false;
        observations.push(value);
        let mut value = normalization();
        value.ssh_host_keys_absent_or_server_not_installed = false;
        observations.push(value);
        let mut value = normalization();
        value.hostname_generic = false;
        observations.push(value);
        let mut value = normalization();
        value.network_connections_generic = false;
        observations.push(value);
        let mut value = normalization();
        value.gnome_initial_setup_enabled = false;
        observations.push(value);
        let mut value = normalization();
        value.selinux_enforcing = false;
        observations.push(value);
        let mut value = normalization();
        value.package_transactions_clean = false;
        observations.push(value);
        for observation in observations {
            assert!(matches!(
                prove_normalized_disk(&preparation, &observation),
                Err(PreparationError::NormalizationCheckFailed(_))
            ));
        }
    }

    #[derive(Default)]
    struct Backend {
        calls: Vec<&'static str>,
        fail_at: Option<&'static str>,
    }

    impl Backend {
        fn call(&mut self, name: &'static str) -> Result<(), String> {
            self.calls.push(name);
            if self.fail_at == Some(name) {
                Err(format!("failed at {name}"))
            } else {
                Ok(())
            }
        }
    }

    impl FedoraWorkstationPromotionBackend for Backend {
        fn create_canonical_from_staging(
            &mut self,
            _: &NormalizedFedoraWorkstationDisk,
            _: &CanonicalWorkstationBasePlan,
        ) -> Result<(), String> {
            self.call("create")
        }
        fn prove_canonical(
            &mut self,
            _: &CanonicalWorkstationBasePlan,
            _: &str,
        ) -> Result<(), String> {
            self.call("prove")
        }
        fn publish_provenance(
            &mut self,
            _: &CanonicalFedoraWorkstationProvenance,
        ) -> Result<(), String> {
            self.call("publish")
        }
        fn protect_canonical(&mut self, _: &CanonicalWorkstationBasePlan) -> Result<(), String> {
            self.call("protect")
        }
        fn retire_staging(&mut self, _: &PreparationOwnedStagingDisk) -> Result<(), String> {
            self.call("retire")
        }
    }

    fn promotion_ready(
        fixture: &Fixture,
    ) -> (
        FedoraWorkstationPreparation,
        NormalizedFedoraWorkstationDisk,
    ) {
        let mut preparation = normalization_ready(fixture);
        let normalized = prove_normalized_disk(&preparation, &normalization()).unwrap();
        preparation.status = FedoraWorkstationPreparationStatus::PromotionReady;
        (preparation, normalized)
    }

    #[test]
    fn successful_promotion_publishes_shared_base_before_staging_retirement() {
        let fixture = Fixture::new();
        let (mut preparation, normalized) = promotion_ready(&fixture);
        let mut backend = Backend::default();
        let (transaction, provenance) =
            execute_canonical_promotion(&mut backend, &mut preparation, &normalized).unwrap();
        assert_eq!(
            backend.calls,
            ["create", "prove", "protect", "publish", "retire"]
        );
        assert!(transaction.provenance_published);
        assert!(transaction.staging_retired);
        assert_eq!(
            provenance.ownership,
            CanonicalBaseOwnership::ImageStoreSharedBase
        );
        assert!(provenance.backing_path.is_none());
        assert!(provenance.protected);
        assert_eq!(provenance.source_iso_sha256, preparation.source.iso_sha256);
    }

    #[test]
    fn failed_promotion_preserves_staging_and_never_publishes_unproven_base() {
        for failure in ["create", "prove", "protect", "publish"] {
            let fixture = Fixture::new();
            let (mut preparation, normalized) = promotion_ready(&fixture);
            let mut backend = Backend {
                fail_at: Some(failure),
                ..Default::default()
            };
            assert!(
                execute_canonical_promotion(&mut backend, &mut preparation, &normalized).is_err()
            );
            assert!(!backend.calls.contains(&"retire"));
            assert_ne!(
                preparation.status,
                FedoraWorkstationPreparationStatus::Promoted
            );
        }
    }

    #[test]
    fn staging_cleanup_failure_keeps_published_canonical_authoritative() {
        let fixture = Fixture::new();
        let (mut preparation, normalized) = promotion_ready(&fixture);
        let mut backend = Backend {
            fail_at: Some("retire"),
            ..Default::default()
        };
        assert!(execute_canonical_promotion(&mut backend, &mut preparation, &normalized).is_err());
        assert_eq!(
            preparation.status,
            FedoraWorkstationPreparationStatus::Promoted
        );
        assert_eq!(
            backend.calls,
            ["create", "prove", "protect", "publish", "retire"]
        );
    }

    #[test]
    fn release_and_compose_are_part_of_every_canonical_identity() {
        let fixture = Fixture::new();
        let first = fixture.plan();
        let mut future = fixture.proof.clone();
        future.metadata.release = "45".to_owned();
        future.metadata.compose = "1.0".to_owned();
        let second = plan_fedora_workstation_preparation(
            Some(&future),
            FedoraWorkstationPreparationId::new("abcd1234").unwrap(),
            "uuid-2",
            &fixture.root,
            &fixture.root,
            PreparationCollisions::default(),
        )
        .unwrap();
        assert_ne!(first.canonical.volume_name, second.canonical.volume_name);
        assert_ne!(first.staging.volume_name, second.staging.volume_name);
    }
}
