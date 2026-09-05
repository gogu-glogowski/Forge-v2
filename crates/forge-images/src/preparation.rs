//! Pure Fedora Workstation canonical-base preparation and promotion model.
//! No function in this module performs host, libvirt, or storage mutation.

use super::{
    FEDORA_WORKSTATION_COMPOSE, FEDORA_WORKSTATION_RELEASE, FedoraIsoArchitecture,
    FedoraWorkstationIsoMetadata, ImageError, VerifiedFedoraWorkstationIso,
    revalidate_fedora_workstation_iso_proof,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

pub const FEDORA_WORKSTATION_STAGING_CAPACITY_BYTES: u64 = 80 * 1024 * 1024 * 1024;
pub const FEDORA_WORKSTATION_NORMALIZATION_RECIPE: &str = "FedoraWorkstationNormalizationV1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FedoraWorkstationArtifactRole {
    VerifiedInstallationSource,
    LibvirtManagedInstallerIso,
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
    InstallerRunning,
    AwaitingInstallationConfirmation,
    InstallationConfirmed,
    InstalledDiskBootPending,
    InstalledDiskBooting,
    AwaitingGraphicalBootConfirmation,
    InstalledSystemProven,
    NormalizationPlanned,
    NormalizationRunning,
    NormalizationGuestComplete,
    ShutdownPending,
    OfflineProofPending,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FedoraWorkstationTopologyMode {
    InstallerAttached,
    DiskOnly,
}

/// Selects topology semantics exclusively from durable preparation state.
///
/// # Errors
/// Refuses states that do not unambiguously describe an installer topology.
pub fn fedora_workstation_topology_mode(
    status: FedoraWorkstationPreparationStatus,
) -> Result<FedoraWorkstationTopologyMode, PreparationError> {
    match status {
        FedoraWorkstationPreparationStatus::InstallerReady
        | FedoraWorkstationPreparationStatus::InstallerRunning
        | FedoraWorkstationPreparationStatus::AwaitingInstallationConfirmation => {
            Ok(FedoraWorkstationTopologyMode::InstallerAttached)
        }
        FedoraWorkstationPreparationStatus::InstallationConfirmed
        | FedoraWorkstationPreparationStatus::InstalledDiskBootPending
        | FedoraWorkstationPreparationStatus::InstalledDiskBooting
        | FedoraWorkstationPreparationStatus::AwaitingGraphicalBootConfirmation
        | FedoraWorkstationPreparationStatus::InstalledSystemProven
        | FedoraWorkstationPreparationStatus::NormalizationPlanned
        | FedoraWorkstationPreparationStatus::NormalizationRunning
        | FedoraWorkstationPreparationStatus::NormalizationGuestComplete
        | FedoraWorkstationPreparationStatus::ShutdownPending
        | FedoraWorkstationPreparationStatus::OfflineProofPending => {
            Ok(FedoraWorkstationTopologyMode::DiskOnly)
        }
        _ => Err(PreparationError::InvalidStateTransition),
    }
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
    #[serde(default)]
    pub execution: FedoraWorkstationExecutionEvidence,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FedoraWorkstationExecutionEvidence {
    pub staging_volume_key: Option<String>,
    pub staging_allocation_bytes: Option<u64>,
    pub installer_xml_sha256: Option<String>,
    pub resolved_topology: Option<ProvenResolvedInstallerTopology>,
    #[serde(default)]
    pub runtime_iso: Option<LibvirtManagedInstallerIso>,
    #[serde(default)]
    pub disk_only_topology: Option<ProvenResolvedInstallerTopology>,
    #[serde(default)]
    pub installed_disk_start_recorded: bool,
    #[serde(default)]
    pub graphical_boot_confirmation: Option<GraphicalBootConfirmationEvidence>,
    #[serde(default)]
    pub helper_bootstrap: Option<PreparationHelperBootstrap>,
    #[serde(default)]
    pub preparation_channel: Option<PreparationChannelEvidence>,
    #[serde(default)]
    pub read_only_guest_inventory: Option<PublishedReadOnlyGuestInventory>,
    #[serde(default)]
    pub privileged_offline_discovery: Option<ProvenPrivilegedOfflineFedoraDiscovery>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GraphicalBootConfirmationKind {
    InstalledFedoraGnomeFirstRunVisible,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct GraphicalBootConfirmationEvidence {
    pub preparation_id: FedoraWorkstationPreparationId,
    pub confirmation_kind: GraphicalBootConfirmationKind,
    pub domain_name: String,
    pub domain_uuid: String,
    pub staging_path: PathBuf,
    pub graphical_confirmation_recorded: bool,
    pub observed_running: bool,
    pub disk_only_topology_xml_sha256: String,
    pub gnome_initial_setup_completed: bool,
    pub display_dynamic_resizing_needs_review: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LibvirtManagedInstallerIso {
    pub preparation_id: FedoraWorkstationPreparationId,
    pub volume_name: String,
    pub path: PathBuf,
    pub source_filename: String,
    pub source_sha256: String,
    pub source_bytes: u64,
    pub destination_bytes: u64,
    pub destination_sha256: String,
    pub volume_key: String,
    pub role: FedoraWorkstationArtifactRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InstallerDeviceClassification {
    Required,
    AllowedLibvirtNormalization,
    OptionalExplicitPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedInstallerDevice {
    pub kind: String,
    pub identity: String,
    pub classification: InstallerDeviceClassification,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenResolvedInstallerTopology {
    pub requested_machine_family: String,
    pub resolved_machine_type: String,
    pub q35_alias_canonical: String,
    pub firmware: String,
    pub loader: String,
    pub nvram: String,
    pub nic_mac: String,
    pub devices: Vec<ResolvedInstallerDevice>,
    pub xml_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparationPoolEvidence {
    pub name: String,
    pub active: bool,
    pub target_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparationVolumeEvidence {
    pub name: String,
    pub key: String,
    pub path: PathBuf,
    pub format: String,
    pub capacity_bytes: u64,
    pub allocation_bytes: u64,
    pub backing_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct InstallerDomainEvidence {
    pub name: String,
    pub uuid: String,
    pub persistent: bool,
    pub shutoff: bool,
    pub running: bool,
    pub autostart: bool,
    pub xml: String,
    pub q35_alias_canonical: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphicalConfirmationDisposition {
    Published,
    AlreadyPublished,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManualInstallationConfirmationDisposition {
    Confirmed,
    AlreadyConfirmed,
}

#[allow(clippy::missing_errors_doc)]
pub trait FedoraWorkstationPreparationBackend {
    fn inspect_pool(&mut self, name: &str) -> Result<PreparationPoolEvidence, String>;
    fn inspect_volume(
        &mut self,
        pool: &str,
        name: &str,
    ) -> Result<Option<PreparationVolumeEvidence>, String>;
    fn create_staging_volume(
        &mut self,
        pool: &str,
        name: &str,
        capacity_bytes: u64,
    ) -> Result<(), String>;
    fn inspect_installer_domain(
        &mut self,
        name: &str,
    ) -> Result<Option<InstallerDomainEvidence>, String>;
    fn define_installer_domain(&mut self, xml: &str) -> Result<(), String>;
    fn start_installer_domain(&mut self, name: &str) -> Result<(), String>;
    fn canonical_base_exists(&mut self, pool: &str, name: &str) -> Result<bool, String>;
    fn materialize_installer_iso(
        &mut self,
        pool: &str,
        name: &str,
        source_path: &std::path::Path,
        source_bytes: u64,
    ) -> Result<PreparationVolumeEvidence, String>;
    fn stream_installer_iso_digest(
        &mut self,
        pool: &str,
        name: &str,
        expected_bytes: u64,
    ) -> Result<(PreparationVolumeEvidence, u64, String), String>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallerReadyDisposition {
    Created,
    Resumed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallerStartDisposition {
    Started,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstalledDiskBootDisposition {
    DiskOnlyPrepared,
    Started,
    AlreadyRunning,
}

/// Advances only after the existing installer domain has actually been observed running.
/// A running domain never implies that Anaconda completed.
///
/// # Errors
/// Refuses any state other than `InstallerReady` or an absent running observation.
pub fn record_installer_started(
    preparation: &mut FedoraWorkstationPreparation,
    domain_running: bool,
) -> Result<InstallerStartDisposition, PreparationError> {
    if preparation.status != FedoraWorkstationPreparationStatus::InstallerReady || !domain_running {
        return Err(PreparationError::InvalidStateTransition);
    }
    preparation.status = FedoraWorkstationPreparationStatus::InstallerRunning;
    Ok(InstallerStartDisposition::Started)
}

/// Refuses to infer installation completion from power state. A later operator
/// continuation must supply the explicit installation-complete boundary.
///
/// # Errors
/// Refuses non-running preparation state, running domains, or missing operator confirmation.
pub fn require_installation_confirmation(
    preparation: &FedoraWorkstationPreparation,
    domain_shutoff: bool,
    operator_confirmed: bool,
) -> Result<(), PreparationError> {
    if preparation.status != FedoraWorkstationPreparationStatus::InstallerRunning
        || !domain_shutoff
        || !operator_confirmed
    {
        return Err(PreparationError::ExplicitContinuationRequired);
    }
    Ok(())
}

/// Durably representable transition for explicit operator confirmation.
///
/// # Errors
/// Refuses any implicit, running-domain, or out-of-order confirmation.
pub fn record_anaconda_installation_completed(
    preparation: &mut FedoraWorkstationPreparation,
    domain_shutoff: bool,
    operator_confirmed: bool,
) -> Result<(), PreparationError> {
    require_installation_confirmation(preparation, domain_shutoff, operator_confirmed)?;
    preparation.status = FedoraWorkstationPreparationStatus::InstallationConfirmed;
    preparation.operator_confirmation_recorded = true;
    Ok(())
}

/// Records an explicit operator attestation for an installation performed
/// outside Forge while preserving the fact that `InstallerRunning` was not
/// observed. This transition performs host-side identity/topology checks only.
///
/// # Errors
/// Refuses missing confirmation, non-`InstallerReady` state, identity or
/// topology drift, unsafe storage, canonical collisions, or publication failure.
pub fn confirm_manually_installed_from_installer_ready<B, P>(
    backend: &mut B,
    preparation: &mut FedoraWorkstationPreparation,
    operator_confirmed: bool,
    mut publish: P,
) -> Result<ManualInstallationConfirmationDisposition, PreparationError>
where
    B: FedoraWorkstationPreparationBackend,
    P: FnMut(&FedoraWorkstationPreparation) -> Result<(), String>,
{
    if preparation.status == FedoraWorkstationPreparationStatus::InstallationConfirmed
        && preparation.operator_confirmation_recorded
    {
        return Ok(ManualInstallationConfirmationDisposition::AlreadyConfirmed);
    }
    if preparation.status != FedoraWorkstationPreparationStatus::InstallerReady
        || !operator_confirmed
    {
        return Err(PreparationError::InvalidStateTransition);
    }
    let volume = backend
        .inspect_volume("default", &preparation.staging.volume_name)
        .map_err(PreparationError::Backend)?
        .ok_or_else(|| PreparationError::Backend("staging volume absent".into()))?;
    prove_staging(preparation, &volume)?;
    if preparation.execution.staging_volume_key.as_deref() != Some(volume.key.as_str()) {
        return Err(PreparationError::Backend(
            "durable staging identity drift".into(),
        ));
    }
    if backend
        .canonical_base_exists("default", &preparation.canonical.volume_name)
        .map_err(PreparationError::Backend)?
    {
        return Err(PreparationError::CanonicalBaseCollision);
    }
    let domain = backend
        .inspect_installer_domain(&preparation.installer.name)
        .map_err(PreparationError::Backend)?
        .ok_or_else(|| PreparationError::Backend("installer domain absent".into()))?;
    if domain.name != preparation.installer.name
        || domain.uuid != preparation.installer.uuid
        || !domain.shutoff
        || domain.running
    {
        return Err(PreparationError::InstallationProofFailed);
    }
    prove_fedora_workstation_post_install_staging_topology(preparation, &domain)?;
    preparation.status = FedoraWorkstationPreparationStatus::InstallationConfirmed;
    preparation.operator_confirmation_recorded = true;
    publish(preparation).map_err(PreparationError::Backend)?;
    Ok(ManualInstallationConfirmationDisposition::Confirmed)
}

#[must_use]
pub fn fedora_workstation_preparation_state_path(home: &std::path::Path) -> PathBuf {
    home.join(".local/share/forge/preparations/fedora-workstation-44-1.7.json")
}

/// Reads the exact durable preparation record.
///
/// # Errors
/// Refuses I/O failure, corrupt state, unsupported schema, or conflicting provenance.
pub fn read_fedora_workstation_preparation(
    path: &std::path::Path,
) -> Result<Option<FedoraWorkstationPreparation>, PreparationError> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(PreparationError::Backend(error.to_string())),
    };
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| PreparationError::Backend(error.to_string()))?;
    let value: FedoraWorkstationPreparation = serde_json::from_slice(&bytes).map_err(|error| {
        PreparationError::Backend(format!("preparation state is corrupt: {error}"))
    })?;
    if value.schema_version != 1
        || value.source.release != FEDORA_WORKSTATION_RELEASE
        || value.source.compose != FEDORA_WORKSTATION_COMPOSE
        || value.source.architecture != FedoraIsoArchitecture::X86_64
        || value.normalization_recipe != FEDORA_WORKSTATION_NORMALIZATION_RECIPE
    {
        return Err(PreparationError::Backend(
            "preparation state has conflicting provenance or schema".to_owned(),
        ));
    }
    Ok(Some(value))
}

fn preparation_bytes(value: &FedoraWorkstationPreparation) -> Result<Vec<u8>, PreparationError> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| PreparationError::Backend(error.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn sync_parent(path: &std::path::Path) -> Result<(), PreparationError> {
    File::open(
        path.parent()
            .ok_or_else(|| PreparationError::Backend("state path has no parent".into()))?,
    )
    .and_then(|directory| directory.sync_all())
    .map_err(|error| PreparationError::Backend(error.to_string()))
}

/// Publishes a new transaction with create-new collision semantics.
///
/// # Errors
/// Refuses an existing transaction and reports durable-write failures.
pub fn publish_new_fedora_workstation_preparation(
    path: &std::path::Path,
    value: &FedoraWorkstationPreparation,
) -> Result<(), PreparationError> {
    let parent = path
        .parent()
        .ok_or_else(|| PreparationError::Backend("state path has no parent".into()))?;
    fs::create_dir_all(parent).map_err(|error| PreparationError::Backend(error.to_string()))?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
        .map_err(|error| PreparationError::Backend(error.to_string()))?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                PreparationError::ActivePreparationCollision
            } else {
                PreparationError::Backend(error.to_string())
            }
        })?;
    file.write_all(&preparation_bytes(value)?)
        .and_then(|()| file.sync_all())
        .map_err(|error| PreparationError::Backend(error.to_string()))?;
    sync_parent(path)
}

/// Atomically replaces an existing transaction record after a proven boundary.
///
/// # Errors
/// Refuses absent state and reports serialization, write, sync, or rename failure.
pub fn update_fedora_workstation_preparation(
    path: &std::path::Path,
    value: &FedoraWorkstationPreparation,
) -> Result<(), PreparationError> {
    if !path.is_file() {
        return Err(PreparationError::Backend(
            "cannot update absent preparation state".to_owned(),
        ));
    }
    let temporary = path.with_extension(format!("json.tmp-{}", std::process::id()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|error| PreparationError::Backend(error.to_string()))?;
    let result = file
        .write_all(&preparation_bytes(value)?)
        .and_then(|()| file.sync_all())
        .and_then(|()| fs::rename(&temporary, path));
    if let Err(error) = result {
        let _ = fs::remove_file(&temporary);
        return Err(PreparationError::Backend(error.to_string()));
    }
    sync_parent(path)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FedoraWorkstationPackagePolicy {
    FullyUpdatedAtPreparationWithRecordedManifest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NormalizationExecutionChannel {
    Unavailable,
    PreparationOnlyEphemeral,
}

pub const FORGE_GUEST_CONTROL_PROTOCOL_VERSION: u32 = 1;
pub const FORGE_PREPARATION_CHANNEL: &str = "org.majorforge.preparation.0";
pub const FORGE_PREPARATION_HELPER_PATH: &str = "/usr/libexec/forge-preparation-control";
pub const FORGE_PREPARATION_GENERATOR_PATH: &str =
    "/usr/lib/systemd/system-generators/forge-preparation-control-generator";
pub const FORGE_PREPARATION_BINDING_PATH: &str = "/usr/lib/forge-preparation-control/binding.json";
pub const FORGE_PREPARATION_BROKER_PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PreparationBrokerOperation {
    InspectFedoraWorkstationPreparation,
    BootstrapPreparationHelperOffline,
    ReplacePreparationHelper,
    ClassifyBootstrapRecoveryReadOnly,
    CompleteBootstrapRecoveryHostOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BootstrapArtifactClassification {
    Absent,
    Exact,
    PartialOrMismatched,
    UnreadableOrIndeterminate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BootstrapRecoveryClassification {
    NothingWritten,
    HelperExactOnly,
    ExactPrefix,
    ExactComplete,
    PartialOrMismatched,
    InconsistentSet,
    Indeterminate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BootstrapResumePlan {
    ResumeWritingHelper,
    ResumeWritingGenerator,
    ResumeWritingBinding,
    VerifyExistingArtifacts,
    RecoveryBlockedMismatch,
    RecoveryBlockedInconsistent,
    RecoveryBlockedIndeterminate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparationBrokerRecoveryResult {
    pub protocol_version: u32,
    pub operation: PreparationBrokerOperation,
    pub operation_id: String,
    pub preparation_id: FedoraWorkstationPreparationId,
    pub domain_uuid: String,
    pub staging_path: PathBuf,
    pub bootstrap_transaction_id: String,
    pub helper: BootstrapArtifactClassification,
    pub generator: BootstrapArtifactClassification,
    pub binding: BootstrapArtifactClassification,
    pub classification: BootstrapRecoveryClassification,
    pub resume_plan: BootstrapResumePlan,
    pub backend: String,
    pub read_only: bool,
    pub clean_close: bool,
    pub host_metadata_unchanged: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PreparationBootstrapTarget {
    SyntheticProof,
    RealPreparation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PreparationBrokerDiagnosticOperation {
    SelfTestLibguestfsAppliance,
    SelfTestDirectBackendSynthetic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparationBrokerDiagnosticRequest {
    pub protocol_version: u32,
    pub operation: PreparationBrokerDiagnosticOperation,
    pub operation_id: String,
    pub nonce: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparationBrokerRequest {
    pub protocol_version: u32,
    pub operation: PreparationBrokerOperation,
    pub preparation_id: FedoraWorkstationPreparationId,
    pub expected_domain_name: String,
    pub expected_domain_uuid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_target: Option<PreparationBootstrapTarget>,
    pub operation_id: String,
    pub nonce: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparationBrokerBootstrapResult {
    pub protocol_version: u32,
    pub operation: PreparationBrokerOperation,
    pub operation_id: String,
    pub nonce: String,
    pub preparation_id: FedoraWorkstationPreparationId,
    pub domain_uuid: String,
    pub target: PreparationBootstrapTarget,
    pub source_checkpoint: String,
    pub helper_sha256: String,
    pub helper_bytes: u64,
    pub generator_sha256: String,
    pub generator_bytes: u64,
    pub binding_sha256: String,
    pub binding_bytes: u64,
    pub helper_protocol_version: u32,
    pub supported_operations: Vec<String>,
    pub bootstrap_transaction_id: String,
    pub guest_paths: Vec<String>,
    pub guest_modes: Vec<String>,
    pub guest_selinux_labels: Vec<String>,
    pub unexpected_paths_modified: bool,
    pub clean_close: bool,
    pub backend: String,
    pub target_sha256_before: String,
    pub target_sha256_after: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PreparationBrokerCompletion {
    Completed,
    Refused,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparationBrokerResult {
    pub protocol_version: u32,
    pub operation: PreparationBrokerOperation,
    pub operation_id: String,
    pub nonce: String,
    pub preparation_id: FedoraWorkstationPreparationId,
    pub domain_uuid: String,
    pub staging_volume_name: String,
    pub staging_volume_key: String,
    pub staging_path: PathBuf,
    pub broker_version: String,
    pub broker_sha256: String,
    pub libguestfs_version: String,
    pub backend: String,
    pub os_root: String,
    pub fedora_product: String,
    pub fedora_release: String,
    pub architecture: String,
    pub filesystems: Vec<String>,
    pub guest_selinux_config: String,
    pub workstation_evidence: String,
    pub filesystem_layout: Vec<String>,
    pub minimal_observations: Vec<String>,
    pub clean_close: bool,
    pub host_metadata_unchanged: bool,
    pub elapsed_millis: u64,
    pub completion: PreparationBrokerCompletion,
    pub error_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparationBrokerApplianceSelfTestResult {
    pub protocol_version: u32,
    pub operation: PreparationBrokerDiagnosticOperation,
    pub operation_id: String,
    pub nonce: String,
    pub broker_version: String,
    pub libguestfs_version: String,
    pub backend: String,
    pub elapsed_millis: u64,
    pub appliance_initialized: bool,
    pub disk_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparationBrokerSyntheticDirectResult {
    pub protocol_version: u32,
    pub operation: PreparationBrokerDiagnosticOperation,
    pub operation_id: String,
    pub nonce: String,
    pub broker_version: String,
    pub libguestfs_version: String,
    pub backend: String,
    pub elapsed_millis: u64,
    pub disk_count: u32,
    pub metadata_unchanged: bool,
    pub sha256_before: String,
    pub sha256_after: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparationGuestIdentityDiagnostics {
    pub inspect_command_failed: bool,
    pub parser_failed: bool,
    pub root_count: u32,
    pub observed_roots: Vec<String>,
    pub distro_id: String,
    pub version_id: String,
    pub workstation: bool,
    pub architecture: String,
    pub selinux: String,
    pub failed_predicates: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PreparationBrokerResponse {
    Success {
        result: Box<PreparationBrokerResult>,
    },
    Refusal {
        error_code: String,
    },
    InternalError {
        error_code: String,
    },
    ApplianceSelfTestSuccess {
        result: PreparationBrokerApplianceSelfTestResult,
    },
    SyntheticDirectSelfTestSuccess {
        result: PreparationBrokerSyntheticDirectResult,
    },
    IdentityRefusal {
        error_code: String,
        diagnostics: PreparationGuestIdentityDiagnostics,
    },
    BootstrapSuccess {
        result: Box<PreparationBrokerBootstrapResult>,
    },
    RecoveryClassificationSuccess {
        result: PreparationBrokerRecoveryResult,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenPrivilegedOfflineFedoraDiscovery {
    pub operation_id: String,
    pub preparation_id: FedoraWorkstationPreparationId,
    pub domain_uuid: String,
    pub staging_volume_key: String,
    pub broker_version: String,
    pub broker_sha256: String,
    pub libguestfs_version: String,
    pub backend: String,
    pub os_root: String,
    pub fedora_product: String,
    pub fedora_release: String,
    pub architecture: String,
    pub filesystems: Vec<String>,
    pub guest_selinux_enforcing_configured: bool,
    pub workstation_evidence: String,
    pub filesystem_layout: Vec<String>,
    pub minimal_observations: Vec<String>,
    pub clean_close: bool,
    pub host_metadata_unchanged: bool,
    pub elapsed_millis: u64,
}

/// Verifies broker output before privileged discovery evidence becomes durable.
///
/// # Errors
/// Refuses replay, identity drift, malformed output, and non-completion.
pub fn prove_privileged_offline_fedora_discovery(
    preparation: &FedoraWorkstationPreparation,
    request: &PreparationBrokerRequest,
    result: PreparationBrokerResult,
) -> Result<ProvenPrivilegedOfflineFedoraDiscovery, PreparationError> {
    if preparation.status != FedoraWorkstationPreparationStatus::InstalledSystemProven
        || preparation.execution.privileged_offline_discovery.is_some()
        || request.protocol_version != FORGE_PREPARATION_BROKER_PROTOCOL_VERSION
        || request.operation != PreparationBrokerOperation::InspectFedoraWorkstationPreparation
        || request.preparation_id != preparation.preparation_id
        || request.expected_domain_name != preparation.installer.name
        || request.expected_domain_uuid != preparation.installer.uuid
        || request.bootstrap_target.is_some()
        || request.operation_id.len() < 16
        || request.nonce.len() < 32
        || result.protocol_version != request.protocol_version
        || result.operation != request.operation
        || result.operation_id != request.operation_id
        || result.nonce != request.nonce
        || result.preparation_id != request.preparation_id
        || result.domain_uuid != request.expected_domain_uuid
        || result.staging_volume_name != preparation.staging.volume_name
        || result.staging_volume_key
            != preparation
                .execution
                .staging_volume_key
                .clone()
                .unwrap_or_default()
        || result.staging_path != preparation.staging.path
        || result.completion != PreparationBrokerCompletion::Completed
        || result.error_code.is_some()
        || result.broker_sha256.len() != 64
        || result.backend != "direct"
        || result.os_root.is_empty()
        || result.fedora_product != "Fedora Workstation"
        || result.fedora_release != preparation.source.release
        || result.architecture != "x86_64"
        || result.filesystems.is_empty()
        || !result.guest_selinux_config.contains("SELINUX=enforcing")
        || result.workstation_evidence.is_empty()
        || result.filesystem_layout.is_empty()
        || !result.clean_close
        || !result.host_metadata_unchanged
    {
        return Err(PreparationError::GuestControlProtocolRefused);
    }
    Ok(ProvenPrivilegedOfflineFedoraDiscovery {
        operation_id: result.operation_id,
        preparation_id: result.preparation_id,
        domain_uuid: result.domain_uuid,
        staging_volume_key: result.staging_volume_key,
        broker_version: result.broker_version,
        broker_sha256: result.broker_sha256,
        libguestfs_version: result.libguestfs_version,
        backend: result.backend,
        os_root: result.os_root,
        fedora_product: result.fedora_product,
        fedora_release: result.fedora_release,
        architecture: result.architecture,
        filesystems: result.filesystems,
        guest_selinux_enforcing_configured: true,
        workstation_evidence: result.workstation_evidence,
        filesystem_layout: result.filesystem_layout,
        minimal_observations: result.minimal_observations,
        clean_close: result.clean_close,
        host_metadata_unchanged: result.host_metadata_unchanged,
        elapsed_millis: result.elapsed_millis,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparationHelperBootstrap {
    pub preparation_id: FedoraWorkstationPreparationId,
    pub domain_uuid: String,
    pub staging_path: PathBuf,
    pub helper_sha256: String,
    pub helper_bytes: u64,
    #[serde(default)]
    pub generator_sha256: String,
    #[serde(default)]
    pub generator_bytes: u64,
    #[serde(default)]
    pub binding_sha256: String,
    #[serde(default)]
    pub binding_bytes: u64,
    #[serde(default)]
    pub guest_paths: Vec<PathBuf>,
    #[serde(default)]
    pub guest_modes: Vec<String>,
    #[serde(default)]
    pub guest_selinux_labels: Vec<String>,
    #[serde(default)]
    pub structured_verification_proven: bool,
    #[serde(default)]
    pub clean_close: bool,
    #[serde(default)]
    pub unexpected_paths_modified: bool,
    pub helper_protocol_version: u32,
    pub bootstrap_transaction_id: String,
    pub guest_installation_path: PathBuf,
    pub persistent_activation_path: PathBuf,
    pub temporary_activation_path: PathBuf,
    pub channel_name: String,
    pub expected_state: FedoraWorkstationPreparationStatus,
    pub cleanup_inventory: GuestChannelCleanupInventory,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparationChannelEvidence {
    pub preparation_id: FedoraWorkstationPreparationId,
    pub domain_uuid: String,
    pub staging_path: PathBuf,
    pub bootstrap_transaction_id: String,
    pub protocol_version: u32,
    pub channel_name: String,
    pub host_endpoint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedReadOnlyGuestInventory {
    pub operation_id: String,
    pub nonce: String,
    pub guest_sequence: u64,
    pub inventory: ReadOnlyGuestInventory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuestControlOperation {
    ReadOnlyGuestInventoryProbe,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestControlBinding {
    pub preparation_id: FedoraWorkstationPreparationId,
    pub domain_name: String,
    pub domain_uuid: String,
    pub staging_path: PathBuf,
    pub recipe: FedoraWorkstationNormalizationRecipe,
    pub expected_state: FedoraWorkstationPreparationStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestControlRequest {
    pub protocol_version: u32,
    pub binding: GuestControlBinding,
    pub operation: GuestControlOperation,
    pub operation_id: String,
    pub nonce: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct ReadOnlyGuestInventory {
    pub fedora_product: String,
    pub fedora_release: String,
    #[serde(default)]
    pub architecture: String,
    #[serde(default)]
    pub kernel: String,
    pub hostname: String,
    pub machine_id_present: bool,
    pub normal_user_count: u32,
    #[serde(default)]
    pub normal_users: Vec<String>,
    #[serde(default)]
    pub root_locked: bool,
    pub accounts_service_entries: Vec<String>,
    pub gnome_initial_setup_completed: bool,
    pub network_profile_summaries: Vec<String>,
    pub preparation_mac_referenced: bool,
    #[serde(default)]
    pub network_static_addresses: Vec<String>,
    #[serde(default)]
    pub dhcp_identity_residue: bool,
    #[serde(default)]
    pub network_secrets_present: bool,
    pub openssh_server_installed: bool,
    #[serde(default)]
    pub openssh_server_enabled: bool,
    pub ssh_host_keys_present: bool,
    pub selinux_enabled: bool,
    pub selinux_enforcing: bool,
    #[serde(default)]
    pub relabel_pending: bool,
    pub package_transactions_clean: bool,
    #[serde(default)]
    pub enabled_fedora_repositories: Vec<String>,
    #[serde(default)]
    pub relevant_packages: Vec<String>,
    pub spice_vdagent_installed: bool,
    pub spice_vdagent_components: Vec<String>,
    pub qemu_guest_agent_installed: bool,
    pub display_stack: Vec<String>,
    #[serde(default)]
    pub dbus_machine_id_relationship: String,
    #[serde(default)]
    pub anaconda_residue: Vec<String>,
    #[serde(default)]
    pub crash_temp_history_residue: Vec<String>,
    #[serde(default)]
    pub preparation_identity_residue: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuestControlCompletion {
    Completed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestControlResult {
    pub protocol_version: u32,
    pub binding: GuestControlBinding,
    pub operation: GuestControlOperation,
    pub operation_id: String,
    pub nonce: String,
    pub completion: GuestControlCompletion,
    pub inventory: Option<ReadOnlyGuestInventory>,
    pub error_code: Option<String>,
    pub guest_sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenReadOnlyGuestInventory {
    binding: GuestControlBinding,
    operation_id: String,
    inventory: ReadOnlyGuestInventory,
}

impl ProvenReadOnlyGuestInventory {
    #[must_use]
    pub fn inventory(&self) -> &ReadOnlyGuestInventory {
        &self.inventory
    }

    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    #[must_use]
    pub fn binding(&self) -> &GuestControlBinding {
        &self.binding
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestOperationLedgerState {
    Prepared,
    SentAwaitingResult,
    Completed,
    FailedAmbiguous,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestChannelCleanupInventory {
    pub guest_helper_path: PathBuf,
    pub guest_service_path: PathBuf,
    pub guest_configuration_path: PathBuf,
    pub guest_generator_path: PathBuf,
    pub domain_channel_name: String,
    pub reusable_secret_created: bool,
}

#[must_use]
pub fn guest_channel_cleanup_inventory() -> GuestChannelCleanupInventory {
    GuestChannelCleanupInventory {
        guest_helper_path: PathBuf::from("/usr/libexec/forge-preparation-control"),
        guest_service_path: PathBuf::from("/run/systemd/system/forge-preparation-control.service"),
        guest_configuration_path: PathBuf::from("/run/forge-preparation-control/binding.json"),
        guest_generator_path: PathBuf::from(FORGE_PREPARATION_GENERATOR_PATH),
        domain_channel_name: "org.majorforge.preparation.0".to_owned(),
        reusable_secret_created: false,
    }
}

/// Constructs the sole Phase 4.6B operation without exposing a command string.
///
/// # Errors
/// Refuses stale state, topology evidence loss, canonical collision, legacy-object exposure,
/// or weak/reusable operation identity.
pub fn create_read_only_guest_inventory_request(
    preparation: &FedoraWorkstationPreparation,
    operation_id: &str,
    nonce: &str,
    canonical_base_absent: bool,
    legacy_fedora_isolated: bool,
) -> Result<GuestControlRequest, PreparationError> {
    if preparation.status != FedoraWorkstationPreparationStatus::InstalledSystemProven
        || preparation.execution.disk_only_topology.is_none()
        || operation_id.len() < 16
        || nonce.len() < 32
        || !canonical_base_absent
        || !legacy_fedora_isolated
    {
        return Err(PreparationError::GuestControlProtocolRefused);
    }
    Ok(GuestControlRequest {
        protocol_version: FORGE_GUEST_CONTROL_PROTOCOL_VERSION,
        binding: GuestControlBinding {
            preparation_id: preparation.preparation_id.clone(),
            domain_name: preparation.installer.name.clone(),
            domain_uuid: preparation.installer.uuid.clone(),
            staging_path: preparation.staging.path.clone(),
            recipe: FedoraWorkstationNormalizationRecipe::V1,
            expected_state: FedoraWorkstationPreparationStatus::InstalledSystemProven,
        },
        operation: GuestControlOperation::ReadOnlyGuestInventoryProbe,
        operation_id: operation_id.to_owned(),
        nonce: nonce.to_owned(),
    })
}

/// Validates a completed result and produces private-field inventory evidence.
///
/// # Errors
/// Refuses malformed, failed, replayed, stale, forged, or cross-preparation results.
pub fn prove_read_only_guest_inventory(
    preparation: &FedoraWorkstationPreparation,
    request: &GuestControlRequest,
    result: GuestControlResult,
    ledger_state: GuestOperationLedgerState,
) -> Result<ProvenReadOnlyGuestInventory, PreparationError> {
    let expected = create_read_only_guest_inventory_request(
        preparation,
        &request.operation_id,
        &request.nonce,
        true,
        true,
    )?;
    if request != &expected
        || result.protocol_version != request.protocol_version
        || result.binding != request.binding
        || result.operation != request.operation
        || result.operation_id != request.operation_id
        || result.nonce != request.nonce
        || result.completion != GuestControlCompletion::Completed
        || result.error_code.is_some()
        || result.guest_sequence != 1
        || ledger_state != GuestOperationLedgerState::SentAwaitingResult
    {
        return Err(PreparationError::GuestControlProtocolRefused);
    }
    let inventory = result
        .inventory
        .ok_or(PreparationError::GuestControlProtocolRefused)?;
    if inventory.fedora_product != "Fedora Workstation"
        || inventory.fedora_release != preparation.source.release
        || inventory.architecture != "x86_64"
        || inventory.gnome_initial_setup_completed
        || !inventory.selinux_enabled
        || !inventory.selinux_enforcing
    {
        return Err(PreparationError::GuestControlProtocolRefused);
    }
    Ok(ProvenReadOnlyGuestInventory {
        binding: request.binding.clone(),
        operation_id: request.operation_id.clone(),
        inventory,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NormalizationAuthority {
    ForgeHost,
    PreparationGuest,
    OfflineReadOnlyInspector,
    Operator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NormalizationTask {
    AccountsAndGnomeFirstUse,
    MachineAndHostIdentity,
    NetworkIdentity,
    SshHostIdentity,
    InstallerResidue,
    PackageConsistency,
    SelinuxAndLabels,
    FilesystemResidue,
    SpiceDesktopIntegration,
    QgaPolicy,
    ControlledShutdown,
    OfflineFinalProof,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizationTaskPlan {
    pub task: NormalizationTask,
    pub authority: NormalizationAuthority,
    pub operator_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FedoraWorkstationNormalizationPlan {
    pub preparation_id: FedoraWorkstationPreparationId,
    pub staging_path: PathBuf,
    pub recipe: FedoraWorkstationNormalizationRecipe,
    pub package_policy: FedoraWorkstationPackagePolicy,
    pub execution_channel: NormalizationExecutionChannel,
    pub execution_ready: bool,
    pub tasks: Vec<NormalizationTaskPlan>,
    pub mutation: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NormalizationStageEvent {
    PlanAccepted,
    GuestExecutionStarted,
    GuestEvidenceProven,
    ControlledShutdownRequested,
    CleanShutdownObserved,
    OfflineProofPassed,
}

/// Returns the only state authorized by a proved normalization event.
///
/// This function is deliberately pure: publishing the returned state belongs to the future
/// executor and must happen only after its event evidence has been durably written.
///
/// # Errors
/// Refuses skipped, repeated, ambiguous, or recovery-inferred transitions.
pub fn normalization_next_status(
    status: FedoraWorkstationPreparationStatus,
    event: NormalizationStageEvent,
) -> Result<FedoraWorkstationPreparationStatus, PreparationError> {
    match (status, event) {
        (
            FedoraWorkstationPreparationStatus::InstalledSystemProven,
            NormalizationStageEvent::PlanAccepted,
        ) => Ok(FedoraWorkstationPreparationStatus::NormalizationPlanned),
        (
            FedoraWorkstationPreparationStatus::NormalizationPlanned,
            NormalizationStageEvent::GuestExecutionStarted,
        ) => Ok(FedoraWorkstationPreparationStatus::NormalizationRunning),
        (
            FedoraWorkstationPreparationStatus::NormalizationRunning,
            NormalizationStageEvent::GuestEvidenceProven,
        ) => Ok(FedoraWorkstationPreparationStatus::NormalizationGuestComplete),
        (
            FedoraWorkstationPreparationStatus::NormalizationGuestComplete,
            NormalizationStageEvent::ControlledShutdownRequested,
        ) => Ok(FedoraWorkstationPreparationStatus::ShutdownPending),
        (
            FedoraWorkstationPreparationStatus::ShutdownPending,
            NormalizationStageEvent::CleanShutdownObserved,
        ) => Ok(FedoraWorkstationPreparationStatus::OfflineProofPending),
        (
            FedoraWorkstationPreparationStatus::OfflineProofPending,
            NormalizationStageEvent::OfflineProofPassed,
        ) => Ok(FedoraWorkstationPreparationStatus::Normalized),
        _ => Err(PreparationError::InvalidStateTransition),
    }
}

/// Produces policy only; it does not advance state or mutate the host or guest.
///
/// # Errors
/// Refuses an unproven installed system, an existing canonical base, or lost isolation.
pub fn plan_fedora_workstation_normalization(
    preparation: &FedoraWorkstationPreparation,
    canonical_base_absent: bool,
    legacy_fedora_isolated: bool,
    execution_channel: NormalizationExecutionChannel,
) -> Result<FedoraWorkstationNormalizationPlan, PreparationError> {
    if preparation.status != FedoraWorkstationPreparationStatus::InstalledSystemProven
        || preparation.execution.graphical_boot_confirmation.is_none()
        || preparation.execution.disk_only_topology.is_none()
    {
        return Err(PreparationError::InvalidStateTransition);
    }
    if !canonical_base_absent || !legacy_fedora_isolated {
        return Err(PreparationError::NormalizationCheckFailed(
            "preparation isolation",
        ));
    }
    let guest = NormalizationAuthority::PreparationGuest;
    let offline = NormalizationAuthority::OfflineReadOnlyInspector;
    let host = NormalizationAuthority::ForgeHost;
    Ok(FedoraWorkstationNormalizationPlan {
        preparation_id: preparation.preparation_id.clone(),
        staging_path: preparation.staging.path.clone(),
        recipe: FedoraWorkstationNormalizationRecipe::V1,
        package_policy:
            FedoraWorkstationPackagePolicy::FullyUpdatedAtPreparationWithRecordedManifest,
        execution_channel,
        execution_ready: execution_channel
            == NormalizationExecutionChannel::PreparationOnlyEphemeral,
        tasks: vec![
            NormalizationTaskPlan {
                task: NormalizationTask::AccountsAndGnomeFirstUse,
                authority: guest,
                operator_required: false,
            },
            NormalizationTaskPlan {
                task: NormalizationTask::MachineAndHostIdentity,
                authority: guest,
                operator_required: false,
            },
            NormalizationTaskPlan {
                task: NormalizationTask::NetworkIdentity,
                authority: guest,
                operator_required: false,
            },
            NormalizationTaskPlan {
                task: NormalizationTask::SshHostIdentity,
                authority: guest,
                operator_required: false,
            },
            NormalizationTaskPlan {
                task: NormalizationTask::InstallerResidue,
                authority: guest,
                operator_required: false,
            },
            NormalizationTaskPlan {
                task: NormalizationTask::PackageConsistency,
                authority: guest,
                operator_required: false,
            },
            NormalizationTaskPlan {
                task: NormalizationTask::SelinuxAndLabels,
                authority: guest,
                operator_required: false,
            },
            NormalizationTaskPlan {
                task: NormalizationTask::FilesystemResidue,
                authority: guest,
                operator_required: false,
            },
            NormalizationTaskPlan {
                task: NormalizationTask::SpiceDesktopIntegration,
                authority: guest,
                operator_required: false,
            },
            NormalizationTaskPlan {
                task: NormalizationTask::QgaPolicy,
                authority: host,
                operator_required: false,
            },
            NormalizationTaskPlan {
                task: NormalizationTask::ControlledShutdown,
                authority: host,
                operator_required: false,
            },
            NormalizationTaskPlan {
                task: NormalizationTask::OfflineFinalProof,
                authority: offline,
                operator_required: false,
            },
        ],
        mutation: false,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NormalizationShutdownEvidence {
    GuestRequestedAndLibvirtObservedShutoff,
    ForcedStop,
    StillRunning,
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
    pub shutdown: NormalizationShutdownEvidence,
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
    GuestControlProtocolRefused,
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
            Self::GuestControlProtocolRefused => {
                formatter.write_str("guest-control protocol refused")
            }
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
        execution: FedoraWorkstationExecutionEvidence::default(),
    }
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('\'', "&apos;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Renders the only Phase 4.4 installer topology. It contains one installation
/// ISO and one preparation disk, and deliberately contains no QGA or seed.
#[must_use]
pub fn render_fedora_workstation_installer_xml(
    preparation: &FedoraWorkstationPreparation,
) -> String {
    let installer = &preparation.installer;
    format!(
        "<domain type='kvm'>\n  <name>{}</name>\n  <uuid>{}</uuid>\n  <memory unit='MiB'>8192</memory>\n  <currentMemory unit='MiB'>8192</currentMemory>\n  <vcpu placement='static'>4</vcpu>\n  <os firmware='efi'>\n    <type arch='x86_64' machine='q35'>hvm</type>\n    <firmware>\n      <feature enabled='no' name='secure-boot'/>\n      <feature enabled='no' name='enrolled-keys'/>\n    </firmware>\n    <boot dev='cdrom'/>\n    <boot dev='hd'/>\n  </os>\n  <features><acpi/><apic/></features>\n  <cpu mode='host-passthrough'/>\n  <devices>\n    <disk type='file' device='disk'>\n      <driver name='qemu' type='qcow2'/>\n      <source file='{}'/>\n      <target dev='vda' bus='virtio'/>\n    </disk>\n    <disk type='file' device='cdrom'>\n      <driver name='qemu' type='raw'/>\n      <source file='{}'/>\n      <target dev='sda' bus='sata'/>\n      <readonly/>\n    </disk>\n    <interface type='network'>\n      <source network='default'/>\n      <model type='virtio'/>\n    </interface>\n    <graphics type='spice' autoport='yes'/>\n    <video><model type='virtio' heads='1' primary='yes'/></video>\n    <input type='tablet' bus='usb'/>\n    <input type='keyboard' bus='usb'/>\n    <sound model='ich9'/>\n  </devices>\n</domain>\n",
        xml_escape(&installer.name),
        xml_escape(&installer.uuid),
        xml_escape(&installer.disk_path.to_string_lossy()),
        xml_escape(&installer.iso_path.to_string_lossy()),
    )
}

/// Renders the disk-only topology while carrying forward the proven network identity.
///
/// # Errors
/// Refuses to render when the authoritative pre-redefine topology is unavailable.
pub fn render_fedora_workstation_disk_only_xml(
    preparation: &FedoraWorkstationPreparation,
) -> Result<String, PreparationError> {
    let mut xml = render_fedora_workstation_installer_xml(preparation);
    let topology = preparation
        .execution
        .resolved_topology
        .as_ref()
        .ok_or_else(|| PreparationError::Backend("authoritative stable MAC unavailable".into()))?;
    xml = xml.replace(
        "    <interface type='network'>\n      <source network='default'/>",
        &format!(
            "    <interface type='network'>\n      <mac address='{}'/>\n      <source network='default'/>",
            xml_escape(&topology.nic_mac)
        ),
    );
    let cdrom = format!(
        "    <disk type='file' device='cdrom'>\n      <driver name='qemu' type='raw'/>\n      <source file='{}'/>\n      <target dev='sda' bus='sata'/>\n      <readonly/>\n    </disk>\n",
        xml_escape(&preparation.installer.iso_path.to_string_lossy())
    );
    Ok(xml
        .replace("    <boot dev='cdrom'/>\n", "")
        .replace(&cdrom, ""))
}

fn xml_attribute(xml: &str, element: &str, attribute: &str) -> Option<String> {
    let start = xml.find(&format!("<{element}"))?;
    let end = xml[start..].find('>')? + start;
    let opening = &xml[start..=end];
    for quote in ['\'', '"'] {
        let marker = format!("{attribute}={quote}");
        if let Some(offset) = opening.find(&marker) {
            let value = &opening[offset + marker.len()..];
            return Some(value[..value.find(quote)?].to_owned());
        }
    }
    None
}

fn xml_blocks<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let start = format!("<{tag}");
    let end = format!("</{tag}>");
    let mut rest = xml;
    let mut blocks = Vec::new();
    while let Some(offset) = rest.find(&start) {
        rest = &rest[offset..];
        let Some(close) = rest.find(&end) else { break };
        let length = close + end.len();
        blocks.push(&rest[..length]);
        rest = &rest[length..];
    }
    blocks
}

fn xml_openings<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let start = format!("<{tag}");
    let mut rest = xml;
    let mut values = Vec::new();
    while let Some(offset) = rest.find(&start) {
        rest = &rest[offset..];
        let Some(end) = rest.find('>') else { break };
        values.push(&rest[..=end]);
        rest = &rest[end + 1..];
    }
    values
}

fn xml_elements<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let start = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut rest = xml;
    let mut values = Vec::new();
    while let Some(offset) = rest.find(&start) {
        rest = &rest[offset..];
        let Some(open_end) = rest.find('>') else {
            break;
        };
        if rest[..=open_end].trim_end().ends_with("/>") {
            values.push(&rest[..=open_end]);
            rest = &rest[open_end + 1..];
        } else if let Some(close_offset) = rest.find(&close) {
            let end = close_offset + close.len();
            values.push(&rest[..end]);
            rest = &rest[end..];
        } else {
            break;
        }
    }
    values
}

fn tag_text(xml: &str, tag: &str) -> Option<String> {
    let after = &xml[xml.find(&format!("<{tag}"))?..];
    let open = after.find('>')? + 1;
    let close = after[open..].find(&format!("</{tag}>"))? + open;
    Some(after[open..close].trim().to_owned())
}

fn direct_child_kinds(xml: &str) -> Vec<String> {
    let Some(open) = xml.find('>') else {
        return Vec::new();
    };
    let mut rest = &xml[open + 1..];
    let mut depth = 0usize;
    let mut kinds = Vec::new();
    while let Some(start) = rest.find('<') {
        rest = &rest[start + 1..];
        let Some(end) = rest.find('>') else { break };
        let token = &rest[..end];
        if token.starts_with('/') {
            depth = depth.saturating_sub(1);
        } else if !token.starts_with(['?', '!']) {
            if depth == 0 {
                kinds.push(
                    token
                        .split_whitespace()
                        .next()
                        .unwrap_or("")
                        .trim_end_matches('/')
                        .to_owned(),
                );
            }
            if !token.ends_with('/') {
                depth += 1;
            }
        }
        rest = &rest[end + 1..];
    }
    kinds
}

fn require_attribute(
    block: &str,
    element: &str,
    attribute: &str,
    expected: &str,
) -> Result<(), PreparationError> {
    if xml_attribute(block, element, attribute).as_deref() == Some(expected) {
        Ok(())
    } else {
        Err(PreparationError::Backend(format!(
            "installer {element} {attribute} is not {expected}"
        )))
    }
}

fn device(
    kind: &str,
    identity: impl Into<String>,
    classification: InstallerDeviceClassification,
) -> ResolvedInstallerDevice {
    ResolvedInstallerDevice {
        kind: kind.to_owned(),
        identity: identity.into(),
        classification,
    }
}

/// Validates the security- and ownership-relevant persistent installer topology.
/// Libvirt may add controllers and addresses, so proof targets semantic devices.
///
/// # Errors
/// Refuses identity, state, device, provisioning, or topology drift.
#[allow(clippy::too_many_lines)]
pub fn prove_fedora_workstation_installer_topology(
    preparation: &FedoraWorkstationPreparation,
    evidence: &InstallerDomainEvidence,
) -> Result<ProvenResolvedInstallerTopology, PreparationError> {
    let expected = &preparation.installer;
    if evidence.name != expected.name
        || evidence.uuid != expected.uuid
        || !evidence.persistent
        || !evidence.shutoff
        || evidence.autostart
    {
        return Err(PreparationError::Backend(
            "installer domain identity/state drift".to_owned(),
        ));
    }
    let xml = &evidence.xml;
    let disk_only = fedora_workstation_topology_mode(preparation.status)?
        == FedoraWorkstationTopologyMode::DiskOnly;
    let os = xml_blocks(xml, "os")
        .into_iter()
        .next()
        .ok_or_else(|| PreparationError::Backend("installer os topology absent".into()))?;
    require_attribute(os, "os", "firmware", "efi")?;
    require_attribute(os, "type", "arch", "x86_64")?;
    let resolved_machine = xml_attribute(os, "type", "machine")
        .ok_or_else(|| PreparationError::Backend("resolved machine type absent".into()))?;
    let q35_alias_canonical = evidence
        .q35_alias_canonical
        .as_deref()
        .ok_or_else(|| PreparationError::Backend("libvirt q35 alias proof absent".into()))?;
    if resolved_machine != q35_alias_canonical {
        return Err(PreparationError::Backend(
            "resolved machine is not libvirt's canonical q35 target".into(),
        ));
    }
    let loader = tag_text(os, "loader")
        .ok_or_else(|| PreparationError::Backend("UEFI loader absent".into()))?;
    let loader_block = xml_blocks(os, "loader")
        .into_iter()
        .next()
        .ok_or_else(|| PreparationError::Backend("UEFI loader absent".into()))?;
    require_attribute(loader_block, "loader", "readonly", "yes")?;
    require_attribute(loader_block, "loader", "type", "pflash")?;
    if loader != "/usr/share/edk2/ovmf/OVMF_CODE_4M.qcow2" {
        return Err(PreparationError::Backend(
            "unexpected UEFI loader path".into(),
        ));
    }
    let nvram = tag_text(os, "nvram")
        .ok_or_else(|| PreparationError::Backend("UEFI NVRAM absent".into()))?;
    if nvram != format!("/var/lib/libvirt/qemu/nvram/{}_VARS.qcow2", expected.name) {
        return Err(PreparationError::Backend(
            "unexpected UEFI NVRAM path".into(),
        ));
    }
    let boots = xml_openings(os, "boot");
    if (disk_only
        && (boots.len() != 1 || xml_attribute(boots[0], "boot", "dev").as_deref() != Some("hd")))
        || (!disk_only
            && (boots.len() != 2
                || xml_attribute(boots[0], "boot", "dev").as_deref() != Some("cdrom")
                || xml_attribute(boots[1], "boot", "dev").as_deref() != Some("hd")))
    {
        return Err(PreparationError::Backend(
            "installer boot policy drift".into(),
        ));
    }
    if tag_text(xml, "vcpu").as_deref() != Some("4")
        || tag_text(xml, "memory").as_deref() != Some("8388608")
        || xml_attribute(xml, "memory", "unit").as_deref() != Some("KiB")
    {
        return Err(PreparationError::Backend(
            "installer CPU/memory drift".into(),
        ));
    }

    let devices_xml = xml_blocks(xml, "devices")
        .into_iter()
        .next()
        .ok_or_else(|| PreparationError::Backend("installer devices absent".into()))?;
    let allowed_kinds = [
        "emulator",
        "disk",
        "controller",
        "interface",
        "input",
        "graphics",
        "sound",
        "audio",
        "video",
        "watchdog",
        "memballoon",
    ];
    for kind in direct_child_kinds(devices_xml) {
        if !allowed_kinds.contains(&kind.as_str()) {
            return Err(PreparationError::Backend(format!(
                "unknown or forbidden direct installer device: {kind}"
            )));
        }
    }
    let mut devices = Vec::new();
    let disks = xml_blocks(devices_xml, "disk");
    if disks.len() != if disk_only { 1 } else { 2 } {
        return Err(PreparationError::Backend(
            "installer requires exactly two disks".into(),
        ));
    }
    let writable = disks
        .iter()
        .filter(|block| xml_attribute(block, "disk", "device").as_deref() == Some("disk"))
        .copied()
        .collect::<Vec<_>>();
    let cdrom = disks
        .iter()
        .filter(|block| xml_attribute(block, "disk", "device").as_deref() == Some("cdrom"))
        .copied()
        .collect::<Vec<_>>();
    if writable.len() != 1 || cdrom.len() != usize::from(!disk_only) {
        return Err(PreparationError::Backend(
            "installer disk roles drift".into(),
        ));
    }
    require_attribute(writable[0], "driver", "type", "qcow2")?;
    require_attribute(writable[0], "target", "dev", "vda")?;
    require_attribute(writable[0], "target", "bus", "virtio")?;
    require_attribute(
        writable[0],
        "source",
        "file",
        &expected.disk_path.to_string_lossy(),
    )?;
    if writable[0].contains("<readonly") {
        return Err(PreparationError::Backend(
            "staging disk became read-only".into(),
        ));
    }
    devices.push(device(
        "disk",
        format!("writable:qcow2:virtio:{}", expected.disk_path.display()),
        InstallerDeviceClassification::Required,
    ));
    if disk_only {
        let interfaces = xml_blocks(devices_xml, "interface");
        let authoritative_mac = preparation
            .execution
            .resolved_topology
            .as_ref()
            .map(|topology| topology.nic_mac.as_str())
            .ok_or_else(|| {
                PreparationError::Backend("authoritative stable MAC unavailable".into())
            })?;
        if interfaces.len() != 1
            || xml_attribute(interfaces[0], "mac", "address").as_deref() != Some(authoritative_mac)
        {
            return Err(PreparationError::Backend(
                "disk-only network identity differs from authoritative stable MAC".into(),
            ));
        }
        let cdrom = format!(
            "    <disk type='file' device='cdrom'>\n      <driver name='qemu' type='raw'/>\n      <source file='{}'/>\n      <target dev='sda' bus='sata'/>\n      <readonly/>\n    </disk>\n",
            xml_escape(&expected.iso_path.to_string_lossy())
        );
        let mut installer_evidence = evidence.clone();
        installer_evidence.xml = installer_evidence
            .xml
            .replace(
                "    <boot dev='hd'/>",
                "    <boot dev='cdrom'/>\n    <boot dev='hd'/>",
            )
            .replace("  </devices>", &format!("{cdrom}  </devices>"));
        let mut installer_preparation = preparation.clone();
        installer_preparation.status = FedoraWorkstationPreparationStatus::InstallerRunning;
        let mut resolved = prove_fedora_workstation_installer_topology(
            &installer_preparation,
            &installer_evidence,
        )?;
        resolved.devices.retain(|device| {
            !(device.kind == "disk" && device.identity.starts_with("readonly-iso:"))
        });
        resolved.xml_sha256 = format!("{:x}", Sha256::digest(evidence.xml.as_bytes()));
        return Ok(resolved);
    }
    require_attribute(cdrom[0], "driver", "type", "raw")?;
    require_attribute(cdrom[0], "target", "dev", "sda")?;
    require_attribute(cdrom[0], "target", "bus", "sata")?;
    require_attribute(
        cdrom[0],
        "source",
        "file",
        &expected.iso_path.to_string_lossy(),
    )?;
    if !cdrom[0].contains("<readonly") {
        return Err(PreparationError::Backend(
            "installer ISO is writable".into(),
        ));
    }
    devices.push(device(
        "disk",
        format!("readonly-iso:sata:{}", expected.iso_path.display()),
        InstallerDeviceClassification::Required,
    ));

    let interfaces = xml_blocks(devices_xml, "interface");
    if interfaces.len() != 1 {
        return Err(PreparationError::Backend(
            "installer requires exactly one NIC".into(),
        ));
    }
    require_attribute(interfaces[0], "interface", "type", "network")?;
    require_attribute(interfaces[0], "source", "network", "default")?;
    require_attribute(interfaces[0], "model", "type", "virtio")?;
    let nic_mac = xml_attribute(interfaces[0], "mac", "address")
        .ok_or_else(|| PreparationError::Backend("resolved NIC MAC absent".into()))?;
    if !nic_mac.starts_with("52:54:00:") || nic_mac.len() != 17 {
        return Err(PreparationError::Backend(
            "resolved NIC MAC policy drift".into(),
        ));
    }
    devices.push(device(
        "interface",
        format!("default:virtio:{nic_mac}"),
        InstallerDeviceClassification::Required,
    ));

    let graphics = xml_blocks(devices_xml, "graphics");
    if graphics.len() != 1 {
        return Err(PreparationError::Backend(
            "installer requires one graphics device".into(),
        ));
    }
    require_attribute(graphics[0], "graphics", "type", "spice")?;
    require_attribute(graphics[0], "graphics", "autoport", "yes")?;
    devices.push(device(
        "graphics",
        "spice:autoport",
        InstallerDeviceClassification::Required,
    ));
    let videos = xml_blocks(devices_xml, "video");
    if videos.len() != 1 {
        return Err(PreparationError::Backend(
            "installer requires one video device".into(),
        ));
    }
    require_attribute(videos[0], "model", "type", "virtio")?;
    require_attribute(videos[0], "model", "heads", "1")?;
    require_attribute(videos[0], "model", "primary", "yes")?;
    devices.push(device(
        "video",
        "virtio:one-head:primary",
        InstallerDeviceClassification::Required,
    ));

    let inputs = xml_elements(devices_xml, "input");
    let input_identities = inputs
        .iter()
        .map(|block| {
            format!(
                "{}:{}",
                xml_attribute(block, "input", "type").unwrap_or_default(),
                xml_attribute(block, "input", "bus").unwrap_or_default()
            )
        })
        .collect::<Vec<_>>();
    for required in ["tablet:usb", "keyboard:usb"] {
        if input_identities
            .iter()
            .filter(|value| value.as_str() == required)
            .count()
            != 1
        {
            return Err(PreparationError::Backend(format!(
                "required input {required} drift"
            )));
        }
        devices.push(device(
            "input",
            required,
            InstallerDeviceClassification::Required,
        ));
    }
    let mut normalized_inputs = input_identities
        .iter()
        .filter(|value| matches!(value.as_str(), "mouse:ps2" | "keyboard:ps2"))
        .cloned()
        .collect::<Vec<_>>();
    normalized_inputs.sort();
    if normalized_inputs != ["keyboard:ps2", "mouse:ps2"] || input_identities.len() != 4 {
        return Err(PreparationError::Backend(
            "libvirt PS/2 input normalization drift".into(),
        ));
    }
    for value in normalized_inputs {
        devices.push(device(
            "input",
            value,
            InstallerDeviceClassification::AllowedLibvirtNormalization,
        ));
    }

    let sounds = xml_blocks(devices_xml, "sound");
    if sounds.len() != 1 {
        return Err(PreparationError::Backend(
            "installer audio policy drift".into(),
        ));
    }
    require_attribute(sounds[0], "sound", "model", "ich9")?;
    devices.push(device(
        "sound",
        "ich9",
        InstallerDeviceClassification::Required,
    ));
    let audio = xml_openings(devices_xml, "audio");
    if audio.len() != 1 {
        return Err(PreparationError::Backend(
            "libvirt audio backend drift".into(),
        ));
    }
    require_attribute(audio[0], "audio", "type", "spice")?;
    devices.push(device(
        "audio",
        "spice",
        InstallerDeviceClassification::AllowedLibvirtNormalization,
    ));

    let controllers = xml_openings(devices_xml, "controller");
    if controllers.len() != 8 {
        return Err(PreparationError::Backend(format!(
            "libvirt controller set drift: {} controllers",
            controllers.len()
        )));
    }
    let mut controller_identities = Vec::new();
    for block in controllers {
        let kind = xml_attribute(block, "controller", "type").unwrap_or_default();
        let index = xml_attribute(block, "controller", "index").unwrap_or_default();
        let model = xml_attribute(block, "controller", "model").unwrap_or_default();
        let identity = format!("{kind}:{index}:{model}");
        let valid = identity == "usb:0:qemu-xhci"
            || identity == "sata:0:"
            || identity == "pci:0:pcie-root"
            || (kind == "pci"
                && matches!(index.as_str(), "1" | "2" | "3" | "4" | "5")
                && model == "pcie-root-port");
        if !valid {
            return Err(PreparationError::Backend(format!(
                "unexpected controller {identity}"
            )));
        }
        controller_identities.push(identity);
    }
    let mut chassis = xml_openings(devices_xml, "target")
        .into_iter()
        .filter_map(|block| xml_attribute(block, "target", "chassis"))
        .collect::<Vec<_>>();
    chassis.sort();
    if chassis != ["1", "2", "3", "4", "5"] {
        return Err(PreparationError::Backend(
            "PCIe root-port chassis normalization drift".into(),
        ));
    }
    controller_identities.sort();
    for identity in controller_identities {
        devices.push(device(
            "controller",
            identity,
            InstallerDeviceClassification::AllowedLibvirtNormalization,
        ));
    }

    let watchdogs = xml_openings(devices_xml, "watchdog");
    if watchdogs.len() != 1 {
        return Err(PreparationError::Backend(
            "libvirt watchdog normalization drift".into(),
        ));
    }
    require_attribute(watchdogs[0], "watchdog", "model", "itco")?;
    require_attribute(watchdogs[0], "watchdog", "action", "reset")?;
    devices.push(device(
        "watchdog",
        "itco:reset",
        InstallerDeviceClassification::AllowedLibvirtNormalization,
    ));
    let balloons = xml_blocks(devices_xml, "memballoon");
    if balloons.len() != 1 {
        return Err(PreparationError::Backend(
            "libvirt balloon normalization drift".into(),
        ));
    }
    require_attribute(balloons[0], "memballoon", "model", "virtio")?;
    devices.push(device(
        "memballoon",
        "virtio",
        InstallerDeviceClassification::AllowedLibvirtNormalization,
    ));
    let emulators = xml_blocks(devices_xml, "emulator");
    if emulators.len() != 1
        || tag_text(devices_xml, "emulator").as_deref() != Some("/usr/bin/qemu-system-x86_64")
    {
        return Err(PreparationError::Backend(
            "emulator normalization drift".into(),
        ));
    }
    devices.push(device(
        "emulator",
        "/usr/bin/qemu-system-x86_64",
        InstallerDeviceClassification::AllowedLibvirtNormalization,
    ));

    devices.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then(left.identity.cmp(&right.identity))
    });
    Ok(ProvenResolvedInstallerTopology {
        requested_machine_family: "Q35".to_owned(),
        resolved_machine_type: resolved_machine,
        q35_alias_canonical: q35_alias_canonical.to_owned(),
        firmware: "UEFI:pflash:readonly".to_owned(),
        loader,
        nvram,
        nic_mac,
        devices,
        xml_sha256: format!("{:x}", Sha256::digest(xml.as_bytes())),
    })
}

/// Proves the exact pre-detach installer topology without deriving installation
/// success from the domain's power state or the current durable stage.
///
/// # Errors
/// Refuses any identity, state, device, or topology drift.
pub fn prove_fedora_workstation_post_install_staging_topology(
    preparation: &FedoraWorkstationPreparation,
    evidence: &InstallerDomainEvidence,
) -> Result<ProvenResolvedInstallerTopology, PreparationError> {
    let mut expected = preparation.clone();
    expected.status = FedoraWorkstationPreparationStatus::InstallerRunning;
    prove_fedora_workstation_installer_topology(&expected, evidence)
}

/// Proves the exact same-domain, staging-disk-only boot topology.
///
/// # Errors
/// Refuses an attached ISO or any identity, state, device, or topology drift.
pub fn prove_fedora_workstation_disk_only_topology(
    preparation: &FedoraWorkstationPreparation,
    evidence: &InstallerDomainEvidence,
) -> Result<ProvenResolvedInstallerTopology, PreparationError> {
    let mut expected = preparation.clone();
    expected.status = FedoraWorkstationPreparationStatus::InstalledDiskBootPending;
    prove_fedora_workstation_installer_topology(&expected, evidence)
}

/// Proves that a disk-only recovery candidate differs only in its single NIC MAC.
///
/// # Errors
/// Refuses missing authority, an already-correct MAC, multiple NICs, or any
/// non-MAC disk-only topology drift.
pub fn prove_fedora_workstation_disk_only_mac_recovery_candidate(
    preparation: &FedoraWorkstationPreparation,
    evidence: &InstallerDomainEvidence,
) -> Result<String, PreparationError> {
    if fedora_workstation_topology_mode(preparation.status)?
        != FedoraWorkstationTopologyMode::DiskOnly
    {
        return Err(PreparationError::InvalidStateTransition);
    }
    let authoritative = preparation
        .execution
        .resolved_topology
        .as_ref()
        .map(|topology| topology.nic_mac.as_str())
        .ok_or_else(|| PreparationError::Backend("authoritative stable MAC unavailable".into()))?;
    let devices = xml_blocks(&evidence.xml, "devices")
        .into_iter()
        .next()
        .ok_or_else(|| PreparationError::Backend("domain devices absent".into()))?;
    let interfaces = xml_blocks(devices, "interface");
    if interfaces.len() != 1 {
        return Err(PreparationError::Backend(
            "disk-only recovery requires exactly one NIC".into(),
        ));
    }
    let observed = xml_attribute(interfaces[0], "mac", "address")
        .ok_or_else(|| PreparationError::Backend("observed disk-only MAC absent".into()))?;
    if observed == authoritative {
        return Err(PreparationError::Backend(
            "disk-only MAC recovery is unnecessary".into(),
        ));
    }
    let mut corrected = evidence.clone();
    corrected.xml = corrected.xml.replacen(
        &format!("<mac address='{observed}'/>"),
        &format!("<mac address='{authoritative}'/>"),
        1,
    );
    if corrected.xml == evidence.xml {
        corrected.xml = corrected.xml.replacen(
            &format!("<mac address=\"{observed}\"/>"),
            &format!("<mac address=\"{authoritative}\"/>"),
            1,
        );
    }
    prove_fedora_workstation_disk_only_topology(preparation, &corrected)?;
    Ok(observed)
}

fn observed_single_domain_mac(
    evidence: &InstallerDomainEvidence,
) -> Result<String, PreparationError> {
    let devices = xml_blocks(&evidence.xml, "devices")
        .into_iter()
        .next()
        .ok_or_else(|| PreparationError::Backend("domain devices absent".into()))?;
    let interfaces = xml_blocks(devices, "interface");
    if interfaces.len() != 1 {
        return Err(PreparationError::Backend(
            "domain requires exactly one NIC".into(),
        ));
    }
    xml_attribute(interfaces[0], "mac", "address")
        .ok_or_else(|| PreparationError::Backend("observed domain MAC absent".into()))
}

/// Publishes installed-system proof only from complete machine evidence and
/// the operator's explicit graphical confirmation.
///
/// # Errors
/// Refuses running-only evidence, operator-only evidence, identity/topology
/// drift, missing durable disk-only authority, or an invalid state transition.
pub fn record_graphical_installed_system_confirmation(
    preparation: &mut FedoraWorkstationPreparation,
    domain: &InstallerDomainEvidence,
    operator_confirmed: bool,
    display_dynamic_resizing_needs_review: bool,
) -> Result<GraphicalConfirmationDisposition, PreparationError> {
    if preparation.status == FedoraWorkstationPreparationStatus::InstalledSystemProven {
        return if preparation.execution.graphical_boot_confirmation.is_some() {
            Ok(GraphicalConfirmationDisposition::AlreadyPublished)
        } else {
            Err(PreparationError::InvalidStateTransition)
        };
    }
    if preparation.status != FedoraWorkstationPreparationStatus::AwaitingGraphicalBootConfirmation
        || !operator_confirmed
        || !domain.running
        || domain.shutoff
    {
        return Err(PreparationError::ExplicitContinuationRequired);
    }
    let mut persistent = domain.clone();
    persistent.shutoff = true;
    persistent.running = false;
    let resolved = prove_fedora_workstation_disk_only_topology(preparation, &persistent)?;
    if preparation.execution.disk_only_topology.as_ref() != Some(&resolved) {
        return Err(PreparationError::Backend(
            "running machine topology differs from durable disk-only proof".into(),
        ));
    }
    preparation.execution.graphical_boot_confirmation = Some(GraphicalBootConfirmationEvidence {
        preparation_id: preparation.preparation_id.clone(),
        confirmation_kind: GraphicalBootConfirmationKind::InstalledFedoraGnomeFirstRunVisible,
        domain_name: preparation.installer.name.clone(),
        domain_uuid: preparation.installer.uuid.clone(),
        staging_path: preparation.staging.path.clone(),
        graphical_confirmation_recorded: true,
        observed_running: true,
        disk_only_topology_xml_sha256: resolved.xml_sha256,
        gnome_initial_setup_completed: false,
        display_dynamic_resizing_needs_review,
    });
    preparation.status = FedoraWorkstationPreparationStatus::InstalledSystemProven;
    Ok(GraphicalConfirmationDisposition::Published)
}

fn prove_staging(
    preparation: &FedoraWorkstationPreparation,
    volume: &PreparationVolumeEvidence,
) -> Result<(), PreparationError> {
    if volume.name != preparation.staging.volume_name
        || volume.path != preparation.staging.path
        || volume.format != "qcow2"
        || volume.capacity_bytes != FEDORA_WORKSTATION_STAGING_CAPACITY_BYTES
        || volume.backing_path.is_some()
        || volume.key.is_empty()
    {
        return Err(PreparationError::Backend(
            "staging volume identity or storage shape drift".to_owned(),
        ));
    }
    Ok(())
}

/// Resumes the operator-confirmed post-install boundary through one disk boot.
/// Every irreversible action is preceded by a durable intent boundary. A crash
/// after the start request is resolved by observing the same domain running;
/// an ambiguous shutoff `InstalledDiskBooting` state fails closed and never retries.
///
/// # Errors
/// Refuses missing confirmation, identity/topology drift, canonical collisions,
/// publication failures, backend failures, and ambiguous start recovery.
#[allow(clippy::too_many_lines)]
pub fn execute_to_installed_disk_running<B, P>(
    backend: &mut B,
    preparation: &mut FedoraWorkstationPreparation,
    operator_confirmed: bool,
    mut publish: P,
) -> Result<InstalledDiskBootDisposition, PreparationError>
where
    B: FedoraWorkstationPreparationBackend,
    P: FnMut(&FedoraWorkstationPreparation) -> Result<(), String>,
{
    let volume = backend
        .inspect_volume("default", &preparation.staging.volume_name)
        .map_err(PreparationError::Backend)?
        .ok_or_else(|| PreparationError::Backend("staging volume absent".into()))?;
    prove_staging(preparation, &volume)?;
    if preparation.execution.staging_volume_key.as_deref() != Some(volume.key.as_str()) {
        return Err(PreparationError::Backend(
            "durable staging identity drift".into(),
        ));
    }
    if backend
        .canonical_base_exists("default", &preparation.canonical.volume_name)
        .map_err(PreparationError::Backend)?
    {
        return Err(PreparationError::CanonicalBaseCollision);
    }

    if preparation.status == FedoraWorkstationPreparationStatus::InstallerRunning {
        let domain = backend
            .inspect_installer_domain(&preparation.installer.name)
            .map_err(PreparationError::Backend)?
            .ok_or_else(|| PreparationError::Backend("installer domain absent".into()))?;
        prove_fedora_workstation_post_install_staging_topology(preparation, &domain)?;
        record_anaconda_installation_completed(preparation, domain.shutoff, operator_confirmed)?;
        publish(preparation).map_err(PreparationError::Backend)?;
    }

    if preparation.status == FedoraWorkstationPreparationStatus::InstallationConfirmed {
        if !preparation.operator_confirmation_recorded {
            return Err(PreparationError::ExplicitContinuationRequired);
        }
        let domain = backend
            .inspect_installer_domain(&preparation.installer.name)
            .map_err(PreparationError::Backend)?
            .ok_or_else(|| PreparationError::Backend("installer domain absent".into()))?;
        if !domain.shutoff {
            return Err(PreparationError::InstallationProofFailed);
        }
        let manually_confirmed_attached = preparation.execution.runtime_iso.is_none();
        if manually_confirmed_attached {
            let mut attached_preparation = preparation.clone();
            attached_preparation.status = FedoraWorkstationPreparationStatus::InstallerRunning;
            prove_fedora_workstation_post_install_staging_topology(&attached_preparation, &domain)?;
        }
        let authoritative_mac = preparation
            .execution
            .resolved_topology
            .as_ref()
            .map(|topology| topology.nic_mac.as_str())
            .ok_or_else(|| {
                PreparationError::Backend("authoritative stable MAC unavailable".into())
            })?;
        let observed_mac = observed_single_domain_mac(&domain)?;
        if manually_confirmed_attached {
            // Manual confirmation proves the installer-attached source topology;
            // the bounded redefine below is what establishes disk-only boot.
            backend
                .define_installer_domain(&render_fedora_workstation_disk_only_xml(preparation)?)
                .map_err(PreparationError::Backend)?;
        } else if observed_mac == authoritative_mac {
            prove_fedora_workstation_disk_only_topology(preparation, &domain)?;
        } else {
            prove_fedora_workstation_disk_only_mac_recovery_candidate(preparation, &domain)?;
            backend
                .define_installer_domain(&render_fedora_workstation_disk_only_xml(preparation)?)
                .map_err(PreparationError::Backend)?;
        }
        let detached = backend
            .inspect_installer_domain(&preparation.installer.name)
            .map_err(PreparationError::Backend)?
            .ok_or_else(|| PreparationError::Backend("redefined domain absent".into()))?;
        let resolved = prove_fedora_workstation_disk_only_topology(preparation, &detached)?;
        if let Some(runtime) = preparation.execution.runtime_iso.as_ref() {
            let retained = backend
                .inspect_volume("default", &runtime.volume_name)
                .map_err(PreparationError::Backend)?
                .ok_or_else(|| PreparationError::Backend("retained runtime ISO absent".into()))?;
            if retained.name != runtime.volume_name
                || retained.key != runtime.volume_key
                || retained.path != runtime.path
                || !matches!(retained.format.as_str(), "raw" | "iso")
                || retained.capacity_bytes != runtime.destination_bytes
                || retained.backing_path.is_some()
            {
                return Err(PreparationError::Backend(
                    "retained runtime ISO identity drift".into(),
                ));
            }
        }
        preparation.execution.disk_only_topology = Some(resolved);
        preparation.status = FedoraWorkstationPreparationStatus::InstalledDiskBootPending;
        publish(preparation).map_err(PreparationError::Backend)?;
        if manually_confirmed_attached {
            return Ok(InstalledDiskBootDisposition::DiskOnlyPrepared);
        }
    }

    if preparation.status == FedoraWorkstationPreparationStatus::InstalledDiskBootPending {
        let domain = backend
            .inspect_installer_domain(&preparation.installer.name)
            .map_err(PreparationError::Backend)?
            .ok_or_else(|| PreparationError::Backend("disk-only domain absent".into()))?;
        let resolved = prove_fedora_workstation_disk_only_topology(preparation, &domain)?;
        if preparation.execution.disk_only_topology.as_ref() != Some(&resolved) {
            return Err(PreparationError::Backend(
                "durable disk-only topology drift".into(),
            ));
        }
        preparation.status = FedoraWorkstationPreparationStatus::InstalledDiskBooting;
        preparation.execution.installed_disk_start_recorded = true;
        publish(preparation).map_err(PreparationError::Backend)?;
        backend
            .start_installer_domain(&preparation.installer.name)
            .map_err(PreparationError::Backend)?;
    }

    if preparation.status == FedoraWorkstationPreparationStatus::InstalledDiskBooting {
        let domain = backend
            .inspect_installer_domain(&preparation.installer.name)
            .map_err(PreparationError::Backend)?
            .ok_or_else(|| PreparationError::Backend("started domain absent".into()))?;
        if domain.shutoff {
            return Err(PreparationError::Backend(
                "installed-disk start outcome ambiguous; automatic retry refused".into(),
            ));
        }
        if !preparation.execution.installed_disk_start_recorded {
            return Err(PreparationError::InvalidStateTransition);
        }
        preparation.status = FedoraWorkstationPreparationStatus::AwaitingGraphicalBootConfirmation;
        publish(preparation).map_err(PreparationError::Backend)?;
        return Ok(InstalledDiskBootDisposition::Started);
    }

    if preparation.status == FedoraWorkstationPreparationStatus::AwaitingGraphicalBootConfirmation {
        let domain = backend
            .inspect_installer_domain(&preparation.installer.name)
            .map_err(PreparationError::Backend)?
            .ok_or_else(|| PreparationError::Backend("installed domain absent".into()))?;
        if domain.shutoff {
            return Err(PreparationError::Backend(
                "installed domain is no longer running".into(),
            ));
        }
        return Ok(InstalledDiskBootDisposition::AlreadyRunning);
    }
    Err(PreparationError::InvalidStateTransition)
}

/// Executes or resumes the preparation-owned staging/domain work and stops shut off.
/// The publisher is called after each proven boundary; resources are never deleted here.
///
/// # Errors
/// Refuses stale state, collisions, storage/topology drift, or backend/publication failure.
pub fn execute_to_installer_ready<B, P>(
    backend: &mut B,
    preparation: &mut FedoraWorkstationPreparation,
    mut publish: P,
) -> Result<InstallerReadyDisposition, PreparationError>
where
    B: FedoraWorkstationPreparationBackend,
    P: FnMut(&FedoraWorkstationPreparation) -> Result<(), String>,
{
    if preparation.status == FedoraWorkstationPreparationStatus::InstallerReady {
        let volume = backend
            .inspect_volume("default", &preparation.staging.volume_name)
            .map_err(PreparationError::Backend)?
            .ok_or_else(|| PreparationError::Backend("proven staging volume disappeared".into()))?;
        prove_staging(preparation, &volume)?;
        let domain = backend
            .inspect_installer_domain(&preparation.installer.name)
            .map_err(PreparationError::Backend)?
            .ok_or_else(|| {
                PreparationError::Backend("proven installer domain disappeared".into())
            })?;
        let resolved = prove_fedora_workstation_installer_topology(preparation, &domain)?;
        if preparation.execution.resolved_topology.as_ref() != Some(&resolved)
            || preparation.execution.installer_xml_sha256.as_deref()
                != Some(resolved.xml_sha256.as_str())
        {
            return Err(PreparationError::Backend(
                "durable resolved installer topology drift".into(),
            ));
        }
        return Ok(InstallerReadyDisposition::Resumed);
    }
    if preparation.status != FedoraWorkstationPreparationStatus::Planned {
        return Err(PreparationError::InvalidStateTransition);
    }
    if backend
        .canonical_base_exists("default", &preparation.canonical.volume_name)
        .map_err(PreparationError::Backend)?
    {
        return Err(PreparationError::CanonicalBaseCollision);
    }
    let pool = backend
        .inspect_pool("default")
        .map_err(PreparationError::Backend)?;
    if !pool.active || preparation.staging.path.parent() != Some(pool.target_path.as_path()) {
        return Err(PreparationError::Backend(
            "default pool inactive or staging path is outside its exact target".to_owned(),
        ));
    }
    let mut created = false;
    let volume = match backend
        .inspect_volume("default", &preparation.staging.volume_name)
        .map_err(PreparationError::Backend)?
    {
        Some(volume) if preparation.execution.staging_volume_key.is_some() => volume,
        Some(_) => return Err(PreparationError::StagingCollision),
        None => {
            backend
                .create_staging_volume(
                    "default",
                    &preparation.staging.volume_name,
                    preparation.staging.capacity_bytes,
                )
                .map_err(PreparationError::Backend)?;
            created = true;
            backend
                .inspect_volume("default", &preparation.staging.volume_name)
                .map_err(PreparationError::Backend)?
                .ok_or_else(|| PreparationError::Backend("created staging volume absent".into()))?
        }
    };
    prove_staging(preparation, &volume)?;
    preparation.execution.staging_volume_key = Some(volume.key);
    preparation.execution.staging_allocation_bytes = Some(volume.allocation_bytes);
    publish(preparation).map_err(PreparationError::Backend)?;

    let domain = match backend
        .inspect_installer_domain(&preparation.installer.name)
        .map_err(PreparationError::Backend)?
    {
        Some(domain) if preparation.execution.staging_volume_key.is_some() => domain,
        Some(_) => return Err(PreparationError::InstallerDomainCollision),
        None => {
            backend
                .define_installer_domain(&render_fedora_workstation_installer_xml(preparation))
                .map_err(PreparationError::Backend)?;
            backend
                .inspect_installer_domain(&preparation.installer.name)
                .map_err(PreparationError::Backend)?
                .ok_or_else(|| {
                    PreparationError::Backend("defined installer domain absent".into())
                })?
        }
    };
    let resolved = prove_fedora_workstation_post_install_staging_topology(preparation, &domain)?;
    preparation.execution.installer_xml_sha256 = Some(resolved.xml_sha256.clone());
    preparation.execution.resolved_topology = Some(resolved);
    preparation.status = FedoraWorkstationPreparationStatus::InstallerReady;
    publish(preparation).map_err(PreparationError::Backend)?;
    Ok(if created {
        InstallerReadyDisposition::Created
    } else {
        InstallerReadyDisposition::Resumed
    })
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
    if preparation.status != FedoraWorkstationPreparationStatus::OfflineProofPending
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
        (
            observation.shutdown
                == NormalizationShutdownEvidence::GuestRequestedAndLibvirtObservedShutoff,
            "clean shutdown",
        ),
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
        clean_shutdown: observation.shutdown
            == NormalizationShutdownEvidence::GuestRequestedAndLibvirtObservedShutoff,
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
            shutdown: NormalizationShutdownEvidence::GuestRequestedAndLibvirtObservedShutoff,
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
        preparation.status = FedoraWorkstationPreparationStatus::OfflineProofPending;
        preparation.operator_confirmation_recorded = true;
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

    #[test]
    fn normalization_planner_requires_installed_proof_and_never_mutates() {
        let (_fixture, mut preparation, mut backend) = executor_fixture();
        assert_eq!(
            plan_fedora_workstation_normalization(
                &preparation,
                true,
                true,
                NormalizationExecutionChannel::Unavailable,
            ),
            Err(PreparationError::InvalidStateTransition)
        );
        execute_to_installer_ready(&mut backend, &mut preparation, |_| Ok(())).unwrap();
        let topology = preparation.execution.resolved_topology.clone().unwrap();
        preparation.execution.disk_only_topology = Some(topology.clone());
        preparation.execution.graphical_boot_confirmation =
            Some(GraphicalBootConfirmationEvidence {
                preparation_id: preparation.preparation_id.clone(),
                confirmation_kind:
                    GraphicalBootConfirmationKind::InstalledFedoraGnomeFirstRunVisible,
                domain_name: preparation.installer.name.clone(),
                domain_uuid: preparation.installer.uuid.clone(),
                staging_path: preparation.staging.path.clone(),
                graphical_confirmation_recorded: true,
                observed_running: true,
                disk_only_topology_xml_sha256: topology.xml_sha256,
                gnome_initial_setup_completed: false,
                display_dynamic_resizing_needs_review: true,
            });
        preparation.status = FedoraWorkstationPreparationStatus::InstalledSystemProven;
        let before = preparation.clone();
        let plan = plan_fedora_workstation_normalization(
            &preparation,
            true,
            true,
            NormalizationExecutionChannel::Unavailable,
        )
        .unwrap();
        assert!(!plan.execution_ready);
        assert!(!plan.mutation);
        assert!(plan.tasks.iter().all(|task| !task.operator_required));
        assert_eq!(preparation, before);
        assert!(
            plan_fedora_workstation_normalization(
                &preparation,
                false,
                true,
                NormalizationExecutionChannel::Unavailable,
            )
            .is_err()
        );
        assert!(
            plan_fedora_workstation_normalization(
                &preparation,
                true,
                false,
                NormalizationExecutionChannel::Unavailable,
            )
            .is_err()
        );
    }

    #[test]
    fn force_stop_and_running_state_cannot_produce_normalized_disk() {
        let fixture = Fixture::new();
        let preparation = normalization_ready(&fixture);
        for shutdown in [
            NormalizationShutdownEvidence::ForcedStop,
            NormalizationShutdownEvidence::StillRunning,
        ] {
            let mut observation = normalization();
            observation.shutdown = shutdown;
            assert_eq!(
                prove_normalized_disk(&preparation, &observation),
                Err(PreparationError::NormalizationCheckFailed("clean shutdown"))
            );
        }
    }

    #[test]
    fn normalization_state_machine_cannot_skip_or_infer_completion() {
        let sequence = [
            (
                FedoraWorkstationPreparationStatus::InstalledSystemProven,
                NormalizationStageEvent::PlanAccepted,
                FedoraWorkstationPreparationStatus::NormalizationPlanned,
            ),
            (
                FedoraWorkstationPreparationStatus::NormalizationPlanned,
                NormalizationStageEvent::GuestExecutionStarted,
                FedoraWorkstationPreparationStatus::NormalizationRunning,
            ),
            (
                FedoraWorkstationPreparationStatus::NormalizationRunning,
                NormalizationStageEvent::GuestEvidenceProven,
                FedoraWorkstationPreparationStatus::NormalizationGuestComplete,
            ),
            (
                FedoraWorkstationPreparationStatus::NormalizationGuestComplete,
                NormalizationStageEvent::ControlledShutdownRequested,
                FedoraWorkstationPreparationStatus::ShutdownPending,
            ),
            (
                FedoraWorkstationPreparationStatus::ShutdownPending,
                NormalizationStageEvent::CleanShutdownObserved,
                FedoraWorkstationPreparationStatus::OfflineProofPending,
            ),
            (
                FedoraWorkstationPreparationStatus::OfflineProofPending,
                NormalizationStageEvent::OfflineProofPassed,
                FedoraWorkstationPreparationStatus::Normalized,
            ),
        ];
        for (current, event, expected) in sequence {
            assert_eq!(normalization_next_status(current, event).unwrap(), expected);
        }
        assert!(
            normalization_next_status(
                FedoraWorkstationPreparationStatus::InstalledSystemProven,
                NormalizationStageEvent::OfflineProofPassed,
            )
            .is_err()
        );
        assert!(
            normalization_next_status(
                FedoraWorkstationPreparationStatus::ShutdownPending,
                NormalizationStageEvent::GuestEvidenceProven,
            )
            .is_err()
        );
    }

    fn guest_control_fixture() -> FedoraWorkstationPreparation {
        let (_fixture, mut preparation, mut backend) = executor_fixture();
        execute_to_installer_ready(&mut backend, &mut preparation, |_| Ok(())).unwrap();
        preparation.execution.disk_only_topology = preparation.execution.resolved_topology.clone();
        preparation.status = FedoraWorkstationPreparationStatus::InstalledSystemProven;
        preparation
    }

    fn guest_inventory() -> ReadOnlyGuestInventory {
        ReadOnlyGuestInventory {
            fedora_product: "Fedora Workstation".to_owned(),
            fedora_release: "44".to_owned(),
            architecture: "x86_64".to_owned(),
            kernel: "6.0.0-test".to_owned(),
            hostname: "localhost".to_owned(),
            machine_id_present: true,
            normal_user_count: 0,
            normal_users: Vec::new(),
            root_locked: true,
            accounts_service_entries: Vec::new(),
            gnome_initial_setup_completed: false,
            network_profile_summaries: vec!["generic-autoconnect".to_owned()],
            preparation_mac_referenced: false,
            network_static_addresses: Vec::new(),
            dhcp_identity_residue: false,
            network_secrets_present: false,
            openssh_server_installed: false,
            openssh_server_enabled: false,
            ssh_host_keys_present: false,
            selinux_enabled: true,
            selinux_enforcing: true,
            relabel_pending: false,
            package_transactions_clean: true,
            enabled_fedora_repositories: vec!["fedora".to_owned(), "updates".to_owned()],
            relevant_packages: Vec::new(),
            spice_vdagent_installed: true,
            spice_vdagent_components: vec!["spice-vdagentd.socket".to_owned()],
            qemu_guest_agent_installed: false,
            display_stack: vec!["Wayland".to_owned()],
            dbus_machine_id_relationship: "/etc/machine-id".to_owned(),
            anaconda_residue: Vec::new(),
            crash_temp_history_residue: Vec::new(),
            preparation_identity_residue: Vec::new(),
        }
    }

    fn guest_result(request: &GuestControlRequest) -> GuestControlResult {
        GuestControlResult {
            protocol_version: request.protocol_version,
            binding: request.binding.clone(),
            operation: request.operation,
            operation_id: request.operation_id.clone(),
            nonce: request.nonce.clone(),
            completion: GuestControlCompletion::Completed,
            inventory: Some(guest_inventory()),
            error_code: None,
            guest_sequence: 1,
        }
    }

    fn broker_request(preparation: &FedoraWorkstationPreparation) -> PreparationBrokerRequest {
        PreparationBrokerRequest {
            protocol_version: FORGE_PREPARATION_BROKER_PROTOCOL_VERSION,
            operation: PreparationBrokerOperation::InspectFedoraWorkstationPreparation,
            preparation_id: preparation.preparation_id.clone(),
            expected_domain_name: preparation.installer.name.clone(),
            expected_domain_uuid: preparation.installer.uuid.clone(),
            bootstrap_target: None,
            operation_id: "broker-operation-0001".to_owned(),
            nonce: "broker-nonce-00000000000000000000".to_owned(),
        }
    }

    fn broker_result(
        preparation: &FedoraWorkstationPreparation,
        request: &PreparationBrokerRequest,
    ) -> PreparationBrokerResult {
        PreparationBrokerResult {
            protocol_version: request.protocol_version,
            operation: request.operation,
            operation_id: request.operation_id.clone(),
            nonce: request.nonce.clone(),
            preparation_id: preparation.preparation_id.clone(),
            domain_uuid: preparation.installer.uuid.clone(),
            staging_volume_name: preparation.staging.volume_name.clone(),
            staging_volume_key: preparation.execution.staging_volume_key.clone().unwrap(),
            staging_path: preparation.staging.path.clone(),
            broker_version: "forge-preparation-broker/1".to_owned(),
            broker_sha256: "a".repeat(64),
            libguestfs_version: "guestfish 1.60.1".to_owned(),
            backend: "direct".to_owned(),
            os_root: "/dev/mapper/fedora-root".to_owned(),
            fedora_product: "Fedora Workstation".to_owned(),
            fedora_release: "44".to_owned(),
            architecture: "x86_64".to_owned(),
            filesystems: vec!["/dev/mapper/fedora-root: xfs".to_owned()],
            guest_selinux_config: "SELINUX=enforcing\nSELINUXTYPE=targeted".to_owned(),
            workstation_evidence: "VARIANT_ID=workstation".to_owned(),
            filesystem_layout: vec!["usr_dir=true".to_owned()],
            minimal_observations: vec!["machine_id_file=true".to_owned()],
            clean_close: true,
            host_metadata_unchanged: true,
            elapsed_millis: 100,
            completion: PreparationBrokerCompletion::Completed,
            error_code: None,
        }
    }

    #[test]
    fn privileged_discovery_is_exact_and_does_not_advance_preparation_state() {
        let preparation = guest_control_fixture();
        let request = broker_request(&preparation);
        let evidence = prove_privileged_offline_fedora_discovery(
            &preparation,
            &request,
            broker_result(&preparation, &request),
        )
        .unwrap();
        assert_eq!(evidence.fedora_release, "44");
        assert_eq!(
            preparation.status,
            FedoraWorkstationPreparationStatus::InstalledSystemProven
        );
    }

    #[test]
    fn unprivileged_broker_result_forgery_and_replay_refuse() {
        let preparation = guest_control_fixture();
        let request = broker_request(&preparation);
        let mut values = Vec::new();
        let mut value = broker_result(&preparation, &request);
        value.nonce = "wrong".to_owned();
        values.push(value);
        let mut value = broker_result(&preparation, &request);
        value.domain_uuid = "wrong".to_owned();
        values.push(value);
        let mut value = broker_result(&preparation, &request);
        value.completion = PreparationBrokerCompletion::Refused;
        values.push(value);
        let mut value = broker_result(&preparation, &request);
        value.broker_sha256 = "forged".to_owned();
        values.push(value);
        let mut value = broker_result(&preparation, &request);
        value.backend = "libvirt".to_owned();
        values.push(value);
        let mut value = broker_result(&preparation, &request);
        value.clean_close = false;
        values.push(value);
        let mut value = broker_result(&preparation, &request);
        value.host_metadata_unchanged = false;
        values.push(value);
        let mut value = broker_result(&preparation, &request);
        value.filesystem_layout.clear();
        values.push(value);
        for value in values {
            assert!(
                prove_privileged_offline_fedora_discovery(&preparation, &request, value).is_err()
            );
        }
        let mut replayed = preparation.clone();
        replayed.execution.privileged_offline_discovery = Some(
            prove_privileged_offline_fedora_discovery(
                &preparation,
                &request,
                broker_result(&preparation, &request),
            )
            .unwrap(),
        );
        assert!(
            prove_privileged_offline_fedora_discovery(
                &replayed,
                &request,
                broker_result(&replayed, &request)
            )
            .is_err()
        );
    }

    #[test]
    fn guest_control_is_typed_bound_read_only_and_does_not_advance_state() {
        let preparation = guest_control_fixture();
        let request = create_read_only_guest_inventory_request(
            &preparation,
            "operation-00000001",
            "nonce-00000000000000000000000000",
            true,
            true,
        )
        .unwrap();
        assert_eq!(
            request.operation,
            GuestControlOperation::ReadOnlyGuestInventoryProbe
        );
        let evidence = prove_read_only_guest_inventory(
            &preparation,
            &request,
            guest_result(&request),
            GuestOperationLedgerState::SentAwaitingResult,
        )
        .unwrap();
        assert_eq!(evidence.operation_id(), "operation-00000001");
        assert_eq!(evidence.binding().domain_uuid, preparation.installer.uuid);
        assert!(evidence.inventory().selinux_enforcing);
        assert_eq!(
            preparation.status,
            FedoraWorkstationPreparationStatus::InstalledSystemProven
        );
        assert!(!guest_channel_cleanup_inventory().reusable_secret_created);
    }

    #[test]
    fn guest_control_refuses_identity_state_replay_failure_and_forgery() {
        let preparation = guest_control_fixture();
        let request = create_read_only_guest_inventory_request(
            &preparation,
            "operation-00000001",
            "nonce-00000000000000000000000000",
            true,
            true,
        )
        .unwrap();
        for ledger in [
            GuestOperationLedgerState::Prepared,
            GuestOperationLedgerState::Completed,
            GuestOperationLedgerState::FailedAmbiguous,
        ] {
            assert!(
                prove_read_only_guest_inventory(
                    &preparation,
                    &request,
                    guest_result(&request),
                    ledger,
                )
                .is_err()
            );
        }
        let mut values = Vec::new();
        let mut value = guest_result(&request);
        value.binding.domain_uuid = "wrong".to_owned();
        values.push(value);
        let mut value = guest_result(&request);
        value.binding.staging_path = PathBuf::from("/wrong");
        values.push(value);
        let mut value = guest_result(&request);
        value.operation_id = "forged-operation".to_owned();
        values.push(value);
        let mut value = guest_result(&request);
        value.nonce = "forged-nonce".to_owned();
        values.push(value);
        let mut value = guest_result(&request);
        value.completion = GuestControlCompletion::Failed;
        value.inventory = None;
        value.error_code = Some("guest-failure".to_owned());
        values.push(value);
        let mut value = guest_result(&request);
        value.inventory.as_mut().unwrap().selinux_enforcing = false;
        values.push(value);
        for result in values {
            assert!(
                prove_read_only_guest_inventory(
                    &preparation,
                    &request,
                    result,
                    GuestOperationLedgerState::SentAwaitingResult,
                )
                .is_err()
            );
        }
        let mut stale = preparation.clone();
        stale.status = FedoraWorkstationPreparationStatus::NormalizationPlanned;
        assert!(
            create_read_only_guest_inventory_request(
                &stale,
                "operation-00000002",
                "nonce-00000000000000000000000001",
                true,
                true,
            )
            .is_err()
        );
        let mut wrong = preparation.clone();
        wrong.preparation_id = FedoraWorkstationPreparationId::new("deadbeef").unwrap();
        assert!(
            prove_read_only_guest_inventory(
                &wrong,
                &request,
                guest_result(&request),
                GuestOperationLedgerState::SentAwaitingResult,
            )
            .is_err()
        );
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

    #[derive(Default)]
    struct ExecutorBackend {
        pool_path: PathBuf,
        volume: Option<PreparationVolumeEvidence>,
        domain: Option<InstallerDomainEvidence>,
        canonical: bool,
        create_calls: usize,
        define_calls: usize,
        start_calls: usize,
        define_failure: bool,
        drift_domain: bool,
    }

    impl FedoraWorkstationPreparationBackend for ExecutorBackend {
        fn inspect_pool(&mut self, name: &str) -> Result<PreparationPoolEvidence, String> {
            Ok(PreparationPoolEvidence {
                name: name.to_owned(),
                active: true,
                target_path: self.pool_path.clone(),
            })
        }

        fn inspect_volume(
            &mut self,
            _: &str,
            name: &str,
        ) -> Result<Option<PreparationVolumeEvidence>, String> {
            if self
                .volume
                .as_ref()
                .is_some_and(|volume| volume.name == name)
            {
                return Ok(self.volume.clone());
            }
            if !name.starts_with("forge-install-") {
                return Ok(None);
            }
            Ok(Some(PreparationVolumeEvidence {
                name: name.to_owned(),
                key: format!("{}/{}", self.pool_path.display(), name),
                path: self.pool_path.join(name),
                format: "raw".to_owned(),
                capacity_bytes: 1024,
                allocation_bytes: 1024,
                backing_path: None,
            }))
        }

        fn create_staging_volume(
            &mut self,
            _: &str,
            name: &str,
            capacity_bytes: u64,
        ) -> Result<(), String> {
            self.create_calls += 1;
            self.volume = Some(PreparationVolumeEvidence {
                name: name.to_owned(),
                key: format!("{}/{}", self.pool_path.display(), name),
                path: self.pool_path.join(name),
                format: "qcow2".to_owned(),
                capacity_bytes,
                allocation_bytes: 196_608,
                backing_path: None,
            });
            Ok(())
        }

        fn inspect_installer_domain(
            &mut self,
            _: &str,
        ) -> Result<Option<InstallerDomainEvidence>, String> {
            let mut value = self.domain.clone();
            if self.drift_domain
                && let Some(domain) = value.as_mut()
            {
                domain.xml = domain.xml.replace("network='default'", "network='evil'");
            }
            Ok(value)
        }

        fn define_installer_domain(&mut self, xml: &str) -> Result<(), String> {
            self.define_calls += 1;
            if self.define_failure {
                return Err("define failed".to_owned());
            }
            let name = tag_value(xml, "name");
            let uuid = tag_value(xml, "uuid");
            let disks = xml_blocks(xml, "disk");
            let staging = xml_attribute(disks[0], "source", "file").unwrap();
            let persistent_xml = if let Some(cdrom) = disks.get(1) {
                let iso = xml_attribute(cdrom, "source", "file").unwrap();
                normalized_fixture(&name, &uuid, &staging, &iso)
            } else {
                normalized_fixture(&name, &uuid, &staging, "unused")
                    .replace("    <boot dev='cdrom'/>\n", "")
                    .replace(
                        "    <disk type='file' device='cdrom'>\n      <driver name='qemu' type='raw'/>\n      <source file='unused'/>\n      <target dev='sda' bus='sata'/>\n      <readonly/>\n      <address type='drive' controller='0' bus='0' target='0' unit='0'/>\n    </disk>\n",
                        "",
                    )
            };
            self.domain = Some(InstallerDomainEvidence {
                name,
                uuid,
                persistent: true,
                shutoff: true,
                running: false,
                autostart: false,
                xml: persistent_xml,
                q35_alias_canonical: Some("pc-q35-10.2".to_owned()),
            });
            Ok(())
        }

        fn start_installer_domain(&mut self, _: &str) -> Result<(), String> {
            self.start_calls += 1;
            if let Some(domain) = self.domain.as_mut() {
                domain.shutoff = false;
                domain.running = true;
                Ok(())
            } else {
                Err("domain absent".to_owned())
            }
        }

        fn canonical_base_exists(&mut self, _: &str, _: &str) -> Result<bool, String> {
            Ok(self.canonical)
        }

        fn materialize_installer_iso(
            &mut self,
            _: &str,
            name: &str,
            _: &std::path::Path,
            source_bytes: u64,
        ) -> Result<PreparationVolumeEvidence, String> {
            Ok(PreparationVolumeEvidence {
                name: name.to_owned(),
                key: format!("{}/{}", self.pool_path.display(), name),
                path: self.pool_path.join(name),
                format: "raw".to_owned(),
                capacity_bytes: source_bytes,
                allocation_bytes: source_bytes,
                backing_path: None,
            })
        }

        fn stream_installer_iso_digest(
            &mut self,
            _: &str,
            name: &str,
            expected_bytes: u64,
        ) -> Result<(PreparationVolumeEvidence, u64, String), String> {
            Ok((
                PreparationVolumeEvidence {
                    name: name.to_owned(),
                    key: format!("{}/{}", self.pool_path.display(), name),
                    path: self.pool_path.join(name),
                    format: "raw".to_owned(),
                    capacity_bytes: expected_bytes,
                    allocation_bytes: expected_bytes,
                    backing_path: None,
                },
                expected_bytes,
                "digest".to_owned(),
            ))
        }
    }

    fn tag_value(xml: &str, tag: &str) -> String {
        let start = format!("<{tag}>");
        let end = format!("</{tag}>");
        let offset = xml.find(&start).unwrap() + start.len();
        xml[offset..xml[offset..].find(&end).unwrap() + offset].to_owned()
    }

    fn normalized_fixture(name: &str, uuid: &str, staging: &str, iso: &str) -> String {
        include_str!("../tests/fixtures/fedora-workstation-installer-libvirt.xml")
            .replace("@NAME@", name)
            .replace("@UUID@", uuid)
            .replace("@STAGING@", staging)
            .replace("@ISO@", iso)
    }

    fn executor_fixture() -> (Fixture, FedoraWorkstationPreparation, ExecutorBackend) {
        let fixture = Fixture::new();
        let pool = fixture.root.join("downloads");
        fs::create_dir_all(&pool).unwrap();
        let preparation = durable_preparation(fixture.plan());
        let backend = ExecutorBackend {
            pool_path: pool,
            ..Default::default()
        };
        (fixture, preparation, backend)
    }

    #[test]
    fn executor_creates_one_preparation_owned_staging_and_exact_installer() {
        let (_fixture, mut preparation, mut backend) = executor_fixture();
        let mut publications = Vec::new();
        let disposition = execute_to_installer_ready(&mut backend, &mut preparation, |value| {
            publications.push(value.clone());
            Ok(())
        })
        .unwrap();
        assert_eq!(disposition, InstallerReadyDisposition::Created);
        assert_eq!(backend.create_calls, 1);
        assert_eq!(backend.define_calls, 1);
        assert_eq!(
            preparation.status,
            FedoraWorkstationPreparationStatus::InstallerReady
        );
        assert_eq!(publications.len(), 2);
        let volume = backend.volume.unwrap();
        assert_eq!(volume.capacity_bytes, 80 * 1024 * 1024 * 1024);
        assert_eq!(volume.format, "qcow2");
        assert!(volume.backing_path.is_none());
    }

    #[test]
    fn manual_install_confirmation_is_explicit_idempotent_and_never_fakes_start() {
        let (_fixture, mut preparation, mut backend) = executor_fixture();
        execute_to_installer_ready(&mut backend, &mut preparation, |_| Ok(())).unwrap();
        let mut published = Vec::new();
        assert_eq!(
            confirm_manually_installed_from_installer_ready(
                &mut backend,
                &mut preparation,
                true,
                |value| {
                    published.push(value.status);
                    Ok(())
                },
            )
            .unwrap(),
            ManualInstallationConfirmationDisposition::Confirmed
        );
        assert_eq!(
            preparation.status,
            FedoraWorkstationPreparationStatus::InstallationConfirmed
        );
        assert!(preparation.operator_confirmation_recorded);
        assert_eq!(
            published,
            [FedoraWorkstationPreparationStatus::InstallationConfirmed]
        );
        assert!(!preparation.execution.installed_disk_start_recorded);
        assert_eq!(
            confirm_manually_installed_from_installer_ready(
                &mut backend,
                &mut preparation,
                true,
                |_| panic!("replay must not publish"),
            )
            .unwrap(),
            ManualInstallationConfirmationDisposition::AlreadyConfirmed
        );
    }

    #[test]
    fn manual_install_confirmation_requires_explicit_attestation_and_shutoff_identity() {
        let (_fixture, mut preparation, mut backend) = executor_fixture();
        execute_to_installer_ready(&mut backend, &mut preparation, |_| Ok(())).unwrap();
        assert_eq!(
            confirm_manually_installed_from_installer_ready(
                &mut backend,
                &mut preparation,
                false,
                |_| panic!("unconfirmed operation must not publish"),
            ),
            Err(PreparationError::InvalidStateTransition)
        );
        backend.domain.as_mut().unwrap().shutoff = false;
        backend.domain.as_mut().unwrap().running = true;
        assert_eq!(
            confirm_manually_installed_from_installer_ready(
                &mut backend,
                &mut preparation,
                true,
                |_| panic!("running domain must not publish"),
            ),
            Err(PreparationError::InstallationProofFailed)
        );
    }

    #[test]
    fn installer_xml_has_desktop_topology_and_no_legacy_provisioning() {
        let (_fixture, preparation, _backend) = executor_fixture();
        let xml = render_fedora_workstation_installer_xml(&preparation);
        assert!(xml.contains("machine='q35'"));
        assert!(xml.contains("firmware='efi'"));
        assert!(xml.contains("device='cdrom'"));
        assert!(xml.contains("type='spice'"));
        assert!(xml.contains("type='tablet'"));
        assert!(!xml.contains("fedora-lab"));
        for forbidden in [
            "seed",
            "NoCloud",
            "cloud-init",
            "user-data",
            "default_user",
            "org.qemu.guest_agent.0",
            "<hostdev",
            "<filesystem",
            "ssh",
        ] {
            assert!(!xml.contains(forbidden), "unexpected {forbidden}");
        }
    }

    fn real_xml_evidence(preparation: &FedoraWorkstationPreparation) -> InstallerDomainEvidence {
        InstallerDomainEvidence {
            name: preparation.installer.name.clone(),
            uuid: preparation.installer.uuid.clone(),
            persistent: true,
            shutoff: true,
            running: false,
            autostart: false,
            xml: normalized_fixture(
                &preparation.installer.name,
                &preparation.installer.uuid,
                &preparation.installer.disk_path.to_string_lossy(),
                &preparation.installer.iso_path.to_string_lossy(),
            ),
            q35_alias_canonical: Some("pc-q35-10.2".to_owned()),
        }
    }

    #[test]
    fn real_libvirt_fixture_proves_q35_alias_and_every_classified_device() {
        let (_fixture, preparation, _backend) = executor_fixture();
        let resolved = prove_fedora_workstation_post_install_staging_topology(
            &preparation,
            &real_xml_evidence(&preparation),
        )
        .unwrap();
        assert_eq!(resolved.requested_machine_family, "Q35");
        assert_eq!(resolved.resolved_machine_type, "pc-q35-10.2");
        assert_eq!(resolved.q35_alias_canonical, "pc-q35-10.2");
        assert!(resolved.devices.iter().any(|device| {
            device.kind == "controller"
                && device.classification
                    == InstallerDeviceClassification::AllowedLibvirtNormalization
        }));
        assert!(resolved.devices.iter().all(|device| {
            matches!(
                device.classification,
                InstallerDeviceClassification::Required
                    | InstallerDeviceClassification::AllowedLibvirtNormalization
                    | InstallerDeviceClassification::OptionalExplicitPolicy
            )
        }));
    }

    #[test]
    fn non_q35_or_unproven_machine_refuses() {
        let (_fixture, preparation, _backend) = executor_fixture();
        let mut wrong = real_xml_evidence(&preparation);
        wrong.xml = wrong.xml.replace("pc-q35-10.2", "pc-i440fx-10.2");
        assert!(prove_fedora_workstation_installer_topology(&preparation, &wrong).is_err());
        let mut unproven = real_xml_evidence(&preparation);
        unproven.q35_alias_canonical = None;
        assert!(prove_fedora_workstation_installer_topology(&preparation, &unproven).is_err());
    }

    #[test]
    fn every_required_device_removal_refuses() {
        let (_fixture, preparation, _backend) = executor_fixture();
        for fragment in [
            "<graphics type='spice' autoport='yes'><listen type='address'/></graphics>",
            "<video><model type='virtio' heads='1' primary='yes'/><address type='pci'/></video>",
            "<input type='tablet' bus='usb'><address type='usb'/></input>",
            "<sound model='ich9'><address type='pci'/></sound>",
        ] {
            let mut evidence = real_xml_evidence(&preparation);
            evidence.xml = evidence.xml.replace(fragment, "");
            assert!(
                prove_fedora_workstation_installer_topology(&preparation, &evidence).is_err(),
                "removal unexpectedly accepted: {fragment}"
            );
        }
    }

    #[test]
    fn extra_writable_disk_second_cdrom_and_seed_media_refuse() {
        let (_fixture, preparation, _backend) = executor_fixture();
        for extra in [
            "<disk type='file' device='disk'><driver name='qemu' type='qcow2'/><source file='/evil.qcow2'/><target dev='vdb' bus='virtio'/></disk>",
            "<disk type='file' device='cdrom'><driver name='qemu' type='raw'/><source file='/other.iso'/><target dev='sdb' bus='sata'/><readonly/></disk>",
            "<disk type='file' device='cdrom'><driver name='qemu' type='raw'/><source file='/tmp/cidata-seed.iso'/><target dev='sdb' bus='sata'/><readonly/></disk>",
        ] {
            let mut evidence = real_xml_evidence(&preparation);
            evidence.xml = evidence
                .xml
                .replace("</devices>", &format!("{extra}</devices>"));
            assert!(prove_fedora_workstation_installer_topology(&preparation, &evidence).is_err());
        }
    }

    #[test]
    fn exact_iso_and_staging_path_drift_refuse() {
        let (_fixture, preparation, _backend) = executor_fixture();
        for (old, new) in [
            (
                preparation.installer.iso_path.to_string_lossy().to_string(),
                "/tmp/wrong.iso".to_owned(),
            ),
            (
                preparation
                    .installer
                    .disk_path
                    .to_string_lossy()
                    .to_string(),
                "/tmp/wrong.qcow2".to_owned(),
            ),
        ] {
            let mut evidence = real_xml_evidence(&preparation);
            evidence.xml = evidence.xml.replace(&old, &new);
            assert!(prove_fedora_workstation_installer_topology(&preparation, &evidence).is_err());
        }
    }

    #[test]
    fn nic_network_and_mac_drift_refuse() {
        let (_fixture, preparation, _backend) = executor_fixture();
        for (old, new) in [
            ("network='default'", "network='evil'"),
            ("model type='virtio'", "model type='e1000'"),
            ("52:54:00:e3:80:9e", "00:11:22:33:44:55"),
        ] {
            let mut evidence = real_xml_evidence(&preparation);
            evidence.xml = evidence.xml.replacen(old, new, 1);
            assert!(prove_fedora_workstation_installer_topology(&preparation, &evidence).is_err());
        }
    }

    #[test]
    fn hostdev_filesystem_channel_tpm_and_unknown_device_refuse() {
        let (_fixture, preparation, _backend) = executor_fixture();
        for extra in [
            "<hostdev mode='subsystem'/>",
            "<filesystem type='mount'><source dir='/host'/><target dir='host'/></filesystem>",
            "<channel type='unix'><target type='virtio' name='org.qemu.guest_agent.0'/></channel>",
            "<tpm model='tpm-crb'><backend type='emulator'/></tpm>",
            "<mystery source='/host/device'/>",
        ] {
            let mut evidence = real_xml_evidence(&preparation);
            evidence.xml = evidence
                .xml
                .replace("</devices>", &format!("{extra}</devices>"));
            assert!(prove_fedora_workstation_installer_topology(&preparation, &evidence).is_err());
        }
    }

    #[test]
    fn autostart_and_libvirt_controller_property_drift_refuse() {
        let (_fixture, preparation, _backend) = executor_fixture();
        let mut autostart = real_xml_evidence(&preparation);
        autostart.autostart = true;
        assert!(prove_fedora_workstation_installer_topology(&preparation, &autostart).is_err());
        let mut controller = real_xml_evidence(&preparation);
        controller.xml = controller
            .xml
            .replace("model='qemu-xhci'", "model='usb-ehci'");
        assert!(prove_fedora_workstation_installer_topology(&preparation, &controller).is_err());
    }

    #[test]
    fn resolved_mac_and_xml_drift_refuse_after_installer_ready() {
        let (_fixture, mut preparation, mut backend) = executor_fixture();
        execute_to_installer_ready(&mut backend, &mut preparation, |_| Ok(())).unwrap();
        backend.domain.as_mut().unwrap().xml = backend
            .domain
            .as_ref()
            .unwrap()
            .xml
            .replace("52:54:00:e3:80:9e", "52:54:00:00:00:01");
        assert!(execute_to_installer_ready(&mut backend, &mut preparation, |_| Ok(())).is_err());
    }

    #[test]
    fn second_prepare_at_installer_ready_is_read_only_and_deterministic() {
        let (_fixture, mut preparation, mut backend) = executor_fixture();
        execute_to_installer_ready(&mut backend, &mut preparation, |_| Ok(())).unwrap();
        let calls = (backend.create_calls, backend.define_calls);
        assert_eq!(
            execute_to_installer_ready(&mut backend, &mut preparation, |_| Ok(())).unwrap(),
            InstallerReadyDisposition::Resumed
        );
        assert_eq!(calls, (backend.create_calls, backend.define_calls));
    }

    #[test]
    fn planned_partial_transaction_reuses_exact_staging_and_domain_without_creation() {
        let (_fixture, mut preparation, mut backend) = executor_fixture();
        backend
            .create_staging_volume(
                "default",
                &preparation.staging.volume_name,
                preparation.staging.capacity_bytes,
            )
            .unwrap();
        preparation.execution.staging_volume_key =
            Some(backend.volume.as_ref().unwrap().key.clone());
        backend
            .define_installer_domain(&render_fedora_workstation_installer_xml(&preparation))
            .unwrap();
        let calls = (backend.create_calls, backend.define_calls);
        assert_eq!(
            execute_to_installer_ready(&mut backend, &mut preparation, |_| Ok(())).unwrap(),
            InstallerReadyDisposition::Resumed
        );
        assert_eq!(calls, (backend.create_calls, backend.define_calls));
        assert_eq!(
            preparation.status,
            FedoraWorkstationPreparationStatus::InstallerReady
        );
        assert!(preparation.execution.resolved_topology.is_some());
    }

    #[test]
    fn installer_start_requires_ready_running_and_never_claims_installation() {
        let (_fixture, mut preparation, _backend) = executor_fixture();
        assert_eq!(
            record_installer_started(&mut preparation, false),
            Err(PreparationError::InvalidStateTransition)
        );
        assert_eq!(
            record_installer_started(&mut preparation, true),
            Err(PreparationError::InvalidStateTransition)
        );
        preparation.status = FedoraWorkstationPreparationStatus::InstallerReady;
        assert_eq!(
            record_installer_started(&mut preparation, true),
            Ok(InstallerStartDisposition::Started)
        );
        assert_eq!(
            preparation.status,
            FedoraWorkstationPreparationStatus::InstallerRunning
        );
    }

    #[test]
    fn installation_completion_requires_explicit_confirmation_and_shutoff() {
        let (_fixture, mut preparation, _backend) = executor_fixture();
        preparation.status = FedoraWorkstationPreparationStatus::InstallerRunning;
        assert_eq!(
            require_installation_confirmation(&preparation, false, true),
            Err(PreparationError::ExplicitContinuationRequired)
        );
        assert_eq!(
            require_installation_confirmation(&preparation, true, false),
            Err(PreparationError::ExplicitContinuationRequired)
        );
        assert!(require_installation_confirmation(&preparation, true, true).is_ok());
        assert_eq!(
            preparation.status,
            FedoraWorkstationPreparationStatus::InstallerRunning
        );
        record_anaconda_installation_completed(&mut preparation, true, true).unwrap();
        assert_eq!(
            preparation.status,
            FedoraWorkstationPreparationStatus::InstallationConfirmed
        );
        assert!(preparation.operator_confirmation_recorded);
    }

    #[test]
    fn post_install_continuation_detaches_iso_starts_once_and_stops_before_graphical_proof() {
        let (_fixture, mut preparation, mut backend) = executor_fixture();
        execute_to_installer_ready(&mut backend, &mut preparation, |_| Ok(())).unwrap();
        preparation.status = FedoraWorkstationPreparationStatus::InstallerRunning;
        let runtime_name = "forge-install-test.iso";
        preparation.execution.runtime_iso = Some(LibvirtManagedInstallerIso {
            preparation_id: preparation.preparation_id.clone(),
            volume_name: runtime_name.to_owned(),
            path: backend.pool_path.join(runtime_name),
            source_filename: preparation.source.filename.clone(),
            source_sha256: preparation.source.iso_sha256.clone(),
            source_bytes: preparation.source.iso_bytes,
            destination_bytes: 1024,
            destination_sha256: preparation.source.iso_sha256.clone(),
            volume_key: format!("{}/{}", backend.pool_path.display(), runtime_name),
            role: FedoraWorkstationArtifactRole::LibvirtManagedInstallerIso,
        });
        let original_uuid = preparation.installer.uuid.clone();
        let original_mac = preparation
            .execution
            .resolved_topology
            .as_ref()
            .unwrap()
            .nic_mac
            .clone();
        assert!(
            render_fedora_workstation_disk_only_xml(&preparation)
                .unwrap()
                .contains(&format!("<mac address='{original_mac}'/>"))
        );
        preparation.status = FedoraWorkstationPreparationStatus::InstallationConfirmed;
        preparation.operator_confirmation_recorded = true;
        backend
            .define_installer_domain(
                &render_fedora_workstation_disk_only_xml(&preparation).unwrap(),
            )
            .unwrap();
        backend.domain.as_mut().unwrap().xml = backend
            .domain
            .as_ref()
            .unwrap()
            .xml
            .replace(&original_mac, "52:54:00:66:51:4d");
        let mut published = Vec::new();
        assert_eq!(
            execute_to_installed_disk_running(&mut backend, &mut preparation, true, |value| {
                published.push(value.status);
                Ok(())
            })
            .unwrap(),
            InstalledDiskBootDisposition::Started
        );
        assert_eq!(backend.start_calls, 1);
        assert_eq!(preparation.installer.uuid, original_uuid);
        assert_eq!(
            preparation
                .execution
                .disk_only_topology
                .as_ref()
                .unwrap()
                .nic_mac,
            original_mac
        );
        assert!(
            !backend
                .domain
                .as_ref()
                .unwrap()
                .xml
                .contains("device='cdrom'")
        );
        assert!(
            backend
                .inspect_volume("default", runtime_name)
                .unwrap()
                .is_some()
        );
        assert_eq!(
            preparation.status,
            FedoraWorkstationPreparationStatus::AwaitingGraphicalBootConfirmation
        );
        assert_ne!(
            preparation.status,
            FedoraWorkstationPreparationStatus::InstalledSystemProven
        );
        assert!(published.contains(&FedoraWorkstationPreparationStatus::InstalledDiskBootPending));
        assert!(published.contains(&FedoraWorkstationPreparationStatus::InstalledDiskBooting));

        assert_eq!(
            execute_to_installed_disk_running(&mut backend, &mut preparation, true, |_| Ok(()))
                .unwrap(),
            InstalledDiskBootDisposition::AlreadyRunning
        );
        assert_eq!(backend.start_calls, 1);
    }

    #[test]
    fn manually_confirmed_installer_attached_topology_transitions_to_disk_only_without_starting() {
        let (_fixture, mut preparation, mut backend) = executor_fixture();
        execute_to_installer_ready(&mut backend, &mut preparation, |_| Ok(())).unwrap();
        preparation.status = FedoraWorkstationPreparationStatus::InstallationConfirmed;
        preparation.operator_confirmation_recorded = true;

        let original_uuid = preparation.installer.uuid.clone();
        let original_staging = preparation.staging.path.clone();
        assert!(preparation.execution.runtime_iso.is_none());
        assert!(
            backend
                .domain
                .as_ref()
                .unwrap()
                .xml
                .contains("<boot dev='cdrom'/>")
        );

        assert_eq!(
            execute_to_installed_disk_running(&mut backend, &mut preparation, true, |_| Ok(()))
                .unwrap(),
            InstalledDiskBootDisposition::DiskOnlyPrepared
        );
        assert_eq!(backend.start_calls, 0);
        assert_eq!(
            preparation.status,
            FedoraWorkstationPreparationStatus::InstalledDiskBootPending
        );
        assert_eq!(preparation.installer.uuid, original_uuid);
        assert_eq!(preparation.staging.path, original_staging);
        let xml = &backend.domain.as_ref().unwrap().xml;
        assert!(xml.contains("<boot dev='hd'/>"));
        assert!(!xml.contains("<boot dev='cdrom'/>"));
        assert!(!xml.contains("device='cdrom'"));
        assert!(xml.contains(&preparation.staging.path.to_string_lossy().to_string()));
        assert!(preparation.execution.disk_only_topology.is_some());
    }

    #[test]
    fn manually_confirmed_wrong_installer_iso_fails_before_redefine() {
        let (_fixture, mut preparation, mut backend) = executor_fixture();
        execute_to_installer_ready(&mut backend, &mut preparation, |_| Ok(())).unwrap();
        preparation.status = FedoraWorkstationPreparationStatus::InstallationConfirmed;
        preparation.operator_confirmation_recorded = true;
        backend.domain.as_mut().unwrap().xml = backend
            .domain
            .as_ref()
            .unwrap()
            .xml
            .replace(&preparation.source.filename, "wrong.iso");
        let before = backend.domain.as_ref().unwrap().xml.clone();
        let result =
            execute_to_installed_disk_running(&mut backend, &mut preparation, true, |_| Ok(()));
        assert!(result.is_err());
        assert_eq!(backend.domain.as_ref().unwrap().xml, before);
        assert_eq!(
            preparation.status,
            FedoraWorkstationPreparationStatus::InstallationConfirmed
        );
        assert!(preparation.execution.disk_only_topology.is_none());
    }

    #[test]
    fn disk_only_render_requires_authoritative_mac_and_proof_rejects_replacement() {
        let (_fixture, mut preparation, mut backend) = executor_fixture();
        assert!(render_fedora_workstation_disk_only_xml(&preparation).is_err());
        execute_to_installer_ready(&mut backend, &mut preparation, |_| Ok(())).unwrap();
        let authoritative = preparation
            .execution
            .resolved_topology
            .as_ref()
            .unwrap()
            .nic_mac
            .clone();
        preparation.status = FedoraWorkstationPreparationStatus::InstallationConfirmed;
        let xml = render_fedora_workstation_disk_only_xml(&preparation).unwrap();
        assert!(xml.contains(&format!("<mac address='{authoritative}'/>")));
        assert_eq!(xml.matches("<interface type='network'>").count(), 1);
        assert!(!xml.contains("device='cdrom'"));
        let mut evidence = real_xml_evidence(&preparation);
        evidence.xml = normalized_fixture(
            &preparation.installer.name,
            &preparation.installer.uuid,
            &preparation.staging.path.to_string_lossy(),
            "unused",
        )
        .replace("    <boot dev='cdrom'/>\n", "")
        .replace(
            "    <disk type='file' device='cdrom'>\n      <driver name='qemu' type='raw'/>\n      <source file='unused'/>\n      <target dev='sda' bus='sata'/>\n      <readonly/>\n      <address type='drive' controller='0' bus='0' target='0' unit='0'/>\n    </disk>\n",
            "",
        )
        .replace(&authoritative, "52:54:00:66:51:4d");
        assert!(prove_fedora_workstation_disk_only_topology(&preparation, &evidence).is_err());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn graphical_proof_requires_machine_and_operator_and_is_evidence_only() {
        let (_fixture, mut preparation, mut backend) = executor_fixture();
        execute_to_installer_ready(&mut backend, &mut preparation, |_| Ok(())).unwrap();
        preparation.status = FedoraWorkstationPreparationStatus::InstallationConfirmed;
        preparation.operator_confirmation_recorded = true;
        let runtime_name = "forge-install-test.iso";
        preparation.execution.runtime_iso = Some(LibvirtManagedInstallerIso {
            preparation_id: preparation.preparation_id.clone(),
            volume_name: runtime_name.to_owned(),
            path: backend.pool_path.join(runtime_name),
            source_filename: preparation.source.filename.clone(),
            source_sha256: preparation.source.iso_sha256.clone(),
            source_bytes: preparation.source.iso_bytes,
            destination_bytes: 1024,
            destination_sha256: preparation.source.iso_sha256.clone(),
            volume_key: format!("{}/{}", backend.pool_path.display(), runtime_name),
            role: FedoraWorkstationArtifactRole::LibvirtManagedInstallerIso,
        });
        backend
            .define_installer_domain(
                &render_fedora_workstation_disk_only_xml(&preparation).unwrap(),
            )
            .unwrap();
        let resolved = prove_fedora_workstation_disk_only_topology(
            &preparation,
            backend.domain.as_ref().unwrap(),
        )
        .unwrap();
        preparation.execution.disk_only_topology = Some(resolved);
        preparation.status = FedoraWorkstationPreparationStatus::InstalledDiskBootPending;
        execute_to_installed_disk_running(&mut backend, &mut preparation, true, |_| Ok(()))
            .unwrap();
        let running = backend.domain.clone().unwrap();
        assert!(
            record_graphical_installed_system_confirmation(
                &mut preparation.clone(),
                &running,
                false,
                true,
            )
            .is_err()
        );
        let mut not_running = running.clone();
        not_running.running = false;
        not_running.shutoff = true;
        assert!(
            record_graphical_installed_system_confirmation(
                &mut preparation.clone(),
                &not_running,
                true,
                true,
            )
            .is_err()
        );
        for mut drifted in [
            running.clone(),
            running.clone(),
            running.clone(),
            running.clone(),
        ] {
            if drifted.uuid == running.uuid {
                drifted.uuid = "wrong-uuid".to_owned();
            }
            assert!(
                record_graphical_installed_system_confirmation(
                    &mut preparation.clone(),
                    &drifted,
                    true,
                    true,
                )
                .is_err()
            );
        }
        for (old, new) in [
            (
                preparation.staging.path.to_string_lossy().to_string(),
                "/wrong.qcow2".to_owned(),
            ),
            (
                "52:54:00:e3:80:9e".to_owned(),
                "52:54:00:66:51:4d".to_owned(),
            ),
            (
                "</devices>".to_owned(),
                "<disk device='cdrom'/></devices>".to_owned(),
            ),
            ("network='default'".to_owned(), "network='wrong'".to_owned()),
        ] {
            let mut drifted = running.clone();
            drifted.xml = drifted.xml.replace(&old, &new);
            assert!(
                record_graphical_installed_system_confirmation(
                    &mut preparation.clone(),
                    &drifted,
                    true,
                    true,
                )
                .is_err()
            );
        }
        let mutation_counts = (
            backend.create_calls,
            backend.define_calls,
            backend.start_calls,
        );
        assert_eq!(
            record_graphical_installed_system_confirmation(&mut preparation, &running, true, true,)
                .unwrap(),
            GraphicalConfirmationDisposition::Published
        );
        assert_eq!(
            preparation.status,
            FedoraWorkstationPreparationStatus::InstalledSystemProven
        );
        assert_ne!(
            preparation.status,
            FedoraWorkstationPreparationStatus::Normalized
        );
        let evidence = preparation
            .execution
            .graphical_boot_confirmation
            .as_ref()
            .unwrap();
        assert!(evidence.graphical_confirmation_recorded);
        assert!(evidence.observed_running);
        assert!(!evidence.gnome_initial_setup_completed);
        assert!(evidence.display_dynamic_resizing_needs_review);
        assert_eq!(
            mutation_counts,
            (
                backend.create_calls,
                backend.define_calls,
                backend.start_calls
            )
        );
        assert_eq!(
            record_graphical_installed_system_confirmation(&mut preparation, &running, true, true)
                .unwrap(),
            GraphicalConfirmationDisposition::AlreadyPublished
        );
    }

    #[test]
    fn graphical_confirmation_accepts_manual_path_without_runtime_iso_evidence() {
        let (_fixture, mut preparation, mut backend) = executor_fixture();
        execute_to_installer_ready(&mut backend, &mut preparation, |_| Ok(())).unwrap();
        preparation.status = FedoraWorkstationPreparationStatus::InstallationConfirmed;
        preparation.operator_confirmation_recorded = true;
        execute_to_installed_disk_running(&mut backend, &mut preparation, true, |_| Ok(()))
            .unwrap();
        execute_to_installed_disk_running(&mut backend, &mut preparation, true, |_| Ok(()))
            .unwrap();
        let running = backend.domain.clone().unwrap();
        assert_eq!(
            preparation.status,
            FedoraWorkstationPreparationStatus::AwaitingGraphicalBootConfirmation
        );
        assert!(preparation.execution.runtime_iso.is_none());
        assert_eq!(
            record_graphical_installed_system_confirmation(&mut preparation, &running, true, false)
                .unwrap(),
            GraphicalConfirmationDisposition::Published
        );
        assert_eq!(
            preparation.status,
            FedoraWorkstationPreparationStatus::InstalledSystemProven
        );
    }

    #[test]
    fn topology_mode_is_selected_only_from_durable_state() {
        for status in [
            FedoraWorkstationPreparationStatus::InstallerReady,
            FedoraWorkstationPreparationStatus::InstallerRunning,
            FedoraWorkstationPreparationStatus::AwaitingInstallationConfirmation,
        ] {
            assert_eq!(
                fedora_workstation_topology_mode(status).unwrap(),
                FedoraWorkstationTopologyMode::InstallerAttached
            );
        }
        for status in [
            FedoraWorkstationPreparationStatus::InstallationConfirmed,
            FedoraWorkstationPreparationStatus::InstalledDiskBootPending,
            FedoraWorkstationPreparationStatus::InstalledDiskBooting,
            FedoraWorkstationPreparationStatus::AwaitingGraphicalBootConfirmation,
            FedoraWorkstationPreparationStatus::InstalledSystemProven,
        ] {
            assert_eq!(
                fedora_workstation_topology_mode(status).unwrap(),
                FedoraWorkstationTopologyMode::DiskOnly
            );
        }
        for status in [
            FedoraWorkstationPreparationStatus::Planned,
            FedoraWorkstationPreparationStatus::Installing,
            FedoraWorkstationPreparationStatus::InstalledPendingProof,
            FedoraWorkstationPreparationStatus::Cancelled,
            FedoraWorkstationPreparationStatus::RecoveryRequired,
        ] {
            assert!(fedora_workstation_topology_mode(status).is_err());
        }
    }

    #[test]
    fn state_topology_contradictions_refuse_within_selected_mode() {
        let (_fixture, mut preparation, mut backend) = executor_fixture();
        execute_to_installer_ready(&mut backend, &mut preparation, |_| Ok(())).unwrap();
        let attached = backend.domain.clone().unwrap();
        assert!(prove_fedora_workstation_installer_topology(&preparation, &attached).is_ok());
        let mut missing_iso = attached.clone();
        missing_iso.xml = missing_iso
            .xml
            .replace("    <boot dev='cdrom'/>\n", "")
            .replace(
                &format!("    <disk type='file' device='cdrom'>\n      <driver name='qemu' type='raw'/>\n      <source file='{}'/>\n      <target dev='sda' bus='sata'/>\n      <readonly/>\n      <address type='drive' controller='0' bus='0' target='0' unit='0'/>\n    </disk>\n", preparation.installer.iso_path.display()),
                "",
            );
        assert!(prove_fedora_workstation_installer_topology(&preparation, &missing_iso).is_err());
        preparation.status = FedoraWorkstationPreparationStatus::InstallationConfirmed;
        assert!(prove_fedora_workstation_installer_topology(&preparation, &attached).is_err());
    }

    #[test]
    fn disk_only_mac_recovery_classification_never_uses_installer_mode() {
        let (_fixture, mut preparation, mut backend) = executor_fixture();
        execute_to_installer_ready(&mut backend, &mut preparation, |_| Ok(())).unwrap();
        preparation.status = FedoraWorkstationPreparationStatus::InstallationConfirmed;
        backend
            .define_installer_domain(
                &render_fedora_workstation_disk_only_xml(&preparation).unwrap(),
            )
            .unwrap();
        let correct = backend.domain.clone().unwrap();
        assert!(prove_fedora_workstation_disk_only_topology(&preparation, &correct).is_ok());
        let authoritative = preparation
            .execution
            .resolved_topology
            .as_ref()
            .unwrap()
            .nic_mac
            .clone();
        let mut drifted = correct;
        drifted.xml = drifted.xml.replace(&authoritative, "52:54:00:66:51:4d");
        assert!(prove_fedora_workstation_disk_only_topology(&preparation, &drifted).is_err());
        assert_eq!(
            prove_fedora_workstation_disk_only_mac_recovery_candidate(&preparation, &drifted)
                .unwrap(),
            "52:54:00:66:51:4d"
        );
        assert!(
            prove_fedora_workstation_post_install_staging_topology(&preparation, &drifted).is_err()
        );
    }

    #[test]
    fn crash_resume_at_booting_never_retries_an_ambiguous_start() {
        let (_fixture, mut preparation, mut backend) = executor_fixture();
        execute_to_installer_ready(&mut backend, &mut preparation, |_| Ok(())).unwrap();
        preparation.status = FedoraWorkstationPreparationStatus::InstalledDiskBooting;
        preparation.execution.installed_disk_start_recorded = true;
        backend
            .define_installer_domain(
                &render_fedora_workstation_disk_only_xml(&preparation).unwrap(),
            )
            .unwrap();
        assert!(
            execute_to_installed_disk_running(&mut backend, &mut preparation, true, |_| Ok(()))
                .is_err()
        );
        assert_eq!(backend.start_calls, 0);
    }

    #[test]
    fn topology_drift_refuses_installer_ready() {
        let (_fixture, mut preparation, mut backend) = executor_fixture();
        backend.drift_domain = true;
        assert!(execute_to_installer_ready(&mut backend, &mut preparation, |_| Ok(())).is_err());
        assert_eq!(
            preparation.status,
            FedoraWorkstationPreparationStatus::Planned
        );
    }

    #[test]
    fn define_failure_preserves_proven_staging_recovery_evidence() {
        let (_fixture, mut preparation, mut backend) = executor_fixture();
        backend.define_failure = true;
        let mut published = Vec::new();
        assert!(
            execute_to_installer_ready(&mut backend, &mut preparation, |value| {
                published.push(value.clone());
                Ok(())
            })
            .is_err()
        );
        assert!(backend.volume.is_some());
        assert!(backend.domain.is_none());
        assert_eq!(published.len(), 1);
        assert!(published[0].execution.staging_volume_key.is_some());
    }

    #[test]
    fn staging_domain_and_canonical_collisions_fail_closed() {
        let (_fixture, mut preparation, mut backend) = executor_fixture();
        backend.canonical = true;
        assert_eq!(
            execute_to_installer_ready(&mut backend, &mut preparation, |_| Ok(())),
            Err(PreparationError::CanonicalBaseCollision)
        );
        let (_fixture, mut preparation, mut backend) = executor_fixture();
        backend
            .create_staging_volume(
                "default",
                &preparation.staging.volume_name,
                preparation.staging.capacity_bytes,
            )
            .unwrap();
        assert_eq!(
            execute_to_installer_ready(&mut backend, &mut preparation, |_| Ok(())),
            Err(PreparationError::StagingCollision)
        );
    }

    #[test]
    fn durable_executor_state_uses_create_new_and_atomic_resume_updates() {
        let (fixture, mut preparation, _backend) = executor_fixture();
        let path = fixture.root.join("state/preparation.json");
        publish_new_fedora_workstation_preparation(&path, &preparation).unwrap();
        assert_eq!(
            publish_new_fedora_workstation_preparation(&path, &preparation),
            Err(PreparationError::ActivePreparationCollision)
        );
        preparation.status = FedoraWorkstationPreparationStatus::InstallerReady;
        update_fedora_workstation_preparation(&path, &preparation).unwrap();
        assert_eq!(
            read_fedora_workstation_preparation(&path).unwrap().unwrap(),
            preparation
        );
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
