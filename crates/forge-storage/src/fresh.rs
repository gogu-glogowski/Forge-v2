//! Pure planning and transaction-state model for Fresh replacements.
//!
//! This module deliberately performs no host or libvirt I/O.  It carries the
//! observations needed by a later executor and makes the Active-generation
//! switch explicit and fail closed.

use forge_core::{
    FirstBootSuccessPolicy, GuestProfileKind, InstanceName, NetworkPolicy, PersistencePolicy,
    ProfileId, ProvisioningPolicy, VmProfile, VmState,
};
use forge_state::{
    GenerationIndex, GenerationManifest, ManagedReconciliationStatus, ManagedResource,
    ObservedGeneration, StateError, commit_fresh_switch,
};
use std::fmt;

use crate::SharedBaseDisposition;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreshUnsupportedReason {
    LegacyFedoraProductRetired,
    WhonixPairAwareRequired,
    ProfilePolicyUnsupported,
}

/// Product action identity; Fresh is intentionally distinct from Create,
/// Clone, Rebuild, and Cleanup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreshAction {
    ReplaceActive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreshCapability {
    Supported,
    Unsupported(FreshUnsupportedReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreshNetworkIdentityPolicy {
    PreserveInstanceIdentity,
    RegenerateGenerationIdentity,
    PairAwareRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreshGuestIdentityPolicy {
    ProfileFreshIdentity,
    Deferred,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreshActivationPolicy {
    OldActiveToRetained,
    NewPreparingToActive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreshRetentionPolicy {
    RetainOldUntilExplicitCleanup,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FreshPlanError {
    RunningInstance,
    NonPersistentInstance,
    InconsistentState,
    AmbiguousGeneration,
    RecoveryRequired,
    MissingProfileBinding,
    UnsupportedFreshProfile(FreshUnsupportedReason),
    StorageIdentityMismatch,
}

impl fmt::Display for FreshPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::RunningInstance => "instance is running; shut it off before Fresh",
            Self::NonPersistentInstance => "Fresh requires a persistent instance",
            Self::InconsistentState => "instance reconciliation is not Consistent",
            Self::AmbiguousGeneration => {
                "instance does not have exactly one unambiguous Active generation"
            }
            Self::RecoveryRequired => "instance has pending Preparing/recovery-required state",
            Self::MissingProfileBinding => "durable profile binding is missing",
            Self::UnsupportedFreshProfile(_) => "profile does not support Fresh",
            Self::StorageIdentityMismatch => {
                "active storage identity does not match durable ownership"
            }
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for FreshPlanError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreshPlanInput {
    pub instance: InstanceName,
    pub profile: Option<VmProfile>,
    pub index: GenerationIndex,
    pub active: Option<GenerationManifest>,
    pub observed: ObservedGeneration,
    pub domain_state: VmState,
    pub reconciliation: ManagedReconciliationStatus,
    pub shared_base_disposition: SharedBaseDisposition,
    pub old_seed: Option<ManagedResource>,
    pub old_network_identity: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreshPlan {
    pub action: FreshAction,
    pub stable_instance: InstanceName,
    pub profile_id: ProfileId,
    pub old_active_generation_id: String,
    pub old_domain_uuid: String,
    pub old_storage: Vec<ManagedResource>,
    pub old_seed: Option<ManagedResource>,
    pub old_network_identity: Option<String>,
    pub new_generation_id: String,
    /// The current state model uses one stable domain UUID per instance; the
    /// replacement generation therefore retains it while its storage identity
    /// remains generation-specific.
    pub new_domain_uuid: String,
    pub new_overlay: String,
    pub new_seed: Option<String>,
    pub trusted_base_disposition: SharedBaseDisposition,
    pub guest_identity: FreshGuestIdentityPolicy,
    pub network_identity: FreshNetworkIdentityPolicy,
    pub activation: FreshActivationPolicy,
    pub retention: FreshRetentionPolicy,
    pub confirmation_required: bool,
    pub mutation: bool,
}

#[must_use]
pub fn fresh_capability(profile: &VmProfile) -> FreshCapability {
    match profile.kind {
        GuestProfileKind::KaliLab
            if profile.persistence == PersistencePolicy::Persistent
                && profile.provisioning == ProvisioningPolicy::None
                && profile.first_boot_success == FirstBootSuccessPolicy::ManualGuest =>
        {
            FreshCapability::Supported
        }
        GuestProfileKind::WhonixGateway | GuestProfileKind::WhonixWorkstation => {
            FreshCapability::Unsupported(FreshUnsupportedReason::WhonixPairAwareRequired)
        }
        GuestProfileKind::FedoraLab
        | GuestProfileKind::LunaDevFedora
        | GuestProfileKind::LunaLabFedora => {
            FreshCapability::Unsupported(FreshUnsupportedReason::LegacyFedoraProductRetired)
        }
        _ => FreshCapability::Unsupported(FreshUnsupportedReason::ProfilePolicyUnsupported),
    }
}

/// Builds a zero-mutation Fresh plan from one exact managed observation.
///
/// # Errors
///
/// Returns a typed refusal for any unmet lifecycle, ownership, profile, or
/// generation precondition.
pub fn plan_fresh(
    input: FreshPlanInput,
    new_generation_id: String,
) -> Result<FreshPlan, FreshPlanError> {
    let profile = input
        .profile
        .as_ref()
        .ok_or(FreshPlanError::MissingProfileBinding)?;
    if profile.persistence != PersistencePolicy::Persistent {
        return Err(FreshPlanError::NonPersistentInstance);
    }
    match fresh_capability(profile) {
        FreshCapability::Supported => {}
        FreshCapability::Unsupported(reason) => {
            return Err(FreshPlanError::UnsupportedFreshProfile(reason));
        }
    }
    if input.domain_state != VmState::Shutoff {
        return Err(FreshPlanError::RunningInstance);
    }
    if input.reconciliation != ManagedReconciliationStatus::Consistent {
        return if input.reconciliation == ManagedReconciliationStatus::RecoveryRequired {
            Err(FreshPlanError::RecoveryRequired)
        } else {
            Err(FreshPlanError::InconsistentState)
        };
    }
    if !input.observed.domain_persistent || input.index.domain_name != input.instance.as_str() {
        return Err(FreshPlanError::StorageIdentityMismatch);
    }
    let active_count = input
        .index
        .generations
        .iter()
        .filter(|entry| entry.status == forge_state::GenerationStatus::Active)
        .count();
    if active_count != 1 {
        return Err(FreshPlanError::AmbiguousGeneration);
    }
    if input
        .index
        .generations
        .iter()
        .any(|entry| entry.status == forge_state::GenerationStatus::Preparing)
    {
        return Err(FreshPlanError::RecoveryRequired);
    }
    let active_id = &input.index.active_generation_id;
    let active = input
        .active
        .as_ref()
        .ok_or(FreshPlanError::AmbiguousGeneration)?;
    if active.generation_id != *active_id
        || active.domain_name != input.instance.as_str()
        || input.observed.resources.is_empty()
    {
        return Err(FreshPlanError::StorageIdentityMismatch);
    }
    let names = forge_state::plan_generation_resources(
        &input.instance,
        new_generation_id.clone(),
        matches!(profile.provisioning, ProvisioningPolicy::NoCloud { .. }),
    )
    .map_err(|_| FreshPlanError::AmbiguousGeneration)?;
    let network_identity = match profile.network_policy {
        NetworkPolicy::DefaultNat | NetworkPolicy::Isolated => {
            FreshNetworkIdentityPolicy::PreserveInstanceIdentity
        }
        NetworkPolicy::WhonixGateway(_) | NetworkPolicy::WhonixWorkstation(_) => {
            FreshNetworkIdentityPolicy::PairAwareRequired
        }
    };
    Ok(FreshPlan {
        action: FreshAction::ReplaceActive,
        stable_instance: input.instance,
        profile_id: profile.id.clone(),
        old_active_generation_id: active.generation_id.clone(),
        old_domain_uuid: active.domain_uuid.clone(),
        old_storage: active.resources.clone(),
        old_seed: input.old_seed,
        old_network_identity: input.old_network_identity,
        new_generation_id,
        new_domain_uuid: active.domain_uuid.clone(),
        new_overlay: names.overlay,
        new_seed: names.seed,
        trusted_base_disposition: input.shared_base_disposition,
        guest_identity: FreshGuestIdentityPolicy::ProfileFreshIdentity,
        network_identity,
        activation: FreshActivationPolicy::OldActiveToRetained,
        retention: FreshRetentionPolicy::RetainOldUntilExplicitCleanup,
        confirmation_required: true,
        mutation: false,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreshTransactionStage {
    Planned,
    Preparing,
    ProvenReady,
    Active,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainReplacementStage {
    OldAuthoritative,
    PreparingPublished,
    OldDomainProven,
    ReplacementDefined,
    ReplacementVerified,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PersistentDomainTopology {
    pub machine: String,
    pub firmware_loader: Option<String>,
    pub vcpus: u32,
    pub memory_kib: u64,
    pub disks: Vec<PersistentDisk>,
    pub interfaces: Vec<PersistentInterface>,
    pub graphics: Vec<String>,
    pub qga_channels: usize,
    pub hostdevs: usize,
    pub filesystems: usize,
    pub device_kinds: Vec<String>,
    pub autostart: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PersistentDisk {
    pub device: String,
    pub kind: String,
    pub driver: String,
    pub format: String,
    pub source: String,
    pub target: String,
    pub bus: String,
    pub readonly: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PersistentInterface {
    pub kind: String,
    pub model: String,
    pub mac: String,
    pub source: String,
    pub backend: Option<String>,
}

impl PersistentDomainTopology {
    #[must_use]
    pub fn with_primary_disk(&self, path: &str) -> Self {
        let mut next = self.clone();
        if let Some(disk) = next.disks.iter_mut().find(|disk| disk.device == "disk") {
            path.clone_into(&mut disk.source);
        }
        next
    }
}

/// Validates the complete security-relevant Kali persistent topology before Fresh/recovery.
///
/// # Errors
/// Refuses any topology outside the exact supported Kali persistent-domain policy.
pub fn validate_kali_topology(
    topology: &PersistentDomainTopology,
    expected_disk: &str,
) -> Result<(), String> {
    let allowed = [
        "audio",
        "channel",
        "console",
        "controller",
        "disk",
        "emulator",
        "graphics",
        "input",
        "interface",
        "memballoon",
        "serial",
        "sound",
        "video",
        "watchdog",
    ];
    let primary = topology
        .disks
        .iter()
        .filter(|disk| disk.device == "disk")
        .collect::<Vec<_>>();
    if !topology.machine.contains("q35")
        || topology.firmware_loader.is_some()
        || topology.vcpus == 0
        || topology.memory_kib == 0
        || primary.len() != 1
        || topology.disks.len() != 1
        || primary[0].source != expected_disk
        || primary[0].kind != "file"
        || primary[0].driver != "qemu"
        || primary[0].format != "qcow2"
        || primary[0].target != "vda"
        || primary[0].bus != "virtio"
        || primary[0].readonly
        || topology.interfaces.len() != 1
        || topology.interfaces[0].kind != "network"
        || topology.interfaces[0].model != "virtio"
        || !topology.interfaces[0].source.contains("network=default")
        || topology.interfaces[0].mac.is_empty()
        || topology.graphics.len() != 1
        || !topology.graphics[0].contains("type=spice")
        || topology.qga_channels != 0
        || topology.hostdevs != 0
        || topology.filesystems != 0
        || topology.autostart
        || topology
            .device_kinds
            .iter()
            .any(|kind| !allowed.contains(&kind.as_str()))
    {
        return Err(format!(
            "persistent Kali domain topology differs from the exact supported policy: {topology:?}"
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StableDomainEvidence {
    pub name: String,
    pub uuid: String,
    pub persistent: bool,
    pub shutoff: bool,
    pub disk_path: String,
    pub network_identity: Option<String>,
    pub topology: PersistentDomainTopology,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainReplacementError {
    IdentityMismatch,
    DomainMustBePersistentShutoff,
}

/// Verifies the typed boundary before and after a define-over-existing call.
/// The actual libvirt operation is intentionally left to a later executor.
///
/// # Errors
///
/// Returns a typed refusal when stable identity, lifecycle, disk, or network
/// evidence differs from the expected replacement boundary.
pub fn verify_domain_replacement(
    old: &StableDomainEvidence,
    replacement: &StableDomainEvidence,
    expected_old_disk: &str,
    expected_new_disk: &str,
) -> Result<(), DomainReplacementError> {
    if old.name != replacement.name
        || old.uuid != replacement.uuid
        || !old.persistent
        || !old.shutoff
        || old.disk_path != expected_old_disk
    {
        return Err(DomainReplacementError::IdentityMismatch);
    }
    if !replacement.persistent || !replacement.shutoff {
        return Err(DomainReplacementError::DomainMustBePersistentShutoff);
    }
    if replacement.disk_path != expected_new_disk {
        return Err(DomainReplacementError::IdentityMismatch);
    }
    if replacement.network_identity != old.network_identity {
        return Err(DomainReplacementError::IdentityMismatch);
    }
    if replacement.topology != old.topology.with_primary_disk(expected_new_disk) {
        return Err(DomainReplacementError::IdentityMismatch);
    }
    Ok(())
}

#[derive(Debug)]
pub enum FreshTransactionError {
    InvalidStage,
    Switch(StateError),
}

pub struct FreshTransaction {
    pub plan: FreshPlan,
    pub stage: FreshTransactionStage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreshExecutionPlan {
    pub fresh: FreshPlan,
    pub created_unix_seconds: u64,
    pub replacement_xml: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreshExecutionResult {
    pub index: GenerationIndex,
    pub observed: ObservedGeneration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FreshExecutionError {
    BeforeOwnership(String),
    RecoveryRequired(String),
}

impl fmt::Display for FreshExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BeforeOwnership(reason) => write!(
                formatter,
                "Fresh refused before durable ownership: {reason}"
            ),
            Self::RecoveryRequired(reason) => write!(
                formatter,
                "Fresh crossed durable Preparing boundary; explicit restore-old recovery required: {reason}"
            ),
        }
    }
}

impl std::error::Error for FreshExecutionError {}

#[allow(clippy::missing_errors_doc)]
pub trait FreshExecutionBackend {
    fn checkpoint(&mut self, _point: FreshFailurePoint) -> Result<(), String> {
        Ok(())
    }
    /// Revalidates the complete plan snapshot immediately before the first mutation.
    fn revalidate(&mut self, plan: &FreshExecutionPlan) -> Result<StableDomainEvidence, String>;
    /// Re-proves the shared base and creates exactly one generation-owned overlay.
    fn create_overlay(&mut self, plan: &FreshExecutionPlan) -> Result<(), String>;
    /// Proves qcow2 format, capacity, exact backing, and collision-free ownership.
    fn inspect_overlay(&mut self, plan: &FreshExecutionPlan) -> Result<ObservedGeneration, String>;
    /// Publishes the immutable manifest and the index containing one Preparing generation.
    fn publish_preparing(
        &mut self,
        manifest: &GenerationManifest,
    ) -> Result<GenerationIndex, String>;
    /// Revalidates the exact old persistent shutoff domain just before redefine.
    fn revalidate_old_domain(&mut self, expected: &StableDomainEvidence) -> Result<(), String>;
    /// Performs the sole replacement primitive: libvirt define-over-existing.
    fn define_replacement(&mut self, xml: &str) -> Result<(), String>;
    /// Re-reads persistent XML and returns exact replacement evidence and storage observation.
    fn inspect_replacement(
        &mut self,
        plan: &FreshExecutionPlan,
    ) -> Result<(StableDomainEvidence, ObservedGeneration), String>;
    /// Atomically publishes old Active -> Retained and new Preparing -> Active.
    fn activate(
        &mut self,
        expected: &GenerationIndex,
        next: &GenerationIndex,
    ) -> Result<(), String>;
    /// Reconciles the final durable and libvirt state.
    fn reconcile_final(
        &mut self,
        expected: &GenerationIndex,
        observed: &ObservedGeneration,
    ) -> Result<(), String>;
    /// Deletes only the transaction-created overlay before Preparing publication.
    fn rollback_overlay(&mut self, plan: &FreshExecutionPlan) -> Result<(), String>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreshFailurePoint {
    BeforeOverlayCreate,
    AfterOverlayCreate,
    AfterPreparing,
    AfterRedefine,
    AfterVerification,
    AfterProvenReady,
}

/// Executes one fail-closed Kali `ManualGuest` Fresh replacement. No boot or cleanup is performed.
#[allow(clippy::missing_errors_doc, clippy::too_many_lines)]
pub fn execute_fresh<B: FreshExecutionBackend>(
    backend: &mut B,
    plan: &FreshExecutionPlan,
) -> Result<FreshExecutionResult, FreshExecutionError> {
    let old = backend
        .revalidate(plan)
        .map_err(FreshExecutionError::BeforeOwnership)?;
    backend
        .checkpoint(FreshFailurePoint::BeforeOverlayCreate)
        .map_err(FreshExecutionError::BeforeOwnership)?;
    if let Err(error) = backend.create_overlay(plan) {
        let rollback = backend.rollback_overlay(plan).err();
        return Err(FreshExecutionError::BeforeOwnership(
            rollback.map_or(error.clone(), |r| {
                format!("{error}; overlay rollback also failed: {r}")
            }),
        ));
    }
    if let Err(error) = backend.checkpoint(FreshFailurePoint::AfterOverlayCreate) {
        let rollback = backend.rollback_overlay(plan).err();
        return Err(FreshExecutionError::BeforeOwnership(
            rollback.map_or(error.clone(), |r| {
                format!("{error}; overlay rollback also failed: {r}")
            }),
        ));
    }
    let preparing = match backend.inspect_overlay(plan) {
        Ok(value) => value,
        Err(error) => {
            let rollback = backend.rollback_overlay(plan).err();
            return Err(FreshExecutionError::BeforeOwnership(
                rollback.map_or(error.clone(), |r| {
                    format!("{error}; overlay rollback also failed: {r}")
                }),
            ));
        }
    };
    let mut manifest = forge_state::manifest_from_observed(
        &preparing,
        plan.fresh.new_generation_id.clone(),
        forge_state::GenerationStatus::Preparing,
        plan.created_unix_seconds,
    );
    let old_disk = plan
        .fresh
        .old_storage
        .iter()
        .find(|r| r.role == forge_state::ResourceRole::WritableOverlay)
        .ok_or_else(|| {
            FreshExecutionError::BeforeOwnership("old Active has no exact overlay".to_owned())
        })?;
    let new_disk = preparing
        .resources
        .iter()
        .find(|r| r.role == forge_state::ResourceRole::WritableOverlay)
        .ok_or_else(|| {
            FreshExecutionError::BeforeOwnership("Preparing has no exact overlay".to_owned())
        })?;
    let old_xml = plan
        .replacement_xml
        .replacen(&new_disk.path, &old_disk.path, 1);
    manifest.fresh_domain_evidence = Some(forge_state::FreshDomainEvidence {
        old_persistent_xml: old_xml,
        old_normalized_topology: format!("{:?}", old.topology),
        replacement_normalized_topology: format!(
            "{:?}",
            old.topology.with_primary_disk(&new_disk.path)
        ),
    });
    let preparing_index = match backend.publish_preparing(&manifest) {
        Ok(index) => index,
        Err(error) => {
            let rollback = backend.rollback_overlay(plan).err();
            return Err(FreshExecutionError::BeforeOwnership(
                rollback.map_or(error.clone(), |r| {
                    format!("{error}; overlay rollback also failed: {r}")
                }),
            ));
        }
    };
    backend
        .checkpoint(FreshFailurePoint::AfterPreparing)
        .map_err(FreshExecutionError::RecoveryRequired)?;
    backend
        .revalidate_old_domain(&old)
        .map_err(FreshExecutionError::RecoveryRequired)?;
    backend
        .define_replacement(&plan.replacement_xml)
        .map_err(FreshExecutionError::RecoveryRequired)?;
    backend
        .checkpoint(FreshFailurePoint::AfterRedefine)
        .map_err(FreshExecutionError::RecoveryRequired)?;
    let (replacement, observed) = backend
        .inspect_replacement(plan)
        .map_err(FreshExecutionError::RecoveryRequired)?;
    verify_domain_replacement(&old, &replacement, &old_disk.path, &new_disk.path).map_err(|e| {
        FreshExecutionError::RecoveryRequired(format!("post-define verification failed: {e:?}"))
    })?;
    backend
        .checkpoint(FreshFailurePoint::AfterVerification)
        .map_err(FreshExecutionError::RecoveryRequired)?;
    let next = commit_fresh_switch(
        &preparing_index,
        &plan.fresh.old_active_generation_id,
        &plan.fresh.new_generation_id,
    )
    .map_err(|e| FreshExecutionError::RecoveryRequired(e.to_string()))?;
    backend
        .checkpoint(FreshFailurePoint::AfterProvenReady)
        .map_err(FreshExecutionError::RecoveryRequired)?;
    backend
        .activate(&preparing_index, &next)
        .map_err(FreshExecutionError::RecoveryRequired)?;
    backend
        .reconcile_final(&next, &observed)
        .map_err(FreshExecutionError::RecoveryRequired)?;
    Ok(FreshExecutionResult {
        index: next,
        observed,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreOldPlan {
    pub source_index: GenerationIndex,
    pub old_active: GenerationManifest,
    pub preparing: GenerationManifest,
    pub current_domain: StableDomainEvidence,
    pub old_domain_xml: String,
    pub mutation: bool,
}

#[allow(clippy::missing_errors_doc)]
pub trait FreshRecoveryBackend {
    fn revalidate_restore(&mut self, plan: &RestoreOldPlan) -> Result<(), String>;
    fn define_old(&mut self, xml: &str) -> Result<(), String>;
    fn inspect_old(&mut self, plan: &RestoreOldPlan) -> Result<StableDomainEvidence, String>;
    fn publish_failed(
        &mut self,
        expected: &GenerationIndex,
        next: &GenerationIndex,
    ) -> Result<(), String>;
    /// Uses exact Preparing ownership to remove only replacement resources.
    fn cleanup_failed_preparing(&mut self, manifest: &GenerationManifest) -> Result<(), String>;
    fn reconcile_old(&mut self, expected: &GenerationIndex) -> Result<(), String>;
}

/// Plans the safe minimum Fresh recovery: restore the durable old Active definition.
#[allow(clippy::missing_errors_doc)]
pub fn plan_restore_old(
    index: &GenerationIndex,
    manifests: &[GenerationManifest],
    current: StableDomainEvidence,
    old_domain_xml: String,
) -> Result<RestoreOldPlan, String> {
    forge_state::validate_index(index).map_err(|e| e.to_string())?;
    let old = manifests
        .iter()
        .filter(|m| {
            m.generation_id == index.active_generation_id
                && m.status == forge_state::GenerationStatus::Active
        })
        .collect::<Vec<_>>();
    let preparing_entries = index
        .generations
        .iter()
        .filter(|e| e.status == forge_state::GenerationStatus::Preparing)
        .collect::<Vec<_>>();
    if old.len() != 1 || preparing_entries.len() != 1 {
        return Err("restore-old requires exactly one durable Active and one Preparing".to_owned());
    }
    let preparing = manifests
        .iter()
        .filter(|m| {
            m.generation_id == preparing_entries[0].generation_id
                && m.status == forge_state::GenerationStatus::Preparing
        })
        .collect::<Vec<_>>();
    if preparing.len() != 1 {
        return Err("restore-old Preparing identity is missing or ambiguous".to_owned());
    }
    let old_disk = old[0]
        .resources
        .iter()
        .find(|r| r.role == forge_state::ResourceRole::WritableOverlay)
        .ok_or("old Active overlay is missing")?;
    let new_disk = preparing[0]
        .resources
        .iter()
        .find(|r| r.role == forge_state::ResourceRole::WritableOverlay)
        .ok_or("Preparing overlay is missing")?;
    let evidence = preparing[0]
        .fresh_domain_evidence
        .as_ref()
        .ok_or("Preparing has no durable Fresh domain evidence")?;
    if current.name != index.domain_name
        || current.uuid != index.domain_uuid
        || !current.persistent
        || !current.shutoff
        || current.disk_path != new_disk.path
        || current.disk_path == old_disk.path
        || format!("{:?}", current.topology) != evidence.replacement_normalized_topology
    {
        return Err(
            "restore-old refused: current domain is not the exact Preparing binding".to_owned(),
        );
    }
    Ok(RestoreOldPlan {
        source_index: index.clone(),
        old_active: old[0].clone(),
        preparing: preparing[0].clone(),
        current_domain: current,
        old_domain_xml: if old_domain_xml == evidence.old_persistent_xml {
            old_domain_xml
        } else {
            return Err("restore-old XML differs from durable Fresh evidence".to_owned());
        },
        mutation: false,
    })
}

/// Restores the exact old definition, verifies it, performs exact-ownership cleanup while
/// Preparing still keeps recovery fail-closed, then atomically marks Preparing Failed.
#[allow(clippy::missing_errors_doc)]
pub fn execute_restore_old<B: FreshRecoveryBackend>(
    backend: &mut B,
    plan: &RestoreOldPlan,
) -> Result<GenerationIndex, String> {
    backend.revalidate_restore(plan)?;
    backend.define_old(&plan.old_domain_xml)?;
    let restored = backend.inspect_old(plan)?;
    let old_disk = plan
        .old_active
        .resources
        .iter()
        .find(|r| r.role == forge_state::ResourceRole::WritableOverlay)
        .ok_or("old Active overlay is missing")?;
    if restored.name != plan.current_domain.name
        || restored.uuid != plan.current_domain.uuid
        || !restored.persistent
        || !restored.shutoff
        || restored.disk_path != old_disk.path
        || restored.network_identity != plan.current_domain.network_identity
        || restored.topology
            != plan
                .current_domain
                .topology
                .with_primary_disk(&old_disk.path)
    {
        return Err("restore-old post-define verification failed".to_owned());
    }
    let next = forge_state::mark_failed(&plan.source_index, &plan.preparing.generation_id)
        .map_err(|e| e.to_string())?;
    backend.cleanup_failed_preparing(&plan.preparing)?;
    backend.publish_failed(&plan.source_index, &next)?;
    backend.reconcile_old(&next)?;
    Ok(next)
}

impl FreshTransaction {
    #[must_use]
    pub fn begin(plan: FreshPlan) -> Self {
        Self {
            plan,
            stage: FreshTransactionStage::Planned,
        }
    }

    /// Publishes the replacement's durable Preparing intent in the model.
    ///
    /// # Errors
    ///
    /// Returns `InvalidStage` unless the transaction is Planned.
    pub fn publish_preparing(&mut self) -> Result<(), FreshTransactionError> {
        if self.stage != FreshTransactionStage::Planned {
            return Err(FreshTransactionError::InvalidStage);
        }
        self.stage = FreshTransactionStage::Preparing;
        Ok(())
    }

    /// Records that replacement resources and domain proof completed.
    ///
    /// # Errors
    ///
    /// Returns `InvalidStage` unless the transaction is Preparing.
    pub fn prove_ready(&mut self) -> Result<(), FreshTransactionError> {
        if self.stage != FreshTransactionStage::Preparing {
            return Err(FreshTransactionError::InvalidStage);
        }
        self.stage = FreshTransactionStage::ProvenReady;
        Ok(())
    }

    /// Atomically publishes the new Active and old Retained index state.
    ///
    /// # Errors
    ///
    /// Refuses an invalid stage or stale/ambiguous durable index.
    pub fn activate(
        &mut self,
        index: &GenerationIndex,
    ) -> Result<GenerationIndex, FreshTransactionError> {
        if self.stage != FreshTransactionStage::ProvenReady {
            return Err(FreshTransactionError::InvalidStage);
        }
        let next = commit_fresh_switch(
            index,
            &self.plan.old_active_generation_id,
            &self.plan.new_generation_id,
        )
        .map_err(FreshTransactionError::Switch)?;
        self.stage = FreshTransactionStage::Active;
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use forge_profiles::kali_lab;
    use forge_state::{GenerationEntry, GenerationStatus, ObservedResource, ResourceRole};

    fn input() -> FreshPlanInput {
        let instance = InstanceName::new("kali-lab").unwrap();
        let generation = "gen-11111111-1111-4111-8111-111111111111".to_owned();
        let resource = ManagedResource {
            role: ResourceRole::WritableOverlay,
            volume_name: "kali-lab-gen.qcow2".to_owned(),
            volume_key: "key-overlay".to_owned(),
            path: "/var/lib/libvirt/images/kali-lab-gen.qcow2".to_owned(),
            format: "qcow2".to_owned(),
            capacity_bytes: 86 * 1024 * 1024 * 1024,
            backing_path: Some("/var/lib/libvirt/images/forge-base-kali-2026.2.qcow2".to_owned()),
        };
        let index = GenerationIndex {
            schema_version: forge_state::INDEX_SCHEMA_VERSION,
            domain_name: instance.as_str().to_owned(),
            domain_uuid: "22222222-2222-4222-8222-222222222222".to_owned(),
            active_generation_id: generation.clone(),
            generations: vec![GenerationEntry {
                generation_id: generation.clone(),
                status: GenerationStatus::Active,
                manifest_file: format!("{generation}.json"),
            }],
            cleanup_progress: vec![],
        };
        let manifest = GenerationManifest {
            schema_version: forge_state::SCHEMA_VERSION,
            domain_name: instance.as_str().to_owned(),
            domain_uuid: index.domain_uuid.clone(),
            generation_id: generation,
            created_unix_seconds: 1,
            libvirt_uri: "qemu:///system".to_owned(),
            storage_pool_name: "default".to_owned(),
            storage_pool_uuid: "pool".to_owned(),
            status: GenerationStatus::Active,
            resources: vec![resource.clone()],
            fresh_domain_evidence: None,
        };
        let observed = ObservedGeneration {
            domain_name: manifest.domain_name.clone(),
            domain_uuid: manifest.domain_uuid.clone(),
            domain_persistent: true,
            libvirt_uri: manifest.libvirt_uri.clone(),
            storage_pool_name: manifest.storage_pool_name.clone(),
            storage_pool_uuid: manifest.storage_pool_uuid.clone(),
            resources: vec![ObservedResource {
                role: resource.role,
                volume_name: resource.volume_name.clone(),
                volume_key: resource.volume_key.clone(),
                path: resource.path.clone(),
                format: resource.format.clone(),
                capacity_bytes: resource.capacity_bytes,
                backing_path: resource.backing_path.clone(),
                referenced_by_domains: vec![manifest.domain_name.clone()],
                backing_for_volumes: vec![],
            }],
            unmanaged_resources: vec![],
        };
        FreshPlanInput {
            instance,
            profile: Some(kali_lab()),
            index,
            active: Some(manifest),
            observed,
            domain_state: VmState::Shutoff,
            reconciliation: ManagedReconciliationStatus::Consistent,
            shared_base_disposition: SharedBaseDisposition::ReuseProven,
            old_seed: None,
            old_network_identity: Some("stable-mac".to_owned()),
        }
    }

    #[test]
    fn valid_plan_is_zero_mutation_and_preserves_instance_identity() {
        let plan = plan_fresh(
            input(),
            "gen-33333333-3333-4333-8333-333333333333".to_owned(),
        )
        .unwrap();
        assert!(!plan.mutation);
        assert_eq!(plan.stable_instance.as_str(), "kali-lab");
        assert_eq!(
            plan.trusted_base_disposition,
            SharedBaseDisposition::ReuseProven
        );
        assert_eq!(plan.new_domain_uuid, plan.old_domain_uuid);
        assert_eq!(
            plan.guest_identity,
            FreshGuestIdentityPolicy::ProfileFreshIdentity
        );
    }

    #[test]
    fn planner_refuses_running_inconsistent_and_missing_profile() {
        let mut running = input();
        running.domain_state = VmState::Running;
        assert_eq!(
            plan_fresh(
                running,
                "gen-33333333-3333-4333-8333-333333333333".to_owned()
            ),
            Err(FreshPlanError::RunningInstance)
        );
        let mut inconsistent = input();
        inconsistent.reconciliation = ManagedReconciliationStatus::Conflict;
        assert_eq!(
            plan_fresh(
                inconsistent,
                "gen-33333333-3333-4333-8333-333333333333".to_owned()
            ),
            Err(FreshPlanError::InconsistentState)
        );
        let mut missing = input();
        missing.profile = None;
        assert_eq!(
            plan_fresh(
                missing,
                "gen-33333333-3333-4333-8333-333333333333".to_owned()
            ),
            Err(FreshPlanError::MissingProfileBinding)
        );
    }

    #[test]
    fn transaction_cannot_activate_before_proof_and_switches_atomically() {
        let mut tx = FreshTransaction::begin(
            plan_fresh(
                input(),
                "gen-33333333-3333-4333-8333-333333333333".to_owned(),
            )
            .unwrap(),
        );
        assert!(matches!(
            tx.activate(&input().index),
            Err(FreshTransactionError::InvalidStage)
        ));
        tx.publish_preparing().unwrap();
        tx.prove_ready().unwrap();
        let mut index = input().index;
        index.generations.push(GenerationEntry {
            generation_id: tx.plan.new_generation_id.clone(),
            status: GenerationStatus::Preparing,
            manifest_file: format!("{}.json", tx.plan.new_generation_id),
        });
        let switched = tx.activate(&index).unwrap();
        assert_eq!(tx.stage, FreshTransactionStage::Active);
        assert_eq!(switched.active_generation_id, tx.plan.new_generation_id);
        assert_eq!(
            switched
                .generations
                .iter()
                .filter(|e| e.status == GenerationStatus::Active)
                .count(),
            1
        );
        assert_eq!(
            switched
                .generations
                .iter()
                .filter(|e| e.status == GenerationStatus::Retained)
                .count(),
            1
        );
    }

    #[test]
    fn preparing_does_not_change_old_active_and_stale_switch_is_rejected() {
        let plan = plan_fresh(
            input(),
            "gen-33333333-3333-4333-8333-333333333333".to_owned(),
        )
        .unwrap();
        let mut tx = FreshTransaction::begin(plan);
        tx.publish_preparing().unwrap();
        let before = input().index;
        assert_eq!(
            before.active_generation_id,
            "gen-11111111-1111-4111-8111-111111111111"
        );
        tx.prove_ready().unwrap();
        let mut stale = before.clone();
        stale.active_generation_id = "gen-44444444-4444-4444-8444-444444444444".to_owned();
        let result = tx.activate(&stale);
        assert!(matches!(result, Err(FreshTransactionError::Switch(_))));
        assert_eq!(
            before.active_generation_id,
            "gen-11111111-1111-4111-8111-111111111111"
        );
    }

    #[test]
    fn missing_preparing_and_retained_generations_are_handled_fail_closed() {
        let plan = plan_fresh(
            input(),
            "gen-33333333-3333-4333-8333-333333333333".to_owned(),
        )
        .unwrap();
        let mut tx = FreshTransaction::begin(plan);
        tx.publish_preparing().unwrap();
        tx.prove_ready().unwrap();
        assert!(matches!(
            tx.activate(&input().index),
            Err(FreshTransactionError::Switch(_))
        ));

        let mut retained = input();
        retained.index.generations.push(GenerationEntry {
            generation_id: "gen-99999999-9999-4999-8999-999999999999".to_owned(),
            status: GenerationStatus::Retained,
            manifest_file: "generations/retained.json".to_owned(),
        });
        assert!(
            plan_fresh(
                retained,
                "gen-33333333-3333-4333-8333-333333333333".to_owned()
            )
            .is_ok()
        );
    }

    #[test]
    fn whonix_and_fedora_capabilities_are_typed_refusals() {
        assert_eq!(
            fresh_capability(&forge_profiles::fedora_lab()),
            FreshCapability::Unsupported(FreshUnsupportedReason::LegacyFedoraProductRetired)
        );
        assert_eq!(
            fresh_capability(&forge_profiles::whonix_gateway()),
            FreshCapability::Unsupported(FreshUnsupportedReason::WhonixPairAwareRequired)
        );
    }

    #[test]
    fn stable_domain_replacement_requires_exact_shutoff_identity() {
        let old = StableDomainEvidence {
            name: "kali-lab".into(),
            uuid: "domain-uuid".into(),
            persistent: true,
            shutoff: true,
            disk_path: "/old.qcow2".into(),
            network_identity: Some("stable-mac".into()),
            topology: PersistentDomainTopology {
                disks: vec![PersistentDisk {
                    device: "disk".into(),
                    source: "/old.qcow2".into(),
                    ..PersistentDisk::default()
                }],
                ..PersistentDomainTopology::default()
            },
        };
        let mut replacement = old.clone();
        replacement.disk_path = "/new.qcow2".into();
        replacement.topology = replacement.topology.with_primary_disk("/new.qcow2");
        assert!(verify_domain_replacement(&old, &replacement, "/old.qcow2", "/new.qcow2").is_ok());
        replacement.uuid = "other".into();
        assert_eq!(
            verify_domain_replacement(&old, &replacement, "/old.qcow2", "/new.qcow2"),
            Err(DomainReplacementError::IdentityMismatch)
        );
    }

    fn restore_fixture() -> (
        GenerationIndex,
        Vec<GenerationManifest>,
        StableDomainEvidence,
    ) {
        let source = input();
        let old = source.active.unwrap();
        let mut preparing = old.clone();
        preparing.generation_id = "gen-33333333-3333-4333-8333-333333333333".to_owned();
        preparing.status = GenerationStatus::Preparing;
        preparing.resources[0].path = "/var/lib/libvirt/images/new.qcow2".to_owned();
        preparing.resources[0].volume_name = "new.qcow2".to_owned();
        preparing.resources[0].volume_key = "new-key".to_owned();
        let index = forge_state::add_preparing(&source.index, &preparing).unwrap();
        let current = StableDomainEvidence {
            name: "kali-lab".to_owned(),
            uuid: index.domain_uuid.clone(),
            persistent: true,
            shutoff: true,
            disk_path: preparing.resources[0].path.clone(),
            network_identity: Some("stable-mac".to_owned()),
            topology: PersistentDomainTopology {
                disks: vec![PersistentDisk {
                    device: "disk".into(),
                    source: preparing.resources[0].path.clone(),
                    ..PersistentDisk::default()
                }],
                ..PersistentDomainTopology::default()
            },
        };
        preparing.fresh_domain_evidence = Some(forge_state::FreshDomainEvidence {
            old_persistent_xml: "<old/>".to_owned(),
            old_normalized_topology: format!(
                "{:?}",
                current.topology.with_primary_disk(&old.resources[0].path)
            ),
            replacement_normalized_topology: format!("{:?}", current.topology),
        });
        (index, vec![old, preparing], current)
    }

    #[derive(Default)]
    #[allow(clippy::struct_excessive_bools)]
    struct RecoveryMock {
        defined: bool,
        published: bool,
        cleaned: bool,
        reconciled: bool,
        drift: bool,
        cleanup_fail: bool,
    }
    impl FreshRecoveryBackend for RecoveryMock {
        fn revalidate_restore(&mut self, _: &RestoreOldPlan) -> Result<(), String> {
            if self.drift {
                Err("drift".to_owned())
            } else {
                Ok(())
            }
        }
        fn define_old(&mut self, _: &str) -> Result<(), String> {
            self.defined = true;
            Ok(())
        }
        fn inspect_old(&mut self, plan: &RestoreOldPlan) -> Result<StableDomainEvidence, String> {
            let mut value = plan.current_domain.clone();
            value.disk_path = plan.old_active.resources[0].path.clone();
            value.topology = value.topology.with_primary_disk(&value.disk_path);
            Ok(value)
        }
        fn publish_failed(
            &mut self,
            _: &GenerationIndex,
            _: &GenerationIndex,
        ) -> Result<(), String> {
            self.published = true;
            Ok(())
        }
        fn cleanup_failed_preparing(
            &mut self,
            manifest: &GenerationManifest,
        ) -> Result<(), String> {
            assert_eq!(manifest.status, GenerationStatus::Preparing);
            self.cleaned = true;
            if self.cleanup_fail {
                Err("cleanup injected".into())
            } else {
                Ok(())
            }
        }
        fn reconcile_old(&mut self, _: &GenerationIndex) -> Result<(), String> {
            self.reconciled = true;
            Ok(())
        }
    }

    #[test]
    fn restore_old_is_exact_preserves_active_and_uses_owned_cleanup() {
        let (index, manifests, current) = restore_fixture();
        let plan = plan_restore_old(&index, &manifests, current, "<old/>".to_owned()).unwrap();
        let mut backend = RecoveryMock::default();
        let restored = execute_restore_old(&mut backend, &plan).unwrap();
        assert_eq!(restored.active_generation_id, index.active_generation_id);
        assert_eq!(
            restored
                .generations
                .iter()
                .filter(|e| e.status == GenerationStatus::Active)
                .count(),
            1
        );
        assert!(
            restored
                .generations
                .iter()
                .any(|e| e.generation_id == plan.preparing.generation_id
                    && e.status == GenerationStatus::Failed)
        );
        assert!(backend.defined && backend.published && backend.cleaned && backend.reconciled);
        assert!(
            plan.old_active
                .resources
                .iter()
                .any(|r| r.role == ResourceRole::WritableOverlay)
        );
    }

    #[test]
    fn restore_old_refuses_domain_and_durable_drift() {
        let (index, manifests, mut current) = restore_fixture();
        current.uuid = "unexpected".to_owned();
        assert!(plan_restore_old(&index, &manifests, current, "<old/>".to_owned()).is_err());
        let (index, manifests, mut current) = restore_fixture();
        current.topology.vcpus += 1;
        assert!(plan_restore_old(&index, &manifests, current, "<old/>".to_owned()).is_err());
        let (_, _, current) = restore_fixture();
        let plan = plan_restore_old(&index, &manifests, current, "<old/>".to_owned()).unwrap();
        let mut backend = RecoveryMock {
            drift: true,
            ..RecoveryMock::default()
        };
        assert!(execute_restore_old(&mut backend, &plan).is_err());
        assert!(!backend.defined);
    }

    #[test]
    fn restore_cleanup_failure_keeps_preparing_recovery_boundary() {
        let (index, manifests, current) = restore_fixture();
        let plan = plan_restore_old(&index, &manifests, current, "<old/>".to_owned()).unwrap();
        let mut backend = RecoveryMock {
            cleanup_fail: true,
            ..RecoveryMock::default()
        };
        assert!(execute_restore_old(&mut backend, &plan).is_err());
        assert!(backend.defined && backend.cleaned && !backend.published && !backend.reconciled);
        assert_eq!(index.active_generation_id, plan.old_active.generation_id);
        assert!(
            index
                .generations
                .iter()
                .any(|entry| entry.status == GenerationStatus::Preparing)
        );
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Inject {
        Check(FreshFailurePoint),
        Define,
        Verify,
        Activate,
        Reconcile,
    }
    struct FreshMock {
        inject: Inject,
        index: GenerationIndex,
        manifests: Vec<GenerationManifest>,
        overlay: bool,
        binding_new: bool,
        rollback: bool,
    }

    impl FreshMock {
        fn new(inject: Inject) -> Self {
            let source = input();
            Self {
                inject,
                index: source.index,
                manifests: vec![source.active.unwrap()],
                overlay: false,
                binding_new: false,
                rollback: false,
            }
        }
        fn old_evidence(&self) -> StableDomainEvidence {
            StableDomainEvidence {
                name: self.index.domain_name.clone(),
                uuid: self.index.domain_uuid.clone(),
                persistent: true,
                shutoff: true,
                disk_path: self.manifests[0].resources[0].path.clone(),
                network_identity: Some("stable-mac".into()),
                topology: PersistentDomainTopology {
                    disks: vec![PersistentDisk {
                        device: "disk".into(),
                        source: self.manifests[0].resources[0].path.clone(),
                        ..PersistentDisk::default()
                    }],
                    ..PersistentDomainTopology::default()
                },
            }
        }
        fn observed(&self, new: bool) -> ObservedGeneration {
            let resource = if new {
                self.manifests.last().unwrap().resources[0].clone()
            } else {
                self.manifests[0].resources[0].clone()
            };
            ObservedGeneration {
                domain_name: self.index.domain_name.clone(),
                domain_uuid: self.index.domain_uuid.clone(),
                domain_persistent: true,
                libvirt_uri: "qemu:///system".into(),
                storage_pool_name: "default".into(),
                storage_pool_uuid: "pool".into(),
                resources: vec![ObservedResource {
                    role: resource.role,
                    volume_name: resource.volume_name,
                    volume_key: resource.volume_key,
                    path: resource.path,
                    format: resource.format,
                    capacity_bytes: resource.capacity_bytes,
                    backing_path: resource.backing_path,
                    referenced_by_domains: vec![self.index.domain_name.clone()],
                    backing_for_volumes: vec![],
                }],
                unmanaged_resources: vec![],
            }
        }
    }
    impl FreshExecutionBackend for FreshMock {
        fn checkpoint(&mut self, point: FreshFailurePoint) -> Result<(), String> {
            if self.inject == Inject::Check(point) {
                Err("injected".into())
            } else {
                Ok(())
            }
        }
        fn revalidate(&mut self, _: &FreshExecutionPlan) -> Result<StableDomainEvidence, String> {
            Ok(self.old_evidence())
        }
        fn create_overlay(&mut self, _: &FreshExecutionPlan) -> Result<(), String> {
            self.overlay = true;
            Ok(())
        }
        fn inspect_overlay(
            &mut self,
            plan: &FreshExecutionPlan,
        ) -> Result<ObservedGeneration, String> {
            let mut observed = self.observed(false);
            let resource = &mut observed.resources[0];
            resource.path = format!("/var/lib/libvirt/images/{}", plan.fresh.new_overlay);
            resource.volume_name = plan.fresh.new_overlay.clone();
            resource.volume_key = "new-key".into();
            Ok(observed)
        }
        fn publish_preparing(
            &mut self,
            manifest: &GenerationManifest,
        ) -> Result<GenerationIndex, String> {
            self.manifests.push(manifest.clone());
            self.index =
                forge_state::add_preparing(&self.index, manifest).map_err(|e| e.to_string())?;
            Ok(self.index.clone())
        }
        fn revalidate_old_domain(&mut self, _: &StableDomainEvidence) -> Result<(), String> {
            Ok(())
        }
        fn define_replacement(&mut self, _: &str) -> Result<(), String> {
            if self.inject == Inject::Define {
                return Err("injected".into());
            }
            self.binding_new = true;
            Ok(())
        }
        fn inspect_replacement(
            &mut self,
            _: &FreshExecutionPlan,
        ) -> Result<(StableDomainEvidence, ObservedGeneration), String> {
            let mut evidence = self.old_evidence();
            let path = self.manifests.last().unwrap().resources[0].path.clone();
            evidence.disk_path.clone_from(&path);
            evidence.topology = evidence.topology.with_primary_disk(&path);
            if self.inject == Inject::Verify {
                evidence.uuid = "drift".into();
            }
            Ok((evidence, self.observed(true)))
        }
        fn activate(&mut self, _: &GenerationIndex, next: &GenerationIndex) -> Result<(), String> {
            if self.inject == Inject::Activate {
                return Err("injected".into());
            }
            self.index = next.clone();
            Ok(())
        }
        fn reconcile_final(
            &mut self,
            _: &GenerationIndex,
            _: &ObservedGeneration,
        ) -> Result<(), String> {
            if self.inject == Inject::Reconcile {
                Err("injected".into())
            } else {
                Ok(())
            }
        }
        fn rollback_overlay(&mut self, _: &FreshExecutionPlan) -> Result<(), String> {
            self.overlay = false;
            self.rollback = true;
            Ok(())
        }
    }

    fn execution_plan() -> FreshExecutionPlan {
        FreshExecutionPlan {
            fresh: plan_fresh(input(), "gen-33333333-3333-4333-8333-333333333333".into()).unwrap(),
            created_unix_seconds: 2,
            replacement_xml: "<domain/>".into(),
        }
    }
    #[allow(clippy::fn_params_excessive_bools)]
    fn assert_failure(
        inject: Inject,
        preparing: bool,
        new_binding: bool,
        switched: bool,
        rollback: bool,
    ) {
        let mut backend = FreshMock::new(inject);
        assert!(execute_fresh(&mut backend, &execution_plan()).is_err());
        assert_eq!(
            backend
                .index
                .generations
                .iter()
                .any(|e| e.status == GenerationStatus::Preparing),
            preparing
        );
        assert_eq!(
            backend.index.active_generation_id == "gen-33333333-3333-4333-8333-333333333333",
            switched
        );
        assert_eq!(backend.binding_new, new_binding);
        assert_eq!(backend.rollback, rollback);
        assert_eq!(
            backend
                .index
                .generations
                .iter()
                .filter(|e| e.status == GenerationStatus::Active)
                .count(),
            1
        );
        if preparing {
            assert_eq!(
                forge_state::reconcile_managed(
                    &backend.index,
                    &backend.manifests,
                    &backend.observed(new_binding)
                )
                .status,
                ManagedReconciliationStatus::RecoveryRequired
            );
        }
        if !switched {
            assert_eq!(
                backend.index.active_generation_id,
                "gen-11111111-1111-4111-8111-111111111111"
            );
        }
        if preparing {
            assert!(backend.overlay);
        } else if rollback {
            assert!(!backend.overlay);
        }
    }

    #[test]
    fn failure_a_before_overlay_create() {
        assert_failure(
            Inject::Check(FreshFailurePoint::BeforeOverlayCreate),
            false,
            false,
            false,
            false,
        );
    }
    #[test]
    fn failure_b_after_overlay_before_preparing() {
        assert_failure(
            Inject::Check(FreshFailurePoint::AfterOverlayCreate),
            false,
            false,
            false,
            true,
        );
    }
    #[test]
    fn failure_c_after_preparing_before_redefine() {
        assert_failure(
            Inject::Check(FreshFailurePoint::AfterPreparing),
            true,
            false,
            false,
            false,
        );
    }
    #[test]
    fn failure_d_define_xml_atomic_failure() {
        assert_failure(Inject::Define, true, false, false, false);
    }
    #[test]
    fn failure_e_after_redefine_before_verification() {
        assert_failure(
            Inject::Check(FreshFailurePoint::AfterRedefine),
            true,
            true,
            false,
            false,
        );
    }
    #[test]
    fn failure_f_post_redefine_verification() {
        assert_failure(Inject::Verify, true, true, false, false);
    }
    #[test]
    fn failure_g_after_verification_before_proven_ready() {
        assert_failure(
            Inject::Check(FreshFailurePoint::AfterVerification),
            true,
            true,
            false,
            false,
        );
    }
    #[test]
    fn failure_h_after_proven_ready_before_switch() {
        assert_failure(
            Inject::Check(FreshFailurePoint::AfterProvenReady),
            true,
            true,
            false,
            false,
        );
    }
    #[test]
    fn failure_i_atomic_switch_publication() {
        assert_failure(Inject::Activate, true, true, false, false);
    }
    #[test]
    fn failure_j_after_switch_before_final_reconciliation() {
        assert_failure(Inject::Reconcile, false, true, true, false);
    }
}
