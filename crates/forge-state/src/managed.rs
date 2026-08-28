use super::{
    GenerationManifest, GenerationStatus, ManagedResource, ObservedGeneration,
    ReconciliationStatus, ResourceRole, STATE_DIRECTORY_MODE, STATE_FILE_MODE, StateError,
    read_manifest, reconcile, write_manifest_atomic,
};
use forge_core::{FirstBootSuccessPolicy, InstanceName};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub const INDEX_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateLayout {
    pub legacy_manifest: PathBuf,
    pub domain_directory: PathBuf,
    pub index: PathBuf,
    pub generations: PathBuf,
}

impl StateLayout {
    #[must_use]
    pub fn new(state_directory: &Path, domain: &str) -> Self {
        let domain_directory = state_directory.join(domain);
        Self {
            legacy_manifest: state_directory.join(format!("{domain}.json")),
            index: domain_directory.join("index.json"),
            generations: domain_directory.join("generations"),
            domain_directory,
        }
    }

    #[must_use]
    pub fn for_instance(state_directory: &Path, instance: &InstanceName) -> Self {
        Self::new(state_directory, instance.as_str())
    }

    #[must_use]
    pub fn generation_path(&self, generation_id: &str) -> PathBuf {
        self.generations.join(format!("{generation_id}.json"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationEntry {
    pub generation_id: String,
    pub status: GenerationStatus,
    pub manifest_file: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationIndex {
    pub schema_version: u32,
    pub domain_name: String,
    pub domain_uuid: String,
    pub active_generation_id: String,
    pub generations: Vec<GenerationEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cleanup_progress: Vec<CleanupProgress>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupPhase {
    SeedDeletePending,
    OverlayDeletePending,
    IncompleteAfterSeed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupProgress {
    pub generation_id: String,
    pub phase: CleanupPhase,
    pub deleted_roles: Vec<ResourceRole>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagedState {
    Missing,
    Legacy(GenerationManifest),
    Current(GenerationIndex),
    Conflict(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedReconciliationStatus {
    Consistent,
    RecoveryRequired,
    Conflict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagedRecoveryReason {
    PreparingGenerationPresent {
        durable_active_generation_id: String,
        preparing_generation_id: String,
        observed_generation_id: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagedConflictReason {
    AmbiguousObservedGeneration { generation_ids: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedReconciliation {
    pub status: ManagedReconciliationStatus,
    pub observed_generation_id: Option<String>,
    pub recovery_reason: Option<ManagedRecoveryReason>,
    pub conflict_reason: Option<ManagedConflictReason>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationPlan {
    pub source: PathBuf,
    pub generation_manifest: PathBuf,
    pub index_path: PathBuf,
    pub index: GenerationIndex,
    pub mutation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedRebuildPlan {
    pub generation_id: String,
    pub overlay_name: String,
    pub seed_name: String,
    pub overlay_path: String,
    pub seed_path: String,
    pub initial_status: GenerationStatus,
    pub current_generation_id: String,
    pub steps: Vec<String>,
    pub recovery_boundaries: Vec<String>,
    pub mutation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct RecoveryObservability {
    pub domain_running: bool,
    pub ip_address: Option<String>,
    pub qga_channel: bool,
    pub qga_available: bool,
    pub ssh_host_identity_verified: bool,
    pub ssh_host_identity: Option<String>,
    pub ssh_authenticated: bool,
    pub cloud_init_done: bool,
    pub forge_user_confirmed: bool,
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedRecoveryPlan {
    pub active_generation_id: String,
    pub preparing_generation_id: String,
    pub source_index: GenerationIndex,
    pub source_manifests: Vec<GenerationManifest>,
    pub observed: ObservedGeneration,
    pub observability: RecoveryObservability,
    pub next_index: GenerationIndex,
    pub mutation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceEvidence {
    pub resource: ManagedResource,
    pub exists: bool,
    pub observed_resource: Option<ManagedResource>,
    pub referenced_by_domains: Vec<String>,
    pub backing_for_volumes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedEvidence {
    pub manifest: GenerationManifest,
    pub observed_pool_uuid: String,
    pub resources: Vec<ResourceEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedCleanupCandidate {
    pub generation_id: String,
    pub resources: Vec<ManagedResource>,
    pub proof: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedCleanupPlan {
    pub active_generation_id: String,
    pub retained_generation_ids: Vec<String>,
    pub unmanaged_legacy: Vec<String>,
    pub shared_protected: Vec<String>,
    pub candidates: Vec<ManagedCleanupCandidate>,
    pub refused: Vec<String>,
    pub already_cleaned_generation_ids: Vec<String>,
    pub source_index: GenerationIndex,
    pub source_evidence: Vec<RetainedEvidence>,
    pub source_reconciliation: ManagedReconciliationStatus,
    pub mutation: bool,
}

pub trait CleanupBackend {
    /// Revalidates the complete candidate immediately before mutation.
    /// # Errors
    /// Returns a fail-closed reason when identity or references changed.
    fn revalidate(
        &mut self,
        plan: &ManagedCleanupPlan,
        candidate: &ManagedCleanupCandidate,
    ) -> Result<(), String>;
    /// Atomically persists one crash-recovery checkpoint after comparing the current index
    /// with `expected`.
    /// # Errors
    /// Returns a fail-closed state-change or durable-write error.
    fn persist_index(
        &mut self,
        expected: &GenerationIndex,
        next: &GenerationIndex,
    ) -> Result<(), String>;
    /// Deletes the exact already-revalidated resource.
    /// # Errors
    /// Returns the backend deletion failure and stops the cleanup sequence.
    fn delete_exact(&mut self, resource: &ManagedResource) -> Result<(), String>;
    /// Proves through the storage API that the exact volume identity no longer exists.
    /// # Errors
    /// Returns an error if the volume still exists or absence cannot be established.
    fn verify_absent(&mut self, resource: &ManagedResource) -> Result<(), String>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupExecution {
    pub next_index: GenerationIndex,
    pub deleted: Vec<String>,
}

/// Revalidates once, deletes only the candidate's disposable resources, and
/// returns a new index only after every exact delete succeeds.
/// # Errors
/// Returns the first revalidation, deletion, or state-transition failure.
pub fn execute_cleanup_candidate<B: CleanupBackend>(
    backend: &mut B,
    plan: &ManagedCleanupPlan,
    candidate: &ManagedCleanupCandidate,
) -> Result<CleanupExecution, String> {
    backend.revalidate(plan, candidate)?;
    let seed = candidate
        .resources
        .iter()
        .find(|resource| resource.role == ResourceRole::NoCloudSeed)
        .ok_or_else(|| "cleanup candidate has no exact seed".to_owned())?;
    let overlay = candidate
        .resources
        .iter()
        .find(|resource| resource.role == ResourceRole::WritableOverlay)
        .ok_or_else(|| "cleanup candidate has no exact overlay".to_owned())?;
    if candidate.resources.len() != 2 {
        return Err("cleanup candidate must contain exactly seed and overlay".to_owned());
    }
    let mut current = begin_cleanup(&plan.source_index, &candidate.generation_id)
        .map_err(|error| error.to_string())?;
    backend.persist_index(&plan.source_index, &current)?;
    let mut deleted = Vec::new();
    if let Err(error) = backend.delete_exact(seed) {
        return Err(format!(
            "seed delete failed before any successful delete: {error}"
        ));
    }
    backend.verify_absent(seed)?;
    deleted.push(seed.path.clone());
    let seed_deleted = record_seed_deleted(&current, &candidate.generation_id)
        .map_err(|error| error.to_string())?;
    backend.persist_index(&current, &seed_deleted)?;
    current = seed_deleted;
    if let Err(error) = backend.delete_exact(overlay) {
        let incomplete = record_cleanup_incomplete(&current, &candidate.generation_id)
            .map_err(|state_error| state_error.to_string())?;
        backend.persist_index(&current, &incomplete)?;
        return Err(format!(
            "overlay delete failed after seed deletion; cleanup is incomplete: {error}"
        ));
    }
    backend.verify_absent(overlay)?;
    deleted.push(overlay.path.clone());
    let next_index =
        complete_cleanup(&current, &candidate.generation_id).map_err(|error| error.to_string())?;
    backend.persist_index(&current, &next_index)?;
    Ok(CleanupExecution {
        next_index,
        deleted,
    })
}

/// Detects the old single-manifest layout or the current index without changing either.
/// # Errors
/// Returns corrupt, unsupported, or I/O state errors.
pub fn inspect_layout(layout: &StateLayout) -> Result<ManagedState, StateError> {
    let legacy = read_manifest(&layout.legacy_manifest)?;
    let index = read_index(&layout.index)?;
    match (legacy, index) {
        (None, None) => Ok(ManagedState::Missing),
        (Some(manifest), None) => Ok(ManagedState::Legacy(manifest)),
        (_, Some(index)) => Ok(ManagedState::Current(index)),
    }
}

/// Classifies the complete durable generation index against persistent libvirt observation.
/// A published Preparing generation is always an explicit recovery boundary: observation alone
/// is not proof that first boot completed or that the atomic Active/Retained transition is safe.
#[must_use]
pub fn reconcile_managed(
    index: &GenerationIndex,
    manifests: &[GenerationManifest],
    observed: &ObservedGeneration,
) -> ManagedReconciliation {
    if let Err(error) = validate_index(index) {
        return ManagedReconciliation {
            status: ManagedReconciliationStatus::Conflict,
            observed_generation_id: None,
            recovery_reason: None,
            conflict_reason: None,
            detail: format!("invalid durable generation index: {error}"),
        };
    }
    let matching = manifests
        .iter()
        .filter(|manifest| generation_identity_matches(manifest, observed))
        .map(|manifest| manifest.generation_id.clone())
        .collect::<Vec<_>>();
    if matching.len() > 1 {
        return ManagedReconciliation {
            status: ManagedReconciliationStatus::Conflict,
            observed_generation_id: None,
            recovery_reason: None,
            conflict_reason: Some(ManagedConflictReason::AmbiguousObservedGeneration {
                generation_ids: matching,
            }),
            detail: "libvirt identities match more than one durable generation".to_owned(),
        };
    }
    let observed_generation_id = (matching.len() == 1).then(|| matching[0].clone());
    if let Some(preparing) = index
        .generations
        .iter()
        .find(|entry| entry.status == GenerationStatus::Preparing)
    {
        return ManagedReconciliation {
            status: ManagedReconciliationStatus::RecoveryRequired,
            observed_generation_id: observed_generation_id.clone(),
            recovery_reason: Some(ManagedRecoveryReason::PreparingGenerationPresent {
                durable_active_generation_id: index.active_generation_id.clone(),
                preparing_generation_id: preparing.generation_id.clone(),
                observed_generation_id,
            }),
            conflict_reason: None,
            detail: "durable Preparing generation requires recovery; libvirt attachment is not proof of successful first boot or authorization to finalize state".to_owned(),
        };
    }
    if matching.len() != 1 || matching[0] != index.active_generation_id {
        return ManagedReconciliation {
            status: ManagedReconciliationStatus::Conflict,
            observed_generation_id,
            recovery_reason: None,
            conflict_reason: None,
            detail: "observed libvirt generation does not uniquely match durable Active".to_owned(),
        };
    }
    ManagedReconciliation {
        status: ManagedReconciliationStatus::Consistent,
        observed_generation_id,
        recovery_reason: None,
        conflict_reason: None,
        detail: "observed libvirt generation uniquely matches durable Active".to_owned(),
    }
}

/// Builds a fail-closed recovery transition from one Active and one observed Preparing
/// generation. Every durable and libvirt identity and every guest health signal must match.
/// # Errors
/// Returns the first incomplete or ambiguous recovery prerequisite.
pub fn plan_managed_recovery(
    index: &GenerationIndex,
    manifests: &[GenerationManifest],
    observed: &ObservedGeneration,
    health: &RecoveryObservability,
) -> Result<ManagedRecoveryPlan, StateError> {
    validate_index(index)?;
    let active = index
        .generations
        .iter()
        .filter(|entry| entry.status == GenerationStatus::Active)
        .collect::<Vec<_>>();
    let preparing = index
        .generations
        .iter()
        .filter(|entry| entry.status == GenerationStatus::Preparing)
        .collect::<Vec<_>>();
    if active.len() != 1 || active[0].generation_id != index.active_generation_id {
        return recovery_refusal("exactly one durable Active generation is required");
    }
    if preparing.len() != 1 {
        return recovery_refusal("exactly one durable Preparing generation is required");
    }
    let preparing_id = &preparing[0].generation_id;
    let manifest = manifests
        .iter()
        .find(|manifest| manifest.generation_id == *preparing_id)
        .ok_or_else(|| {
            StateError::InvalidObservedState(
                "recovery refused: Preparing manifest is missing".into(),
            )
        })?;
    if manifests
        .iter()
        .filter(|candidate| candidate.generation_id == *preparing_id)
        .count()
        != 1
    {
        return recovery_refusal("Preparing manifest identity is ambiguous");
    }
    if !generation_identity_matches_exact(manifest, observed) {
        return recovery_refusal(
            "observed generation is not the exact durable Preparing generation",
        );
    }
    let reconciliation = reconcile_managed(index, manifests, observed);
    if reconciliation.status != ManagedReconciliationStatus::RecoveryRequired
        || reconciliation.observed_generation_id.as_deref() != Some(preparing_id)
    {
        return recovery_refusal("managed reconciliation does not uniquely observe Preparing");
    }
    validate_recovery_health(health)?;
    let next_index = finalize_switch(index, preparing_id)?;
    Ok(ManagedRecoveryPlan {
        active_generation_id: active[0].generation_id.clone(),
        preparing_generation_id: preparing_id.clone(),
        source_index: index.clone(),
        source_manifests: manifests.to_vec(),
        observed: observed.clone(),
        observability: health.clone(),
        next_index,
        mutation: false,
    })
}

/// Revalidates all state, libvirt identities, and guest health immediately before returning
/// the single next index value that can be atomically committed.
/// # Errors
/// Refuses when any input differs from the approved plan or no longer passes recovery planning.
pub fn execute_managed_recovery(
    plan: &ManagedRecoveryPlan,
    fresh_index: &GenerationIndex,
    manifests: &[GenerationManifest],
    fresh_observed: &ObservedGeneration,
    fresh_health: &RecoveryObservability,
) -> Result<GenerationIndex, StateError> {
    if fresh_index != &plan.source_index
        || manifests != plan.source_manifests
        || fresh_observed != &plan.observed
        || fresh_health != &plan.observability
    {
        return recovery_refusal("state, libvirt, or observability changed since planning");
    }
    let fresh_plan = plan_managed_recovery(fresh_index, manifests, fresh_observed, fresh_health)?;
    if fresh_plan.active_generation_id != plan.active_generation_id
        || fresh_plan.preparing_generation_id != plan.preparing_generation_id
        || fresh_plan.next_index != plan.next_index
    {
        return recovery_refusal("revalidated recovery transition differs from the plan");
    }
    Ok(fresh_plan.next_index)
}

fn validate_recovery_health(health: &RecoveryObservability) -> Result<(), StateError> {
    validate_recovery_evidence(
        &FirstBootSuccessPolicy::CloudInitManaged {
            expected_user: "forge".to_owned(),
            require_guest_agent: true,
        },
        &InstanceName::new("fedora-lab").expect("compatibility identity is valid"),
        health,
    )
}

/// Validates fresh guest evidence according to the selected profile policy.
/// Storage and domain identity checks remain mandatory in the surrounding recovery plan.
///
/// # Errors
///
/// Refuses incomplete evidence required by the selected success policy.
pub fn validate_recovery_evidence(
    policy: &FirstBootSuccessPolicy,
    instance: &InstanceName,
    health: &RecoveryObservability,
) -> Result<(), StateError> {
    if matches!(policy, FirstBootSuccessPolicy::ManualGuest) {
        return Ok(());
    }
    if !health.domain_running {
        return recovery_refusal("domain is not running");
    }
    if matches!(policy, FirstBootSuccessPolicy::BootOnly) {
        return Ok(());
    }
    if health.ip_address.is_none() {
        return recovery_refusal("typed IP discovery is incomplete");
    }
    let FirstBootSuccessPolicy::CloudInitManaged {
        expected_user,
        require_guest_agent,
    } = policy
    else {
        unreachable!("manual and boot-only policies returned above")
    };
    if *require_guest_agent && (!health.qga_channel || !health.qga_available) {
        return recovery_refusal("QGA channel and successful guest-ping are required");
    }
    if !health.ssh_host_identity_verified {
        return recovery_refusal("SSH host identity is not strictly verified");
    }
    if !health.ssh_authenticated {
        return recovery_refusal("SSH authentication as forge failed");
    }
    if !health.cloud_init_done {
        return recovery_refusal("cloud-init is not Done");
    }
    if !health.forge_user_confirmed {
        return recovery_refusal(&format!("expected user {expected_user} is not confirmed"));
    }
    if health.hostname.as_deref() != Some(instance.as_str()) {
        return recovery_refusal("guest hostname does not match the instance identity");
    }
    Ok(())
}

fn recovery_refusal<T>(reason: &str) -> Result<T, StateError> {
    Err(StateError::InvalidObservedState(format!(
        "recovery refused: {reason}"
    )))
}

fn generation_identity_matches_exact(
    manifest: &GenerationManifest,
    observed: &ObservedGeneration,
) -> bool {
    manifest.domain_name == observed.domain_name
        && manifest.domain_uuid == observed.domain_uuid
        && observed.domain_persistent
        && manifest.libvirt_uri == observed.libvirt_uri
        && manifest.storage_pool_name == observed.storage_pool_name
        && manifest.storage_pool_uuid == observed.storage_pool_uuid
        && matches!(manifest.resources.len(), 2 | 3)
        && manifest.resources.len() == observed.resources.len()
        && manifest
            .resources
            .iter()
            .any(|resource| resource.role == ResourceRole::SharedBase)
        && manifest
            .resources
            .iter()
            .any(|resource| resource.role == ResourceRole::WritableOverlay)
        && manifest.resources.iter().all(|expected| {
            observed.resources.iter().any(|actual| {
                expected.role == actual.role
                    && expected.volume_name == actual.volume_name
                    && expected.volume_key == actual.volume_key
                    && expected.path == actual.path
                    && expected.format == actual.format
                    && expected.capacity_bytes == actual.capacity_bytes
                    && expected.backing_path == actual.backing_path
            })
        })
}

fn generation_identity_matches(
    manifest: &GenerationManifest,
    observed: &ObservedGeneration,
) -> bool {
    if manifest.domain_uuid != observed.domain_uuid
        || manifest.storage_pool_uuid != observed.storage_pool_uuid
    {
        return false;
    }
    let expected_overlay = manifest
        .resources
        .iter()
        .find(|resource| resource.role == ResourceRole::WritableOverlay);
    let expected_seed = manifest
        .resources
        .iter()
        .find(|resource| resource.role == ResourceRole::NoCloudSeed);
    let actual_overlay = observed
        .resources
        .iter()
        .find(|resource| resource.role == ResourceRole::WritableOverlay);
    let actual_seed = observed
        .resources
        .iter()
        .find(|resource| resource.role == ResourceRole::NoCloudSeed);
    let overlay_matches = matches!(
        (expected_overlay, actual_overlay),
        (Some(expected), Some(actual))
            if expected.volume_key == actual.volume_key
                && expected.path == actual.path
                && expected.backing_path == actual.backing_path
    );
    let seed_matches = match (expected_seed, actual_seed) {
        (None, None) => true,
        (Some(expected), Some(actual)) => {
            expected.volume_key == actual.volume_key && expected.path == actual.path
        }
        _ => false,
    };
    overlay_matches && seed_matches
}

/// Publishes immutable Preparing ownership before the first domain definition.
///
/// # Errors
/// Refuses an existing index/manifest or a manifest that is not Preparing.
pub fn publish_initial_preparing(
    layout: &StateLayout,
    manifest: &GenerationManifest,
) -> Result<(), StateError> {
    if manifest.status != GenerationStatus::Preparing {
        return Err(StateError::InvalidObservedState(
            "initial generation manifest must be Preparing".to_owned(),
        ));
    }
    if layout.index.exists() || layout.generation_path(&manifest.generation_id).exists() {
        return Err(StateError::AlreadyExists(layout.domain_directory.clone()));
    }
    write_manifest_atomic(&layout.generation_path(&manifest.generation_id), manifest)
}

/// Atomically publishes the first Active index after exact domain/storage proof.
///
/// # Errors
/// Refuses mismatched observation, missing Preparing intent, or an existing index.
pub fn activate_initial_generation(
    layout: &StateLayout,
    manifest: &GenerationManifest,
    observed: &ObservedGeneration,
) -> Result<GenerationIndex, StateError> {
    if layout.index.exists()
        || read_manifest(&layout.generation_path(&manifest.generation_id))?.as_ref()
            != Some(manifest)
        || !generation_identity_matches_exact(manifest, observed)
    {
        return Err(StateError::InvalidObservedState(
            "initial activation identity or durable intent changed".to_owned(),
        ));
    }
    let index = GenerationIndex {
        schema_version: INDEX_SCHEMA_VERSION,
        domain_name: manifest.domain_name.clone(),
        domain_uuid: manifest.domain_uuid.clone(),
        active_generation_id: manifest.generation_id.clone(),
        generations: vec![GenerationEntry {
            generation_id: manifest.generation_id.clone(),
            status: GenerationStatus::Active,
            manifest_file: format!("generations/{}.json", manifest.generation_id),
        }],
        cleanup_progress: Vec::new(),
    };
    write_index_atomic(&layout.index, &index)?;
    Ok(index)
}

/// Plans a lossless migration. The legacy manifest remains as a recovery source.
/// # Errors
/// Rejects a non-active or malformed legacy manifest.
pub fn plan_migration(
    layout: &StateLayout,
    manifest: &GenerationManifest,
) -> Result<MigrationPlan, StateError> {
    if manifest.status != GenerationStatus::Active {
        return Err(StateError::InvalidObservedState(
            "legacy manifest is not Active".to_owned(),
        ));
    }
    let index = GenerationIndex {
        schema_version: INDEX_SCHEMA_VERSION,
        domain_name: manifest.domain_name.clone(),
        domain_uuid: manifest.domain_uuid.clone(),
        active_generation_id: manifest.generation_id.clone(),
        generations: vec![GenerationEntry {
            generation_id: manifest.generation_id.clone(),
            status: GenerationStatus::Active,
            manifest_file: format!("generations/{}.json", manifest.generation_id),
        }],
        cleanup_progress: Vec::new(),
    };
    validate_index(&index)?;
    Ok(MigrationPlan {
        source: layout.legacy_manifest.clone(),
        generation_manifest: layout.generation_path(&manifest.generation_id),
        index_path: layout.index.clone(),
        index,
        mutation: false,
    })
}

/// Writes the immutable generation first and publishes the index last.
/// # Errors
/// Refuses collisions and returns atomic state-write failures.
pub fn execute_migration(
    layout: &StateLayout,
    manifest: &GenerationManifest,
) -> Result<GenerationIndex, StateError> {
    let plan = plan_migration(layout, manifest)?;
    if layout.index.exists() {
        return Err(StateError::AlreadyExists(layout.index.clone()));
    }
    if plan.generation_manifest.exists() {
        if read_manifest(&plan.generation_manifest)?.as_ref() != Some(manifest) {
            return Err(StateError::AlreadyExists(plan.generation_manifest));
        }
    } else {
        write_manifest_atomic(&plan.generation_manifest, manifest)?;
    }
    write_index_atomic(&layout.index, &plan.index)?;
    Ok(plan.index)
}

/// Creates a random-ID, zero-mutation plan for the next owned generation.
/// # Errors
/// Rejects invalid indexes, IDs, or an unresolved Preparing generation.
pub fn plan_managed_rebuild(
    index: &GenerationIndex,
    pool_path: &str,
    generation_id: String,
) -> Result<ManagedRebuildPlan, StateError> {
    validate_index(index)?;
    if index
        .generations
        .iter()
        .any(|entry| entry.status == GenerationStatus::Preparing)
    {
        return Err(StateError::InvalidObservedState(
            "a Preparing generation already requires recovery".to_owned(),
        ));
    }
    let instance = InstanceName::new(&index.domain_name).map_err(|error| {
        StateError::InvalidObservedState(format!("invalid managed instance identity: {error}"))
    })?;
    let resources = plan_generation_resources(&instance, generation_id, true)?;
    let overlay_name = resources.overlay;
    let seed_name = resources.seed.ok_or_else(|| {
        StateError::InvalidObservedState("managed NoCloud rebuild requires a seed".to_owned())
    })?;
    Ok(ManagedRebuildPlan {
        generation_id: resources.generation_id,
        overlay_path: format!("{pool_path}/{overlay_name}"),
        seed_path: format!("{pool_path}/{seed_name}"),
        overlay_name,
        seed_name,
        initial_status: GenerationStatus::Preparing,
        current_generation_id: index.active_generation_id.clone(),
        steps: vec![
            "create and validate the new overlay and NoCloud seed".to_owned(),
            "record exact libvirt identities in an immutable Preparing manifest".to_owned(),
            "atomically publish Preparing in the generation index and reconcile".to_owned(),
            "gracefully shut down the current guest, then switch and verify persistent XML".to_owned(),
            "boot exactly once and complete typed DHCP/QGA/SSH/cloud-init observability".to_owned(),
            "atomically publish new Active and previous Active as Retained".to_owned(),
        ],
        recovery_boundaries: vec![
            "before switch: remove only new resources and mark the generation Failed".to_owned(),
            "after switch before final state: preserve both generations and report recovery conflict".to_owned(),
            "failed first boot: preserve the previous generation and never cleanup it".to_owned(),
        ],
        mutation: false,
    })
}

/// Produces exact generation-scoped names without inspecting or mutating libvirt.
///
/// # Errors
///
/// Refuses generation identities that are not Forge-prefixed UUID v4 values.
pub fn plan_generation_resources(
    instance: &InstanceName,
    generation_id: String,
    needs_seed: bool,
) -> Result<forge_core::GenerationResourceNames, StateError> {
    let token = generation_id.strip_prefix("gen-").ok_or_else(|| {
        StateError::InvalidObservedState("generation ID is not a Forge UUID v4 identity".to_owned())
    })?;
    let uuid = uuid::Uuid::parse_str(token)
        .map_err(|_| StateError::InvalidObservedState("generation ID is not a UUID".to_owned()))?;
    if uuid.get_version_num() != 4 {
        return Err(StateError::InvalidObservedState(
            "generation ID is not UUID v4".to_owned(),
        ));
    }
    let prefix = format!("{}-{token}", instance.as_str());
    Ok(forge_core::GenerationResourceNames {
        generation_id,
        overlay: format!("{prefix}.qcow2"),
        seed: needs_seed.then(|| format!("{prefix}-seed.iso")),
    })
}

/// Adds one Preparing generation without changing the current Active identity.
/// # Errors
/// Rejects identity conflicts, duplicate generations, and pending recovery.
pub fn add_preparing(
    index: &GenerationIndex,
    manifest: &GenerationManifest,
) -> Result<GenerationIndex, StateError> {
    validate_index(index)?;
    if manifest.status != GenerationStatus::Preparing || manifest.domain_uuid != index.domain_uuid {
        return Err(StateError::InvalidObservedState(
            "new generation identity/status does not match the index".to_owned(),
        ));
    }
    if index.generations.iter().any(|entry| {
        entry.generation_id == manifest.generation_id || entry.status == GenerationStatus::Preparing
    }) {
        return Err(StateError::InvalidObservedState(
            "generation already exists or recovery is pending".to_owned(),
        ));
    }
    let mut next = index.clone();
    next.generations.push(GenerationEntry {
        generation_id: manifest.generation_id.clone(),
        status: GenerationStatus::Preparing,
        manifest_file: format!("generations/{}.json", manifest.generation_id),
    });
    validate_index(&next)?;
    Ok(next)
}

#[must_use]
pub fn manifest_from_observed(
    observed: &ObservedGeneration,
    generation_id: String,
    status: GenerationStatus,
    created_unix_seconds: u64,
) -> GenerationManifest {
    GenerationManifest {
        schema_version: super::SCHEMA_VERSION,
        domain_name: observed.domain_name.clone(),
        domain_uuid: observed.domain_uuid.clone(),
        generation_id,
        created_unix_seconds,
        libvirt_uri: observed.libvirt_uri.clone(),
        storage_pool_name: observed.storage_pool_name.clone(),
        storage_pool_uuid: observed.storage_pool_uuid.clone(),
        status,
        resources: observed
            .resources
            .iter()
            .map(|resource| ManagedResource {
                role: resource.role,
                volume_name: resource.volume_name.clone(),
                volume_key: resource.volume_key.clone(),
                path: resource.path.clone(),
                format: resource.format.clone(),
                capacity_bytes: resource.capacity_bytes,
                backing_path: resource.backing_path.clone(),
            })
            .collect(),
    }
}

/// One index replacement commits both sides of the successful transition.
/// # Errors
/// Rejects missing or non-Preparing target generations and invalid indexes.
pub fn finalize_switch(
    index: &GenerationIndex,
    new_id: &str,
) -> Result<GenerationIndex, StateError> {
    validate_index(index)?;
    let mut next = index.clone();
    let old_id = next.active_generation_id.clone();
    let mut found_new = false;
    for entry in &mut next.generations {
        if entry.generation_id == old_id {
            entry.status = GenerationStatus::Retained;
        }
        if entry.generation_id == new_id {
            if entry.status != GenerationStatus::Preparing {
                return Err(StateError::InvalidObservedState(
                    "new generation is not Preparing".to_owned(),
                ));
            }
            entry.status = GenerationStatus::Active;
            found_new = true;
        }
    }
    if !found_new {
        return Err(StateError::InvalidObservedState(
            "Preparing generation is absent".to_owned(),
        ));
    }
    new_id.clone_into(&mut next.active_generation_id);
    validate_index(&next)?;
    Ok(next)
}

/// Marks a Preparing generation Failed while preserving the current Active.
/// # Errors
/// Rejects any non-Preparing target or an invalid index.
pub fn mark_failed(
    index: &GenerationIndex,
    generation_id: &str,
) -> Result<GenerationIndex, StateError> {
    validate_index(index)?;
    let mut next = index.clone();
    let entry = next
        .generations
        .iter_mut()
        .find(|entry| entry.generation_id == generation_id)
        .ok_or_else(|| {
            StateError::InvalidObservedState("Preparing generation is absent".to_owned())
        })?;
    if entry.status != GenerationStatus::Preparing {
        return Err(StateError::InvalidObservedState(
            "only Preparing generation can become Failed".to_owned(),
        ));
    }
    entry.status = GenerationStatus::Failed;
    validate_index(&next)?;
    Ok(next)
}

/// Validates the single-Active invariant and unique generation identities.
/// # Errors
/// Returns a typed schema or invariant failure.
pub fn validate_index(index: &GenerationIndex) -> Result<(), StateError> {
    if index.schema_version != INDEX_SCHEMA_VERSION {
        return Err(StateError::UnsupportedSchema(index.schema_version));
    }
    let active = index
        .generations
        .iter()
        .filter(|entry| entry.status == GenerationStatus::Active)
        .collect::<Vec<_>>();
    if active.len() != 1 || active[0].generation_id != index.active_generation_id {
        return Err(StateError::InvalidObservedState(
            "index must contain exactly one matching Active generation".to_owned(),
        ));
    }
    let ids = index
        .generations
        .iter()
        .map(|entry| &entry.generation_id)
        .collect::<BTreeSet<_>>();
    if ids.len() != index.generations.len() {
        return Err(StateError::InvalidObservedState(
            "duplicate generation ID".to_owned(),
        ));
    }
    let progress_ids = index
        .cleanup_progress
        .iter()
        .map(|progress| &progress.generation_id)
        .collect::<BTreeSet<_>>();
    if progress_ids.len() != index.cleanup_progress.len() {
        return Err(StateError::InvalidObservedState(
            "duplicate cleanup progress identity".to_owned(),
        ));
    }
    for progress in &index.cleanup_progress {
        let Some(entry) = index
            .generations
            .iter()
            .find(|entry| entry.generation_id == progress.generation_id)
        else {
            return Err(StateError::InvalidObservedState(
                "cleanup progress generation is absent".to_owned(),
            ));
        };
        if entry.status != GenerationStatus::Retained {
            return Err(StateError::InvalidObservedState(
                "cleanup progress is allowed only for Retained generation".to_owned(),
            ));
        }
        let expected_deleted = match progress.phase {
            CleanupPhase::SeedDeletePending => &[][..],
            CleanupPhase::OverlayDeletePending | CleanupPhase::IncompleteAfterSeed => {
                &[ResourceRole::NoCloudSeed][..]
            }
        };
        if progress.deleted_roles != expected_deleted {
            return Err(StateError::InvalidObservedState(
                "cleanup progress roles do not match its phase".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Publishes durable intent before the first irreversible delete.
/// # Errors
/// Refuses non-Retained, active, missing, or already-progressing generations.
pub fn begin_cleanup(
    index: &GenerationIndex,
    generation_id: &str,
) -> Result<GenerationIndex, StateError> {
    validate_index(index)?;
    let entry = index
        .generations
        .iter()
        .find(|entry| entry.generation_id == generation_id)
        .ok_or_else(|| StateError::InvalidObservedState("cleanup generation is absent".into()))?;
    if entry.status == GenerationStatus::Cleaned {
        return Err(StateError::InvalidObservedState(
            "generation is already Cleaned".into(),
        ));
    }
    if entry.status != GenerationStatus::Retained {
        return Err(StateError::InvalidObservedState(
            "cleanup requires a Retained generation".into(),
        ));
    }
    if index
        .cleanup_progress
        .iter()
        .any(|progress| progress.generation_id == generation_id)
    {
        return Err(StateError::InvalidObservedState(
            "generation already has durable cleanup progress".into(),
        ));
    }
    let mut next = index.clone();
    next.cleanup_progress.push(CleanupProgress {
        generation_id: generation_id.to_owned(),
        phase: CleanupPhase::SeedDeletePending,
        deleted_roles: Vec::new(),
    });
    validate_index(&next)?;
    Ok(next)
}

/// Records verified seed absence and authorizes only the overlay step.
/// # Errors
/// Refuses missing or unexpected cleanup progress.
pub fn record_seed_deleted(
    index: &GenerationIndex,
    generation_id: &str,
) -> Result<GenerationIndex, StateError> {
    let mut next = index.clone();
    let progress = next
        .cleanup_progress
        .iter_mut()
        .find(|progress| progress.generation_id == generation_id)
        .ok_or_else(|| StateError::InvalidObservedState("cleanup progress is absent".into()))?;
    if progress.phase != CleanupPhase::SeedDeletePending {
        return Err(StateError::InvalidObservedState(
            "seed delete is not the pending cleanup step".into(),
        ));
    }
    progress.phase = CleanupPhase::OverlayDeletePending;
    progress.deleted_roles = vec![ResourceRole::NoCloudSeed];
    validate_index(&next)?;
    Ok(next)
}

/// Records an irreversible partial result without attempting rollback.
/// # Errors
/// Refuses a failure outside the overlay step.
pub fn record_cleanup_incomplete(
    index: &GenerationIndex,
    generation_id: &str,
) -> Result<GenerationIndex, StateError> {
    let mut next = index.clone();
    let progress = next
        .cleanup_progress
        .iter_mut()
        .find(|progress| progress.generation_id == generation_id)
        .ok_or_else(|| StateError::InvalidObservedState("cleanup progress is absent".into()))?;
    if progress.phase != CleanupPhase::OverlayDeletePending {
        return Err(StateError::InvalidObservedState(
            "partial cleanup can be recorded only after seed deletion".into(),
        ));
    }
    progress.phase = CleanupPhase::IncompleteAfterSeed;
    validate_index(&next)?;
    Ok(next)
}

/// Marks a generation Cleaned only after both exact disposable resources were verified absent.
/// # Errors
/// Refuses incomplete progress and every status other than Retained.
pub fn complete_cleanup(
    index: &GenerationIndex,
    generation_id: &str,
) -> Result<GenerationIndex, StateError> {
    validate_index(index)?;
    let progress = index
        .cleanup_progress
        .iter()
        .find(|progress| progress.generation_id == generation_id)
        .ok_or_else(|| StateError::InvalidObservedState("cleanup progress is absent".into()))?;
    if progress.phase != CleanupPhase::OverlayDeletePending
        || progress.deleted_roles != [ResourceRole::NoCloudSeed]
    {
        return Err(StateError::InvalidObservedState(
            "cleanup is not ready for final completion".into(),
        ));
    }
    let mut next = index.clone();
    let entry = next
        .generations
        .iter_mut()
        .find(|entry| entry.generation_id == generation_id)
        .ok_or_else(|| StateError::InvalidObservedState("cleanup generation is absent".into()))?;
    if entry.status != GenerationStatus::Retained {
        return Err(StateError::InvalidObservedState(
            "only Retained generation can become Cleaned".into(),
        ));
    }
    entry.status = GenerationStatus::Cleaned;
    next.cleanup_progress
        .retain(|progress| progress.generation_id != generation_id);
    validate_index(&next)?;
    Ok(next)
}

/// Reads and validates an index; absence is not an error.
/// # Errors
/// Returns I/O, parse, schema, or invariant failures.
pub fn read_index(path: &Path) -> Result<Option<GenerationIndex>, StateError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let index: GenerationIndex = serde_json::from_slice(&bytes)
        .map_err(|error| StateError::CorruptManifest(error.to_string()))?;
    validate_index(&index)?;
    Ok(Some(index))
}

/// Atomically writes a validated index with private permissions.
/// # Errors
/// Returns validation, serialization, or durable-write failures.
pub fn write_index_atomic(path: &Path, index: &GenerationIndex) -> Result<(), StateError> {
    validate_index(index)?;
    let bytes = serde_json::to_vec_pretty(index)
        .map_err(|error| StateError::CorruptManifest(error.to_string()))?;
    atomic_bytes(path, &bytes)
}

fn atomic_bytes(path: &Path, bytes: &[u8]) -> Result<(), StateError> {
    use std::fs::{File, OpenOptions};
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let parent = path
        .parent()
        .ok_or_else(|| StateError::InvalidObservedState("state path has no parent".to_owned()))?;
    fs::create_dir_all(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(STATE_DIRECTORY_MODE))?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name().and_then(|v| v.to_str()).unwrap_or("state"),
        std::process::id()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(STATE_FILE_MODE)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.write_all(b"\n")?;
        file.flush()?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(STATE_FILE_MODE))?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

/// Plans exact deletion only for reconciled Retained resources. Shared base is always excluded.
/// Produces a zero-mutation cleanup plan from manifests and libvirt evidence.
/// # Errors
/// Rejects an invalid or ambiguous generation index.
#[allow(clippy::too_many_lines)]
pub fn plan_managed_cleanup(
    index: &GenerationIndex,
    evidence: &[RetainedEvidence],
    unmanaged: Vec<String>,
    reconciliation: ManagedReconciliationStatus,
) -> Result<ManagedCleanupPlan, StateError> {
    validate_index(index)?;
    if reconciliation != ManagedReconciliationStatus::Consistent {
        return Err(StateError::InvalidObservedState(
            "cleanup requires Consistent managed reconciliation".to_owned(),
        ));
    }
    if !index.cleanup_progress.is_empty() {
        return Err(StateError::InvalidObservedState(
            "cleanup progress requires explicit resume/recovery".to_owned(),
        ));
    }
    if index
        .generations
        .iter()
        .any(|entry| entry.status == GenerationStatus::Preparing)
    {
        return Err(StateError::InvalidObservedState(
            "cleanup is forbidden while a Preparing generation requires recovery".to_owned(),
        ));
    }
    let mut candidates = Vec::new();
    let mut refused = Vec::new();
    let retained_ids = index
        .generations
        .iter()
        .filter(|entry| entry.status == GenerationStatus::Retained)
        .map(|entry| entry.generation_id.clone())
        .collect::<Vec<_>>();
    let already_cleaned_generation_ids = index
        .generations
        .iter()
        .filter(|entry| entry.status == GenerationStatus::Cleaned)
        .map(|entry| entry.generation_id.clone())
        .collect::<Vec<_>>();
    let mut protected = BTreeSet::new();
    for generation in evidence {
        for resource in &generation.manifest.resources {
            if resource.role == ResourceRole::SharedBase {
                protected.insert(resource.path.clone());
            }
        }
        if generation.manifest.status != GenerationStatus::Retained
            || !retained_ids.contains(&generation.manifest.generation_id)
        {
            continue;
        }
        if generation.observed_pool_uuid != generation.manifest.storage_pool_uuid {
            refused.push(format!(
                "{}: storage pool UUID changed",
                generation.manifest.generation_id
            ));
            continue;
        }
        let disposable = generation
            .resources
            .iter()
            .filter(|item| item.resource.role != ResourceRole::SharedBase)
            .collect::<Vec<_>>();
        let safe = disposable.len() == 2
            && disposable.iter().all(|item| {
                item.exists
                    && item.observed_resource.as_ref() == Some(&item.resource)
                    && item.referenced_by_domains.is_empty()
                    && item.backing_for_volumes.is_empty()
            });
        if safe {
            let mut resources = disposable
                .iter()
                .map(|item| item.resource.clone())
                .collect::<Vec<_>>();
            resources.sort_by_key(|resource| match resource.role {
                ResourceRole::NoCloudSeed => 0,
                ResourceRole::WritableOverlay => 1,
                ResourceRole::SharedBase => 2,
            });
            candidates.push(ManagedCleanupCandidate {
                generation_id: generation.manifest.generation_id.clone(),
                resources,
                proof: vec![
                    "durable Retained manifest and index agree".to_owned(),
                    "exact libvirt key/path/format/capacity/backing metadata agree".to_owned(),
                    "no domain or volume references either disposable resource".to_owned(),
                ],
            });
        } else {
            refused.push(format!(
                "{}: drift, missing resource, or active/backing reference",
                generation.manifest.generation_id
            ));
        }
    }
    for id in &retained_ids {
        if !evidence
            .iter()
            .any(|item| &item.manifest.generation_id == id)
        {
            refused.push(format!("{id}: manifest/evidence missing"));
        }
    }
    Ok(ManagedCleanupPlan {
        active_generation_id: index.active_generation_id.clone(),
        retained_generation_ids: retained_ids,
        unmanaged_legacy: unmanaged,
        shared_protected: protected.into_iter().collect(),
        candidates,
        refused,
        already_cleaned_generation_ids,
        source_index: index.clone(),
        source_evidence: evidence.to_vec(),
        source_reconciliation: reconciliation,
        mutation: false,
    })
}

#[must_use]
pub fn reconcile_preparing(
    manifest: &GenerationManifest,
    observed: &ObservedGeneration,
) -> super::ReconciliationReport {
    let mut adjusted = observed.clone();
    for resource in &mut adjusted.resources {
        resource.referenced_by_domains.clear();
    }
    let mut manifest = manifest.clone();
    manifest.status = GenerationStatus::Preparing;
    reconcile_without_domain_references(&manifest, &adjusted)
}

fn reconcile_without_domain_references(
    manifest: &GenerationManifest,
    observed: &ObservedGeneration,
) -> super::ReconciliationReport {
    let mut report = reconcile(manifest, observed);
    report
        .issues
        .retain(|issue| !issue.field.ends_with("domain_reference"));
    report.status = if report
        .issues
        .iter()
        .any(|issue| issue.status == ReconciliationStatus::Conflict)
    {
        ReconciliationStatus::Conflict
    } else if report
        .issues
        .iter()
        .any(|issue| issue.status == ReconciliationStatus::Missing)
    {
        ReconciliationStatus::Missing
    } else if report
        .issues
        .iter()
        .any(|issue| issue.status == ReconciliationStatus::Drifted)
    {
        ReconciliationStatus::Drifted
    } else {
        ReconciliationStatus::Consistent
    };
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn typed_instances_have_isolated_backward_compatible_state_layouts() {
        let root = PathBuf::from("/state");
        let fedora = InstanceName::new("fedora-lab").unwrap();
        let test = InstanceName::new("fedora-lab-test").unwrap();
        let fedora_layout = StateLayout::for_instance(&root, &fedora);
        let test_layout = StateLayout::for_instance(&root, &test);
        assert_eq!(fedora_layout.domain_directory, root.join("fedora-lab"));
        assert_eq!(fedora_layout.index, root.join("fedora-lab/index.json"));
        assert_ne!(fedora_layout.domain_directory, test_layout.domain_directory);
        assert_ne!(fedora_layout.index, test_layout.index);
    }

    fn manifest(id: &str, status: GenerationStatus) -> GenerationManifest {
        GenerationManifest {
            schema_version: 1,
            domain_name: "fedora-lab".into(),
            domain_uuid: "du".into(),
            generation_id: id.into(),
            created_unix_seconds: 1,
            libvirt_uri: "qemu:///system".into(),
            storage_pool_name: "default".into(),
            storage_pool_uuid: "pu".into(),
            status,
            resources: vec![
                ManagedResource {
                    role: ResourceRole::SharedBase,
                    volume_name: "base".into(),
                    volume_key: "bk".into(),
                    path: "/p/base".into(),
                    format: "qcow2".into(),
                    capacity_bytes: 5,
                    backing_path: None,
                },
                ManagedResource {
                    role: ResourceRole::WritableOverlay,
                    volume_name: format!("{id}.qcow2"),
                    volume_key: format!("{id}-ok"),
                    path: format!("/p/{id}.qcow2"),
                    format: "qcow2".into(),
                    capacity_bytes: 64,
                    backing_path: Some("/p/base".into()),
                },
                ManagedResource {
                    role: ResourceRole::NoCloudSeed,
                    volume_name: format!("{id}.iso"),
                    volume_key: format!("{id}-sk"),
                    path: format!("/p/{id}.iso"),
                    format: "raw".into(),
                    capacity_bytes: 1,
                    backing_path: None,
                },
            ],
        }
    }
    fn index() -> GenerationIndex {
        GenerationIndex {
            schema_version: 1,
            domain_name: "fedora-lab".into(),
            domain_uuid: "du".into(),
            active_generation_id: "old".into(),
            generations: vec![GenerationEntry {
                generation_id: "old".into(),
                status: GenerationStatus::Active,
                manifest_file: "generations/old.json".into(),
            }],
            cleanup_progress: Vec::new(),
        }
    }
    fn observed(id: &str) -> ObservedGeneration {
        let manifest = manifest(id, GenerationStatus::Preparing);
        ObservedGeneration {
            domain_name: manifest.domain_name,
            domain_uuid: manifest.domain_uuid,
            domain_persistent: true,
            libvirt_uri: manifest.libvirt_uri,
            storage_pool_name: manifest.storage_pool_name,
            storage_pool_uuid: manifest.storage_pool_uuid,
            resources: manifest
                .resources
                .into_iter()
                .map(|resource| super::super::ObservedResource {
                    role: resource.role,
                    volume_name: resource.volume_name,
                    volume_key: resource.volume_key,
                    path: resource.path,
                    format: resource.format,
                    capacity_bytes: resource.capacity_bytes,
                    backing_path: resource.backing_path,
                    referenced_by_domains: vec!["fedora-lab".into()],
                    backing_for_volumes: Vec::new(),
                })
                .collect(),
            unmanaged_resources: Vec::new(),
        }
    }
    fn recovery_index() -> GenerationIndex {
        GenerationIndex {
            schema_version: 1,
            domain_name: "fedora-lab".into(),
            domain_uuid: "du".into(),
            active_generation_id: "a".into(),
            generations: vec![
                GenerationEntry {
                    generation_id: "a".into(),
                    status: GenerationStatus::Active,
                    manifest_file: "generations/a.json".into(),
                },
                GenerationEntry {
                    generation_id: "b".into(),
                    status: GenerationStatus::Failed,
                    manifest_file: "generations/b.json".into(),
                },
                GenerationEntry {
                    generation_id: "c".into(),
                    status: GenerationStatus::Preparing,
                    manifest_file: "generations/c.json".into(),
                },
            ],
            cleanup_progress: Vec::new(),
        }
    }
    fn recovery_manifests() -> Vec<GenerationManifest> {
        vec![
            manifest("a", GenerationStatus::Active),
            manifest("b", GenerationStatus::Failed),
            manifest("c", GenerationStatus::Preparing),
        ]
    }
    fn healthy_recovery() -> RecoveryObservability {
        RecoveryObservability {
            domain_running: true,
            ip_address: Some("192.0.2.10".into()),
            qga_channel: true,
            qga_available: true,
            ssh_host_identity_verified: true,
            ssh_host_identity: Some("192.0.2.10 ssh-ed25519 test-key".into()),
            ssh_authenticated: true,
            cloud_init_done: true,
            forge_user_confirmed: true,
            hostname: Some("fedora-lab".into()),
        }
    }
    fn temp() -> PathBuf {
        std::env::temp_dir().join(format!(
            "forge-managed-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn migration_preserves_active_ownership() {
        let root = temp();
        fs::create_dir_all(&root).unwrap();
        let layout = StateLayout::new(&root, "fedora-lab");
        let old = manifest("old", GenerationStatus::Active);
        write_manifest_atomic(&layout.legacy_manifest, &old).unwrap();
        let migrated = execute_migration(&layout, &old).unwrap();
        assert_eq!(migrated.active_generation_id, "old");
        assert!(layout.legacy_manifest.exists());
        assert!(layout.generation_path("old").exists());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn migration_resumes_after_generation_write_before_index_publish() {
        let root = temp();
        fs::create_dir_all(&root).unwrap();
        let layout = StateLayout::new(&root, "fedora-lab");
        let old = manifest("old", GenerationStatus::Active);
        write_manifest_atomic(&layout.legacy_manifest, &old).unwrap();
        write_manifest_atomic(&layout.generation_path("old"), &old).unwrap();
        assert_eq!(
            execute_migration(&layout, &old)
                .unwrap()
                .active_generation_id,
            "old"
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn generation_starts_preparing() {
        let id = super::super::new_generation_id();
        let plan = plan_managed_rebuild(&index(), "/p", id).unwrap();
        assert_eq!(plan.initial_status, GenerationStatus::Preparing);
        assert!(!plan.mutation);
    }
    #[test]
    fn successful_transition_is_single_atomic_index_value() {
        let mut current = index();
        current = add_preparing(&current, &manifest("new", GenerationStatus::Preparing)).unwrap();
        let next = finalize_switch(&current, "new").unwrap();
        assert_eq!(next.active_generation_id, "new");
        assert_eq!(
            next.generations
                .iter()
                .filter(|e| e.status == GenerationStatus::Active)
                .count(),
            1
        );
        assert_eq!(next.generations[0].status, GenerationStatus::Retained);
    }
    #[test]
    fn recovery_plan_accepts_active_and_observed_preparing() {
        let plan = plan_managed_recovery(
            &recovery_index(),
            &recovery_manifests(),
            &observed("c"),
            &healthy_recovery(),
        )
        .unwrap();
        assert_eq!(plan.active_generation_id, "a");
        assert_eq!(plan.preparing_generation_id, "c");
        assert!(!plan.mutation);
    }
    #[test]
    fn recovery_refuses_observed_active_or_unknown() {
        let index = recovery_index();
        let manifests = recovery_manifests();
        assert!(
            plan_managed_recovery(&index, &manifests, &observed("a"), &healthy_recovery()).is_err()
        );
        assert!(
            plan_managed_recovery(
                &index,
                &manifests,
                &observed("unknown"),
                &healthy_recovery()
            )
            .is_err()
        );
    }
    #[test]
    fn recovery_refuses_incomplete_guest_observability() {
        let index = recovery_index();
        let manifests = recovery_manifests();
        let actual = observed("c");
        for unhealthy in [
            RecoveryObservability {
                qga_available: false,
                ..healthy_recovery()
            },
            RecoveryObservability {
                ssh_authenticated: false,
                ..healthy_recovery()
            },
            RecoveryObservability {
                ssh_host_identity_verified: false,
                ..healthy_recovery()
            },
            RecoveryObservability {
                cloud_init_done: false,
                ..healthy_recovery()
            },
            RecoveryObservability {
                forge_user_confirmed: false,
                ..healthy_recovery()
            },
            RecoveryObservability {
                hostname: Some("wrong".into()),
                ..healthy_recovery()
            },
        ] {
            assert!(plan_managed_recovery(&index, &manifests, &actual, &unhealthy).is_err());
        }
    }
    #[test]
    fn recovery_refuses_wrong_domain_pool_or_volume_identity() {
        let index = recovery_index();
        let manifests = recovery_manifests();
        let mut wrong_domain = observed("c");
        wrong_domain.domain_uuid = "wrong".into();
        let mut wrong_pool = observed("c");
        wrong_pool.storage_pool_uuid = "wrong".into();
        let mut wrong_volume = observed("c");
        wrong_volume.resources[1].volume_key = "wrong".into();
        for actual in [wrong_domain, wrong_pool, wrong_volume] {
            assert!(
                plan_managed_recovery(&index, &manifests, &actual, &healthy_recovery()).is_err()
            );
        }
    }
    #[test]
    fn recovery_transition_is_atomic_single_active_and_preserves_failed() {
        let index = recovery_index();
        let manifests = recovery_manifests();
        let actual = observed("c");
        let health = healthy_recovery();
        let plan = plan_managed_recovery(&index, &manifests, &actual, &health).unwrap();
        let next = execute_managed_recovery(&plan, &index, &manifests, &actual, &health).unwrap();
        assert_eq!(next.active_generation_id, "c");
        assert_eq!(
            next.generations
                .iter()
                .filter(|entry| entry.status == GenerationStatus::Active)
                .count(),
            1
        );
        assert_eq!(next.generations[0].status, GenerationStatus::Retained);
        assert_eq!(next.generations[1].status, GenerationStatus::Failed);
        assert_eq!(next.generations[2].status, GenerationStatus::Active);
        assert_eq!(index.generations[0].status, GenerationStatus::Active);
        assert_eq!(index.generations[2].status, GenerationStatus::Preparing);
    }
    #[test]
    fn recovery_execute_refuses_changed_revalidation() {
        let index = recovery_index();
        let manifests = recovery_manifests();
        let actual = observed("c");
        let health = healthy_recovery();
        let plan = plan_managed_recovery(&index, &manifests, &actual, &health).unwrap();
        let mut changed = actual.clone();
        changed.resources[1].volume_key = "changed".into();
        assert!(execute_managed_recovery(&plan, &index, &manifests, &changed, &health).is_err());
    }
    #[test]
    fn two_active_is_rejected() {
        let mut value = index();
        value.generations.push(GenerationEntry {
            generation_id: "new".into(),
            status: GenerationStatus::Active,
            manifest_file: "x".into(),
        });
        assert!(validate_index(&value).is_err());
    }
    #[test]
    fn interruption_before_switch_leaves_old_active_and_new_preparing() {
        let next = add_preparing(&index(), &manifest("new", GenerationStatus::Preparing)).unwrap();
        assert_eq!(next.active_generation_id, "old");
        assert_eq!(next.generations[1].status, GenerationStatus::Preparing);
    }
    #[test]
    fn interruption_after_switch_is_detectable_not_auto_finalized() {
        let next = add_preparing(&index(), &manifest("new", GenerationStatus::Preparing)).unwrap();
        let report = reconcile_managed(
            &next,
            &[
                manifest("old", GenerationStatus::Active),
                manifest("new", GenerationStatus::Preparing),
            ],
            &observed("new"),
        );
        assert_eq!(report.status, ManagedReconciliationStatus::RecoveryRequired);
        assert_eq!(report.observed_generation_id.as_deref(), Some("new"));
        assert_eq!(next.active_generation_id, "old");
        assert!(matches!(
            report.recovery_reason,
            Some(ManagedRecoveryReason::PreparingGenerationPresent {
                durable_active_generation_id,
                preparing_generation_id,
                observed_generation_id: Some(observed_generation_id),
            }) if durable_active_generation_id == "old"
                && preparing_generation_id == "new"
                && observed_generation_id == "new"
        ));
    }
    #[test]
    fn successful_first_boot_before_final_state_write_still_requires_recovery() {
        let next = add_preparing(&index(), &manifest("new", GenerationStatus::Preparing)).unwrap();
        let report = reconcile_managed(
            &next,
            &[
                manifest("old", GenerationStatus::Active),
                manifest("new", GenerationStatus::Preparing),
            ],
            &observed("new"),
        );
        assert_eq!(report.status, ManagedReconciliationStatus::RecoveryRequired);
        assert_eq!(next.generations[0].status, GenerationStatus::Active);
        assert_eq!(next.generations[1].status, GenerationStatus::Preparing);
    }
    #[test]
    fn observed_generation_uses_exact_libvirt_identities_not_names_or_shape() {
        let next = add_preparing(&index(), &manifest("new", GenerationStatus::Preparing)).unwrap();
        let mut actual = observed("new");
        actual.domain_name = "renamed-display-value".into();
        actual.storage_pool_name = "renamed-pool-display-value".into();
        for resource in &mut actual.resources {
            resource.volume_name = "not-used-for-identity".into();
            resource.format = "different-observed-format".into();
            resource.capacity_bytes = 999;
        }
        let report = reconcile_managed(
            &next,
            &[
                manifest("old", GenerationStatus::Active),
                manifest("new", GenerationStatus::Preparing),
            ],
            &actual,
        );
        assert_eq!(report.status, ManagedReconciliationStatus::RecoveryRequired);
        assert_eq!(report.observed_generation_id.as_deref(), Some("new"));
    }
    #[test]
    fn duplicate_exact_libvirt_identities_are_a_typed_conflict() {
        let next = add_preparing(&index(), &manifest("new", GenerationStatus::Preparing)).unwrap();
        let new = manifest("new", GenerationStatus::Preparing);
        let mut duplicate = new.clone();
        duplicate.generation_id = "old".into();
        duplicate.status = GenerationStatus::Active;
        let report = reconcile_managed(&next, &[duplicate, new], &observed("new"));
        assert_eq!(report.status, ManagedReconciliationStatus::Conflict);
        assert_eq!(report.observed_generation_id, None);
        assert!(matches!(
            report.conflict_reason,
            Some(ManagedConflictReason::AmbiguousObservedGeneration { generation_ids })
                if generation_ids == ["old", "new"]
        ));
    }
    #[test]
    fn recovery_boundary_forbids_cleanup_of_every_generation() {
        let mut recovery_index = retained_index();
        recovery_index.generations.push(GenerationEntry {
            generation_id: "pending".into(),
            status: GenerationStatus::Preparing,
            manifest_file: "pending".into(),
        });
        assert!(
            plan_managed_cleanup(
                &recovery_index,
                &[evidence(GenerationStatus::Retained, false)],
                vec![],
                ManagedReconciliationStatus::Consistent,
            )
            .is_err()
        );
    }
    #[test]
    fn failed_pre_switch_generation_preserves_single_active() {
        let next = add_preparing(&index(), &manifest("new", GenerationStatus::Preparing)).unwrap();
        let failed = mark_failed(&next, "new").unwrap();
        assert_eq!(failed.active_generation_id, "old");
        assert_eq!(failed.generations[1].status, GenerationStatus::Failed);
    }
    fn evidence(status: GenerationStatus, refs: bool) -> RetainedEvidence {
        let m = manifest("old", status);
        let resources = m
            .resources
            .iter()
            .cloned()
            .map(|resource| ResourceEvidence {
                observed_resource: Some(resource.clone()),
                resource,
                exists: true,
                referenced_by_domains: if refs { vec!["other".into()] } else { vec![] },
                backing_for_volumes: vec![],
            })
            .collect();
        RetainedEvidence {
            manifest: m,
            observed_pool_uuid: "pu".into(),
            resources,
        }
    }
    fn retained_index() -> GenerationIndex {
        GenerationIndex {
            schema_version: 1,
            domain_name: "fedora-lab".into(),
            domain_uuid: "du".into(),
            active_generation_id: "new".into(),
            generations: vec![
                GenerationEntry {
                    generation_id: "old".into(),
                    status: GenerationStatus::Retained,
                    manifest_file: "old".into(),
                },
                GenerationEntry {
                    generation_id: "new".into(),
                    status: GenerationStatus::Active,
                    manifest_file: "new".into(),
                },
            ],
            cleanup_progress: Vec::new(),
        }
    }
    #[test]
    fn retained_owned_is_candidate_but_shared_base_is_not() {
        let plan = plan_managed_cleanup(
            &retained_index(),
            &[evidence(GenerationStatus::Retained, false)],
            vec![],
            ManagedReconciliationStatus::Consistent,
        )
        .unwrap();
        assert_eq!(plan.candidates.len(), 1);
        assert!(
            plan.candidates[0]
                .resources
                .iter()
                .all(|r| r.role != ResourceRole::SharedBase)
        );
    }
    #[test]
    fn active_generation_is_never_candidate() {
        let plan = plan_managed_cleanup(
            &index(),
            &[evidence(GenerationStatus::Active, false)],
            vec![],
            ManagedReconciliationStatus::Consistent,
        )
        .unwrap();
        assert!(plan.candidates.is_empty());
    }
    #[test]
    fn unmanaged_legacy_is_never_candidate() {
        let plan = plan_managed_cleanup(
            &index(),
            &[],
            vec!["legacy".into()],
            ManagedReconciliationStatus::Consistent,
        )
        .unwrap();
        assert_eq!(plan.unmanaged_legacy, ["legacy"]);
        assert!(plan.candidates.is_empty());
    }
    #[test]
    fn drift_or_reference_blocks_cleanup() {
        let plan = plan_managed_cleanup(
            &retained_index(),
            &[evidence(GenerationStatus::Retained, true)],
            vec![],
            ManagedReconciliationStatus::Consistent,
        )
        .unwrap();
        assert!(plan.candidates.is_empty());
        assert!(!plan.refused.is_empty());
    }
    #[test]
    fn cleanup_dry_run_has_zero_mutation() {
        let plan = plan_managed_cleanup(
            &retained_index(),
            &[evidence(GenerationStatus::Retained, false)],
            vec![],
            ManagedReconciliationStatus::Consistent,
        )
        .unwrap();
        assert!(!plan.mutation);
    }
    #[test]
    fn cleanup_refuses_non_retained_and_reports_unmanaged_without_candidates() {
        let active = plan_managed_cleanup(
            &index(),
            &[evidence(GenerationStatus::Active, false)],
            vec![],
            ManagedReconciliationStatus::Consistent,
        )
        .unwrap();
        assert!(active.candidates.is_empty());

        let mut preparing = retained_index();
        preparing.generations[0].status = GenerationStatus::Preparing;
        assert!(
            plan_managed_cleanup(
                &preparing,
                &[evidence(GenerationStatus::Preparing, false)],
                vec![],
                ManagedReconciliationStatus::RecoveryRequired,
            )
            .is_err()
        );

        let mut failed = retained_index();
        failed.generations[0].status = GenerationStatus::Failed;
        let failed_plan = plan_managed_cleanup(
            &failed,
            &[evidence(GenerationStatus::Failed, false)],
            vec![],
            ManagedReconciliationStatus::Consistent,
        )
        .unwrap();
        assert!(failed_plan.candidates.is_empty());

        let unmanaged = plan_managed_cleanup(
            &index(),
            &[],
            vec!["/unmanaged".into()],
            ManagedReconciliationStatus::Consistent,
        )
        .unwrap();
        assert_eq!(unmanaged.unmanaged_legacy, ["/unmanaged"]);
        assert!(unmanaged.candidates.is_empty());
    }
    #[test]
    fn cleanup_refuses_wrong_pool_and_every_volume_identity_field() {
        let mut wrong_pool = evidence(GenerationStatus::Retained, false);
        wrong_pool.observed_pool_uuid = "wrong".into();
        let pool_plan = plan_managed_cleanup(
            &retained_index(),
            &[wrong_pool],
            vec![],
            ManagedReconciliationStatus::Consistent,
        )
        .unwrap();
        assert!(pool_plan.candidates.is_empty());

        for mutate in [
            |resource: &mut ManagedResource| resource.volume_key = "wrong".into(),
            |resource: &mut ManagedResource| resource.path = "/wrong".into(),
            |resource: &mut ManagedResource| resource.format = "wrong".into(),
            |resource: &mut ManagedResource| resource.capacity_bytes += 1,
            |resource: &mut ManagedResource| resource.backing_path = Some("/wrong".into()),
        ] {
            let mut wrong = evidence(GenerationStatus::Retained, false);
            let observed = wrong.resources[1].observed_resource.as_mut().unwrap();
            mutate(observed);
            let plan = plan_managed_cleanup(
                &retained_index(),
                &[wrong],
                vec![],
                ManagedReconciliationStatus::Consistent,
            )
            .unwrap();
            assert!(plan.candidates.is_empty());
            assert!(!plan.refused.is_empty());
        }
    }
    #[test]
    fn cleanup_refuses_cross_domain_and_backing_references() {
        let mut domain_reference = evidence(GenerationStatus::Retained, false);
        domain_reference.resources[1].referenced_by_domains = vec!["other-domain".into()];
        let mut backing_reference = evidence(GenerationStatus::Retained, false);
        backing_reference.resources[1].backing_for_volumes = vec!["dependent.qcow2".into()];
        for unsafe_evidence in [domain_reference, backing_reference] {
            let plan = plan_managed_cleanup(
                &retained_index(),
                &[unsafe_evidence],
                vec![],
                ManagedReconciliationStatus::Consistent,
            )
            .unwrap();
            assert!(plan.candidates.is_empty());
        }
    }
    #[test]
    fn cleanup_requires_consistent_reconciliation() {
        assert!(
            plan_managed_cleanup(
                &retained_index(),
                &[evidence(GenerationStatus::Retained, false)],
                vec![],
                ManagedReconciliationStatus::Conflict,
            )
            .is_err()
        );
    }
    #[test]
    fn cleaned_generation_is_typed_idempotent_zero_mutation() {
        let mut cleaned = retained_index();
        cleaned.generations[0].status = GenerationStatus::Cleaned;
        let plan = plan_managed_cleanup(
            &cleaned,
            &[],
            vec![],
            ManagedReconciliationStatus::Consistent,
        )
        .unwrap();
        assert!(plan.candidates.is_empty());
        assert_eq!(plan.already_cleaned_generation_ids, ["old"]);
        assert!(begin_cleanup(&cleaned, "old").is_err());
    }
    #[test]
    fn index_atomic_write_has_private_permissions() {
        let root = temp();
        let layout = StateLayout::new(&root, "fedora-lab");
        write_index_atomic(&layout.index, &index()).unwrap();
        assert_eq!(
            fs::metadata(&layout.domain_directory)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&layout.index).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::remove_dir_all(root).unwrap();
    }
    struct CleanupMock {
        revalidated: bool,
        durable: GenerationIndex,
        deletes: Vec<ResourceRole>,
        existing: Vec<ResourceRole>,
        fail_at: Option<usize>,
        revalidation_fails: bool,
    }
    impl CleanupBackend for CleanupMock {
        fn revalidate(
            &mut self,
            _: &ManagedCleanupPlan,
            _: &ManagedCleanupCandidate,
        ) -> Result<(), String> {
            self.revalidated = true;
            if self.revalidation_fails {
                Err("snapshot changed".into())
            } else {
                Ok(())
            }
        }
        fn persist_index(
            &mut self,
            expected: &GenerationIndex,
            next: &GenerationIndex,
        ) -> Result<(), String> {
            if &self.durable != expected {
                return Err("durable index changed".into());
            }
            self.durable = next.clone();
            Ok(())
        }
        fn delete_exact(&mut self, resource: &ManagedResource) -> Result<(), String> {
            self.deletes.push(resource.role);
            if self.fail_at == Some(self.deletes.len()) {
                Err("delete failed".into())
            } else {
                self.existing.retain(|role| role != &resource.role);
                Ok(())
            }
        }
        fn verify_absent(&mut self, resource: &ManagedResource) -> Result<(), String> {
            if self.existing.contains(&resource.role) {
                Err("resource still exists".into())
            } else {
                Ok(())
            }
        }
    }
    #[test]
    fn cleanup_revalidates_before_delete_and_updates_state_after_success() {
        let plan = plan_managed_cleanup(
            &retained_index(),
            &[evidence(GenerationStatus::Retained, false)],
            vec![],
            ManagedReconciliationStatus::Consistent,
        )
        .unwrap();
        let mut backend = CleanupMock {
            revalidated: false,
            durable: retained_index(),
            deletes: Vec::new(),
            existing: vec![
                ResourceRole::SharedBase,
                ResourceRole::WritableOverlay,
                ResourceRole::NoCloudSeed,
            ],
            fail_at: None,
            revalidation_fails: false,
        };
        let result = execute_cleanup_candidate(&mut backend, &plan, &plan.candidates[0]).unwrap();
        assert!(backend.revalidated);
        assert_eq!(
            backend.deletes,
            [ResourceRole::NoCloudSeed, ResourceRole::WritableOverlay]
        );
        assert_eq!(backend.existing, [ResourceRole::SharedBase]);
        assert!(
            result
                .next_index
                .generations
                .iter()
                .any(|e| e.generation_id == "old" && e.status == GenerationStatus::Cleaned)
        );
    }
    #[test]
    fn partial_delete_failure_stops_and_does_not_produce_state_update() {
        let plan = plan_managed_cleanup(
            &retained_index(),
            &[evidence(GenerationStatus::Retained, false)],
            vec![],
            ManagedReconciliationStatus::Consistent,
        )
        .unwrap();
        let mut backend = CleanupMock {
            revalidated: false,
            durable: retained_index(),
            deletes: Vec::new(),
            existing: vec![
                ResourceRole::SharedBase,
                ResourceRole::WritableOverlay,
                ResourceRole::NoCloudSeed,
            ],
            fail_at: Some(2),
            revalidation_fails: false,
        };
        assert!(execute_cleanup_candidate(&mut backend, &plan, &plan.candidates[0]).is_err());
        assert_eq!(backend.deletes.len(), 2);
        assert_eq!(
            backend.durable.cleanup_progress[0].phase,
            CleanupPhase::IncompleteAfterSeed
        );
        assert_eq!(
            backend.durable.cleanup_progress[0].deleted_roles,
            [ResourceRole::NoCloudSeed]
        );
        assert_eq!(
            backend.durable.generations[0].status,
            GenerationStatus::Retained
        );
        assert!(!backend.existing.contains(&ResourceRole::NoCloudSeed));
        assert!(backend.existing.contains(&ResourceRole::WritableOverlay));
        assert!(backend.existing.contains(&ResourceRole::SharedBase));
    }
    #[test]
    fn cleanup_toctou_refusal_happens_before_delete() {
        let plan = plan_managed_cleanup(
            &retained_index(),
            &[evidence(GenerationStatus::Retained, false)],
            vec![],
            ManagedReconciliationStatus::Consistent,
        )
        .unwrap();
        let mut backend = CleanupMock {
            revalidated: false,
            durable: retained_index(),
            deletes: Vec::new(),
            existing: vec![
                ResourceRole::SharedBase,
                ResourceRole::WritableOverlay,
                ResourceRole::NoCloudSeed,
            ],
            fail_at: None,
            revalidation_fails: true,
        };
        assert!(execute_cleanup_candidate(&mut backend, &plan, &plan.candidates[0]).is_err());
        assert!(backend.deletes.is_empty());
        assert!(backend.durable.cleanup_progress.is_empty());
    }

    #[test]
    fn generation_resource_names_use_instance_identity_and_optional_role() {
        let id = "gen-123e4567-e89b-42d3-a456-426614174000".to_owned();
        let first =
            plan_generation_resources(&InstanceName::new("factory-one").unwrap(), id.clone(), true)
                .unwrap();
        let second =
            plan_generation_resources(&InstanceName::new("factory-two").unwrap(), id, false)
                .unwrap();
        assert!(first.overlay.starts_with("factory-one-"));
        assert!(first.seed.unwrap().starts_with("factory-one-"));
        assert!(second.overlay.starts_with("factory-two-"));
        assert!(second.seed.is_none());
    }

    #[test]
    fn recovery_guest_evidence_is_selected_by_profile_policy() {
        let instance = InstanceName::new("manual-one").unwrap();
        let empty = RecoveryObservability {
            domain_running: false,
            ip_address: None,
            qga_channel: false,
            qga_available: false,
            ssh_host_identity_verified: false,
            ssh_host_identity: None,
            ssh_authenticated: false,
            cloud_init_done: false,
            forge_user_confirmed: false,
            hostname: None,
        };
        assert!(
            validate_recovery_evidence(&FirstBootSuccessPolicy::ManualGuest, &instance, &empty)
                .is_ok()
        );
        assert!(
            validate_recovery_evidence(&FirstBootSuccessPolicy::BootOnly, &instance, &empty)
                .is_err()
        );
        assert!(
            validate_recovery_evidence(
                &FirstBootSuccessPolicy::CloudInitManaged {
                    expected_user: "forge".to_owned(),
                    require_guest_agent: true,
                },
                &instance,
                &empty
            )
            .is_err()
        );
    }
}
