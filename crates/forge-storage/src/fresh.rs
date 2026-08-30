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
    FedoraNoCloudDeferred,
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
            FreshCapability::Unsupported(FreshUnsupportedReason::FedoraNoCloudDeferred)
        }
        _ => FreshCapability::Unsupported(FreshUnsupportedReason::ProfilePolicyUnsupported),
    }
}

fn storage_matches(active: &GenerationManifest, observed: &ObservedGeneration) -> bool {
    active.domain_name == observed.domain_name
        && active.domain_uuid == observed.domain_uuid
        && active.libvirt_uri == observed.libvirt_uri
        && active.storage_pool_name == observed.storage_pool_name
        && active.storage_pool_uuid == observed.storage_pool_uuid
        && active.resources.len() == observed.resources.len()
        && active.resources.iter().all(|expected| {
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
        || active.status != forge_state::GenerationStatus::Active
        || active.domain_name != input.instance.as_str()
        || !storage_matches(active, &input.observed)
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

#[derive(Debug)]
pub enum FreshTransactionError {
    InvalidStage,
    Switch(StateError),
}

pub struct FreshTransaction {
    pub plan: FreshPlan,
    pub stage: FreshTransactionStage,
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
            FreshCapability::Unsupported(FreshUnsupportedReason::FedoraNoCloudDeferred)
        );
        assert_eq!(
            fresh_capability(&forge_profiles::whonix_gateway()),
            FreshCapability::Unsupported(FreshUnsupportedReason::WhonixPairAwareRequired)
        );
    }
}
