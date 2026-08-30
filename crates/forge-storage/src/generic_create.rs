use forge_core::FirstBootSuccessPolicy;
use forge_profiles::GenericCreatePlan;
use forge_state::{
    GenerationIndex, GenerationManifest, ManagedResource, ObservedGeneration, ResourceRole,
};
use std::fmt;

use crate::{BaseImageVolume, OverlayVolume};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenericCreateExecutionPlan {
    pub factory: GenericCreatePlan,
    pub created_unix_seconds: u64,
    pub domain_xml: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenericCreateResult {
    pub index: GenerationIndex,
    pub observed: ObservedGeneration,
}

/// The only two safe states for the protected image-store asset at create time.
/// Generation-owned resources never use this disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharedBaseDisposition {
    Prepare,
    ReuseProven,
}

/// Classifies only the shared image-store asset. An existing object is reusable
/// solely when current storage shape and a freshly reconciled durable consumer
/// identify the same protected base.
///
/// # Errors
/// Refuses existing objects without proof or with any identity/shape mismatch.
pub fn classify_shared_base(
    expected: &BaseImageVolume,
    existing: Option<&OverlayVolume>,
    durable_proof: Option<&ManagedResource>,
) -> Result<SharedBaseDisposition, String> {
    let Some(existing) = existing else {
        return Ok(SharedBaseDisposition::Prepare);
    };
    if existing.name != expected.name
        || existing.path != expected.path
        || existing.format != expected.format
        || existing.capacity_bytes != expected.capacity_bytes
        || existing.backing_path.is_some()
    {
        return Err("existing shared base has wrong format, capacity, path, or backing".to_owned());
    }
    let proof = durable_proof.ok_or_else(|| {
        "existing shared base has no exact Consistent durable managed-consumer proof".to_owned()
    })?;
    if proof.role != ResourceRole::SharedBase
        || proof.volume_name != existing.name
        || proof.path != existing.path
        || proof.format != existing.format
        || proof.capacity_bytes != existing.capacity_bytes
        || proof.backing_path != existing.backing_path
        || proof.volume_key.is_empty()
    {
        return Err("existing shared base differs from durable managed-consumer proof".to_owned());
    }
    Ok(SharedBaseDisposition::ReuseProven)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenericCreateError {
    InvalidPlan(String),
    BeforeOwnership(String),
    RecoveryRequired(String),
}

impl fmt::Display for GenericCreateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPlan(reason) => write!(formatter, "generic create plan refused: {reason}"),
            Self::BeforeOwnership(reason) => {
                write!(
                    formatter,
                    "create failed before durable ownership: {reason}"
                )
            }
            Self::RecoveryRequired(reason) => write!(
                formatter,
                "create crossed durable Preparing boundary; explicit recovery required: {reason}"
            ),
        }
    }
}

impl std::error::Error for GenericCreateError {}

#[allow(clippy::missing_errors_doc)]
pub trait GenericCreateBackend {
    /// Revalidates domain, generation-owned storage, network, and state absence immediately
    /// before mutation, and returns the proven disposition of the shared base.
    fn revalidate_targets(
        &mut self,
        plan: &GenericCreateExecutionPlan,
    ) -> Result<SharedBaseDisposition, String>;
    /// Prepares or re-proves the protected base and creates the exact owned overlay.
    fn prepare_storage(
        &mut self,
        plan: &GenericCreateExecutionPlan,
        base: SharedBaseDisposition,
    ) -> Result<(), String>;
    /// Returns exact pool/key/path/format/capacity/backing identities before domain definition.
    fn inspect_preparing(
        &mut self,
        plan: &GenericCreateExecutionPlan,
    ) -> Result<ObservedGeneration, String>;
    /// Durably publishes the immutable Preparing ownership intent.
    fn persist_preparing(&mut self, manifest: &GenerationManifest) -> Result<(), String>;
    /// Defines the persistent domain without starting it.
    fn define_domain(&mut self, domain_xml: &str) -> Result<(), String>;
    /// Re-reads exact domain and storage identities after definition.
    fn inspect_defined(
        &mut self,
        plan: &GenericCreateExecutionPlan,
    ) -> Result<ObservedGeneration, String>;
    /// Atomically publishes the first Active generation index.
    fn activate(
        &mut self,
        manifest: &GenerationManifest,
        observed: &ObservedGeneration,
    ) -> Result<GenerationIndex, String>;
    /// Removes only resources created before durable ownership was published.
    fn rollback_before_ownership(
        &mut self,
        plan: &GenericCreateExecutionPlan,
    ) -> Result<(), String>;
}

/// Executes the shared persistent `ManualGuest` creation transaction.
///
/// After `persist_preparing` succeeds no destructive rollback is attempted: any
/// later ambiguity is retained for explicit recovery.
///
/// # Errors
/// Refuses non-manual/booting/seed plans, failed revalidation, identity drift,
/// backend failures, and incomplete activation.
pub fn execute_generic_create<B: GenericCreateBackend>(
    backend: &mut B,
    plan: &GenericCreateExecutionPlan,
) -> Result<GenericCreateResult, GenericCreateError> {
    if plan.factory.mutation
        || plan.factory.auto_boot
        || !plan.factory.observations.is_empty()
        || plan.factory.generation.seed.is_some()
        || plan.factory.instance.first_boot_success != FirstBootSuccessPolicy::ManualGuest
    {
        return Err(GenericCreateError::InvalidPlan(
            "only a zero-boot persistent ManualGuest plan is supported".to_owned(),
        ));
    }
    let base = backend
        .revalidate_targets(plan)
        .map_err(GenericCreateError::BeforeOwnership)?;
    if let Err(error) = backend.prepare_storage(plan, base) {
        let rollback = backend.rollback_before_ownership(plan).err();
        return Err(GenericCreateError::BeforeOwnership(match rollback {
            Some(rollback) => format!("{error}; rollback also failed: {rollback}"),
            None => error,
        }));
    }
    let preparing = match backend.inspect_preparing(plan) {
        Ok(observed) => observed,
        Err(error) => {
            let rollback = backend.rollback_before_ownership(plan).err();
            return Err(GenericCreateError::BeforeOwnership(match rollback {
                Some(rollback) => format!("{error}; rollback also failed: {rollback}"),
                None => error,
            }));
        }
    };
    let manifest = forge_state::manifest_from_observed(
        &preparing,
        plan.factory.generation.generation_id.clone(),
        forge_state::GenerationStatus::Preparing,
        plan.created_unix_seconds,
    );
    if let Err(error) = backend.persist_preparing(&manifest) {
        let rollback = backend.rollback_before_ownership(plan).err();
        return Err(GenericCreateError::BeforeOwnership(match rollback {
            Some(rollback) => format!("{error}; rollback also failed: {rollback}"),
            None => error,
        }));
    }
    backend
        .define_domain(&plan.domain_xml)
        .map_err(GenericCreateError::RecoveryRequired)?;
    let observed = backend
        .inspect_defined(plan)
        .map_err(GenericCreateError::RecoveryRequired)?;
    let index = backend
        .activate(&manifest, &observed)
        .map_err(GenericCreateError::RecoveryRequired)?;
    Ok(GenericCreateResult { index, observed })
}

#[cfg(test)]
mod tests {
    use super::*;
    use forge_core::{CpuInfo, HardwareInfo, InstanceName, KvmInfo};
    use forge_profiles::InstanceIdentity;
    use forge_state::{GenerationEntry, GenerationStatus, ObservedResource, ResourceRole};

    fn execution_plan() -> GenericCreateExecutionPlan {
        let profile = forge_profiles::kali_lab();
        let hardware = HardwareInfo {
            cpu: CpuInfo {
                model: "test".to_owned(),
                logical_cores: 8,
                virtualization: true,
            },
            memory_bytes: 16 * 1024 * 1024 * 1024,
            gpus: vec![],
            storage: vec![],
            kvm: KvmInfo {
                present: true,
                accessible: true,
            },
        };
        let instance = forge_profiles::plan_instance(
            &hardware,
            &profile,
            InstanceIdentity {
                name: InstanceName::new("kali-lab").unwrap(),
                profile_id: profile.id.clone(),
            },
        )
        .unwrap();
        let generation = forge_core::GenerationResourceNames {
            generation_id: "gen-123e4567-e89b-42d3-a456-426614174000".to_owned(),
            overlay: "kali-lab-123e4567-e89b-42d3-a456-426614174000.qcow2".to_owned(),
            seed: None,
        };
        GenericCreateExecutionPlan {
            factory: forge_profiles::plan_create(instance, generation).unwrap(),
            created_unix_seconds: 1,
            domain_xml: "<domain/>".to_owned(),
        }
    }

    fn observed() -> ObservedGeneration {
        ObservedGeneration {
            domain_name: "kali-lab".to_owned(),
            domain_uuid: "domain-uuid".to_owned(),
            domain_persistent: true,
            libvirt_uri: "qemu:///system".to_owned(),
            storage_pool_name: "default".to_owned(),
            storage_pool_uuid: "pool-uuid".to_owned(),
            resources: vec![
                ObservedResource {
                    role: ResourceRole::SharedBase,
                    volume_name: "forge-base-kali-2026.2.qcow2".to_owned(),
                    volume_key: "/pool/base".to_owned(),
                    path: "/pool/base".to_owned(),
                    format: "qcow2".to_owned(),
                    capacity_bytes: 86,
                    backing_path: None,
                    referenced_by_domains: vec![],
                    backing_for_volumes: vec!["/pool/overlay".to_owned()],
                },
                ObservedResource {
                    role: ResourceRole::WritableOverlay,
                    volume_name: "overlay".to_owned(),
                    volume_key: "/pool/overlay".to_owned(),
                    path: "/pool/overlay".to_owned(),
                    format: "qcow2".to_owned(),
                    capacity_bytes: 86,
                    backing_path: Some("/pool/base".to_owned()),
                    referenced_by_domains: vec![],
                    backing_for_volumes: vec![],
                },
            ],
            unmanaged_resources: vec![],
        }
    }

    fn base_plan() -> BaseImageVolume {
        BaseImageVolume {
            name: "forge-base-example.qcow2".to_owned(),
            path: "/pool/forge-base-example.qcow2".to_owned(),
            imported_bytes: 10,
            capacity_bytes: 20,
            format: "qcow2".to_owned(),
        }
    }

    fn existing_base() -> OverlayVolume {
        OverlayVolume {
            name: "forge-base-example.qcow2".to_owned(),
            path: "/pool/forge-base-example.qcow2".to_owned(),
            capacity_bytes: 20,
            allocation_bytes: 10,
            format: "qcow2".to_owned(),
            backing_path: None,
        }
    }

    fn durable_base() -> ManagedResource {
        ManagedResource {
            role: ResourceRole::SharedBase,
            volume_name: "forge-base-example.qcow2".to_owned(),
            volume_key: "/pool/forge-base-example.qcow2".to_owned(),
            path: "/pool/forge-base-example.qcow2".to_owned(),
            format: "qcow2".to_owned(),
            capacity_bytes: 20,
            backing_path: None,
        }
    }

    #[test]
    fn absent_shared_base_uses_normal_preparation() {
        assert_eq!(
            classify_shared_base(&base_plan(), None, None).unwrap(),
            SharedBaseDisposition::Prepare
        );
    }

    #[test]
    fn proven_shared_base_is_reusable_for_multiple_consumers() {
        for _consumer in ["second", "third"] {
            assert_eq!(
                classify_shared_base(&base_plan(), Some(&existing_base()), Some(&durable_base()))
                    .unwrap(),
                SharedBaseDisposition::ReuseProven
            );
        }
    }

    #[test]
    fn existing_path_without_durable_proof_is_refused() {
        assert!(classify_shared_base(&base_plan(), Some(&existing_base()), None).is_err());
    }

    #[test]
    fn wrong_or_generation_owned_existing_base_is_refused() {
        let mut wrong = existing_base();
        wrong.backing_path = Some("/pool/unexpected.qcow2".to_owned());
        assert!(classify_shared_base(&base_plan(), Some(&wrong), Some(&durable_base())).is_err());
        let mut wrong_role = durable_base();
        wrong_role.role = ResourceRole::WritableOverlay;
        assert!(
            classify_shared_base(&base_plan(), Some(&existing_base()), Some(&wrong_role)).is_err()
        );
    }

    struct Mock {
        persisted: bool,
        fail_define: bool,
        rollback_calls: usize,
        base: SharedBaseDisposition,
        prepared_with: Option<SharedBaseDisposition>,
    }

    impl GenericCreateBackend for Mock {
        fn revalidate_targets(
            &mut self,
            _: &GenericCreateExecutionPlan,
        ) -> Result<SharedBaseDisposition, String> {
            Ok(self.base)
        }
        fn prepare_storage(
            &mut self,
            _: &GenericCreateExecutionPlan,
            base: SharedBaseDisposition,
        ) -> Result<(), String> {
            self.prepared_with = Some(base);
            Ok(())
        }
        fn inspect_preparing(
            &mut self,
            _: &GenericCreateExecutionPlan,
        ) -> Result<ObservedGeneration, String> {
            Ok(observed())
        }
        fn persist_preparing(&mut self, _: &GenerationManifest) -> Result<(), String> {
            self.persisted = true;
            Ok(())
        }
        fn define_domain(&mut self, _: &str) -> Result<(), String> {
            if self.fail_define {
                Err("define failed".to_owned())
            } else {
                Ok(())
            }
        }
        fn inspect_defined(
            &mut self,
            _: &GenericCreateExecutionPlan,
        ) -> Result<ObservedGeneration, String> {
            let mut value = observed();
            value.resources[1].referenced_by_domains = vec!["kali-lab".to_owned()];
            Ok(value)
        }
        fn activate(
            &mut self,
            manifest: &GenerationManifest,
            _: &ObservedGeneration,
        ) -> Result<GenerationIndex, String> {
            Ok(GenerationIndex {
                schema_version: forge_state::INDEX_SCHEMA_VERSION,
                domain_name: manifest.domain_name.clone(),
                domain_uuid: manifest.domain_uuid.clone(),
                active_generation_id: manifest.generation_id.clone(),
                generations: vec![GenerationEntry {
                    generation_id: manifest.generation_id.clone(),
                    status: GenerationStatus::Active,
                    manifest_file: "manifest.json".to_owned(),
                }],
                cleanup_progress: vec![],
            })
        }
        fn rollback_before_ownership(
            &mut self,
            _: &GenericCreateExecutionPlan,
        ) -> Result<(), String> {
            self.rollback_calls += 1;
            Ok(())
        }
    }

    #[test]
    fn manual_guest_create_activates_without_boot_observation() {
        let mut backend = Mock {
            persisted: false,
            fail_define: false,
            rollback_calls: 0,
            base: SharedBaseDisposition::Prepare,
            prepared_with: None,
        };
        let result = execute_generic_create(&mut backend, &execution_plan()).unwrap();
        assert!(backend.persisted);
        assert_eq!(backend.rollback_calls, 0);
        assert_eq!(backend.prepared_with, Some(SharedBaseDisposition::Prepare));
        assert_eq!(result.index.generations[0].status, GenerationStatus::Active);
    }

    #[test]
    fn failure_after_preparing_requires_recovery_without_rollback() {
        let mut backend = Mock {
            persisted: false,
            fail_define: true,
            rollback_calls: 0,
            base: SharedBaseDisposition::ReuseProven,
            prepared_with: None,
        };
        assert!(matches!(
            execute_generic_create(&mut backend, &execution_plan()),
            Err(GenericCreateError::RecoveryRequired(_))
        ));
        assert!(backend.persisted);
        assert_eq!(backend.rollback_calls, 0);
        assert_eq!(
            backend.prepared_with,
            Some(SharedBaseDisposition::ReuseProven)
        );
    }

    #[test]
    fn proven_shared_base_disposition_is_carried_into_storage_without_becoming_owned() {
        let mut backend = Mock {
            persisted: false,
            fail_define: false,
            rollback_calls: 0,
            base: SharedBaseDisposition::ReuseProven,
            prepared_with: None,
        };
        let result = execute_generic_create(&mut backend, &execution_plan()).unwrap();
        assert_eq!(
            backend.prepared_with,
            Some(SharedBaseDisposition::ReuseProven)
        );
        assert_eq!(
            result
                .observed
                .resources
                .iter()
                .filter(|resource| resource.role == ResourceRole::WritableOverlay)
                .count(),
            1
        );
    }
}
