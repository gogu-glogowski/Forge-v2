use forge_core::FirstBootSuccessPolicy;
use forge_profiles::GenericCreatePlan;
use forge_state::{GenerationIndex, GenerationManifest, ObservedGeneration};
use std::fmt;

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
    /// Revalidates domain, pool, storage, network, and state absence immediately before mutation.
    fn revalidate_absent(&mut self, plan: &GenericCreateExecutionPlan) -> Result<(), String>;
    /// Acquires/verifies/imports the protected base and creates the exact owned overlay.
    fn prepare_storage(&mut self, plan: &GenericCreateExecutionPlan) -> Result<(), String>;
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
    backend
        .revalidate_absent(plan)
        .map_err(GenericCreateError::BeforeOwnership)?;
    if let Err(error) = backend.prepare_storage(plan) {
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

    struct Mock {
        persisted: bool,
        fail_define: bool,
        rollback_calls: usize,
    }

    impl GenericCreateBackend for Mock {
        fn revalidate_absent(&mut self, _: &GenericCreateExecutionPlan) -> Result<(), String> {
            Ok(())
        }
        fn prepare_storage(&mut self, _: &GenericCreateExecutionPlan) -> Result<(), String> {
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
        };
        let result = execute_generic_create(&mut backend, &execution_plan()).unwrap();
        assert!(backend.persisted);
        assert_eq!(backend.rollback_calls, 0);
        assert_eq!(result.index.generations[0].status, GenerationStatus::Active);
    }

    #[test]
    fn failure_after_preparing_requires_recovery_without_rollback() {
        let mut backend = Mock {
            persisted: false,
            fail_define: true,
            rollback_calls: 0,
        };
        assert!(matches!(
            execute_generic_create(&mut backend, &execution_plan()),
            Err(GenericCreateError::RecoveryRequired(_))
        ));
        assert!(backend.persisted);
        assert_eq!(backend.rollback_calls, 0);
    }
}
