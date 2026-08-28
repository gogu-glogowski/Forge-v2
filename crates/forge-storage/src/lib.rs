//! Safe orchestration for Fedora-Lab storage and domain definition.

use forge_core::{GuestProfileKind, VmProfile, VmResourcePlan, VmState};
use forge_domain::{DomainMetadata, DomainSpec, DomainSpecError};
use std::fmt;

mod image_prepare;
pub use image_prepare::*;
mod generic_create;
pub use generic_create::*;

pub const DEFAULT_POOL: &str = "default";
pub const FEDORA_LAB_VOLUME: &str = "fedora-lab.qcow2";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoragePoolInfo {
    pub name: String,
    pub active: bool,
    pub target_path: String,
    pub available_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeInfo {
    pub name: String,
    pub path: String,
    pub capacity_bytes: u64,
    pub allocation_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefinedDomain {
    pub uuid: String,
    pub state: VmState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainDefineError {
    pub error: StorageError,
    pub domain_defined: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefinePlan {
    pub domain_name: String,
    pub pool: StoragePoolInfo,
    pub volume_name: String,
    pub volume_path: String,
    pub capacity_bytes: u64,
    pub spec: DomainSpec,
    pub xml: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecutionContext {
    pub volume_created: bool,
    pub domain_defined: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefineResult {
    pub domain: DefinedDomain,
    pub volume: VolumeInfo,
    pub context: ExecutionContext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageError {
    UnsupportedProfile,
    PoolNotFound(String),
    PoolInactive(String),
    PoolUnusable(String),
    AlreadyExists {
        resource: String,
        name: String,
    },
    InvalidDomain(DomainSpecError),
    Backend(String),
    DefineFailed {
        primary: String,
        rollback: Option<String>,
    },
    PostDefineInspection(String),
}

impl fmt::Display for StorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedProfile => formatter.write_str("only fedora-lab can be defined"),
            Self::PoolNotFound(name) => write!(formatter, "storage pool {name} does not exist"),
            Self::PoolInactive(name) => write!(formatter, "storage pool {name} is inactive"),
            Self::PoolUnusable(message) => write!(formatter, "storage pool is unusable: {message}"),
            Self::AlreadyExists { resource, name } => {
                write!(formatter, "{resource} already exists: {name}")
            }
            Self::InvalidDomain(error) => {
                write!(formatter, "invalid domain specification: {error}")
            }
            Self::Backend(message) => formatter.write_str(message),
            Self::DefineFailed {
                primary,
                rollback: None,
            } => {
                write!(
                    formatter,
                    "domain definition failed: {primary}; volume rollback succeeded"
                )
            }
            Self::DefineFailed {
                primary,
                rollback: Some(rollback),
            } => write!(
                formatter,
                "domain definition failed: {primary}; volume rollback also failed: {rollback}"
            ),
            Self::PostDefineInspection(message) => write!(
                formatter,
                "domain was defined, but result inspection failed: {message}"
            ),
        }
    }
}

impl std::error::Error for StorageError {}

pub trait DefineBackend {
    /// # Errors
    /// Returns a backend query error.
    fn inspect_pool(&mut self, name: &str) -> Result<Option<StoragePoolInfo>, StorageError>;
    /// # Errors
    /// Returns a backend query error.
    fn domain_exists(&mut self, name: &str) -> Result<bool, StorageError>;
    /// # Errors
    /// Returns a backend query error.
    fn volume_exists(&mut self, pool: &str, name: &str) -> Result<bool, StorageError>;
    /// # Errors
    /// Returns a backend mutation error.
    fn create_volume(
        &mut self,
        pool: &str,
        name: &str,
        capacity_bytes: u64,
    ) -> Result<VolumeInfo, StorageError>;
    /// # Errors
    /// Returns a backend mutation error.
    fn define_domain(&mut self, xml: &str) -> Result<DefinedDomain, DomainDefineError>;
    /// # Errors
    /// Returns a backend rollback error.
    fn delete_volume(&mut self, pool: &str, name: &str) -> Result<(), StorageError>;
}

/// Performs read-only checks and builds the complete validated define plan.
///
/// # Errors
///
/// Returns an error for policy violations, missing/inactive storage, or any
/// pre-existing Fedora-Lab resource.
pub fn prepare<B: DefineBackend>(
    backend: &mut B,
    profile: &VmProfile,
    resource_plan: &VmResourcePlan,
) -> Result<DefinePlan, StorageError> {
    if profile.kind != GuestProfileKind::FedoraLab || profile.id.as_str() != "fedora-lab" {
        return Err(StorageError::UnsupportedProfile);
    }
    let pool = backend
        .inspect_pool(DEFAULT_POOL)?
        .ok_or_else(|| StorageError::PoolNotFound(DEFAULT_POOL.to_owned()))?;
    if !pool.active {
        return Err(StorageError::PoolInactive(pool.name));
    }
    if pool.target_path.is_empty() || !pool.target_path.starts_with('/') {
        return Err(StorageError::PoolUnusable("invalid target path".to_owned()));
    }
    if pool.available_bytes == 0 {
        return Err(StorageError::PoolUnusable(
            "pool reports no available space".to_owned(),
        ));
    }
    if backend.domain_exists(profile.id.as_str())? {
        return Err(StorageError::AlreadyExists {
            resource: "domain".to_owned(),
            name: profile.id.to_string(),
        });
    }
    if backend.volume_exists(&pool.name, FEDORA_LAB_VOLUME)? {
        return Err(StorageError::AlreadyExists {
            resource: "volume".to_owned(),
            name: FEDORA_LAB_VOLUME.to_owned(),
        });
    }
    let volume_path = format!(
        "{}/{}",
        pool.target_path.trim_end_matches('/'),
        FEDORA_LAB_VOLUME
    );
    let spec = forge_domain::fedora_lab_spec(
        profile,
        resource_plan,
        DomainMetadata {
            name: profile.id.to_string(),
            disk_path: volume_path.clone(),
        },
    )
    .map_err(StorageError::InvalidDomain)?;
    forge_domain::validate(&spec).map_err(StorageError::InvalidDomain)?;
    let xml = forge_domain::render_xml(&spec).map_err(StorageError::InvalidDomain)?;
    Ok(DefinePlan {
        domain_name: profile.id.to_string(),
        pool,
        volume_name: FEDORA_LAB_VOLUME.to_owned(),
        volume_path,
        capacity_bytes: resource_plan.disk_bytes,
        spec,
        xml,
    })
}

/// Creates the planned volume and defines the shut-off domain transactionally.
///
/// # Errors
///
/// Rolls back only the volume created in this execution when domain definition
/// fails, reporting both failures when rollback also fails.
pub fn execute<B: DefineBackend>(
    backend: &mut B,
    plan: &DefinePlan,
) -> Result<DefineResult, StorageError> {
    if backend.domain_exists(&plan.domain_name)? {
        return Err(StorageError::AlreadyExists {
            resource: "domain".to_owned(),
            name: plan.domain_name.clone(),
        });
    }
    if backend.volume_exists(&plan.pool.name, &plan.volume_name)? {
        return Err(StorageError::AlreadyExists {
            resource: "volume".to_owned(),
            name: plan.volume_name.clone(),
        });
    }
    let mut context = ExecutionContext::default();
    let volume = backend.create_volume(&plan.pool.name, &plan.volume_name, plan.capacity_bytes)?;
    context.volume_created = true;
    if volume.path != plan.volume_path {
        return Err(rollback_define_failure(
            backend,
            plan,
            format!(
                "created volume path {} differs from planned path {}",
                volume.path, plan.volume_path
            ),
        ));
    }
    match backend.domain_exists(&plan.domain_name) {
        Ok(false) => {}
        Ok(true) => {
            return Err(rollback_define_failure(
                backend,
                plan,
                format!("domain appeared during execution: {}", plan.domain_name),
            ));
        }
        Err(error) => {
            return Err(rollback_define_failure(backend, plan, error.to_string()));
        }
    }
    match backend.define_domain(&plan.xml) {
        Ok(domain) => {
            context.domain_defined = true;
            Ok(DefineResult {
                domain,
                volume,
                context,
            })
        }
        Err(error) if error.domain_defined => {
            Err(StorageError::PostDefineInspection(error.error.to_string()))
        }
        Err(error) => Err(rollback_define_failure(
            backend,
            plan,
            error.error.to_string(),
        )),
    }
}

fn rollback_define_failure<B: DefineBackend>(
    backend: &mut B,
    plan: &DefinePlan,
    primary: String,
) -> StorageError {
    let rollback = backend
        .delete_volume(&plan.pool.name, &plan.volume_name)
        .err()
        .map(|error| error.to_string());
    StorageError::DefineFailed { primary, rollback }
}

#[cfg(test)]
mod tests {
    use super::*;
    use forge_core::{GpuMode, NetworkMode, VmResources};

    const GIB: u64 = 1024 * 1024 * 1024;

    #[derive(Clone, Copy, Default)]
    enum FailureMode {
        #[default]
        None,
        Define,
        DefineAndRollback,
    }

    #[derive(Default)]
    struct MockBackend {
        domain_exists: bool,
        volume_exists: bool,
        failure: FailureMode,
        creates: usize,
        defines: usize,
        deletes: usize,
    }

    impl DefineBackend for MockBackend {
        fn inspect_pool(&mut self, name: &str) -> Result<Option<StoragePoolInfo>, StorageError> {
            Ok(Some(StoragePoolInfo {
                name: name.to_owned(),
                active: true,
                target_path: "/var/lib/libvirt/images".to_owned(),
                available_bytes: 100 * GIB,
            }))
        }

        fn domain_exists(&mut self, _: &str) -> Result<bool, StorageError> {
            Ok(self.domain_exists)
        }

        fn volume_exists(&mut self, _: &str, _: &str) -> Result<bool, StorageError> {
            Ok(self.volume_exists)
        }

        fn create_volume(
            &mut self,
            _: &str,
            name: &str,
            capacity_bytes: u64,
        ) -> Result<VolumeInfo, StorageError> {
            self.creates += 1;
            Ok(VolumeInfo {
                name: name.to_owned(),
                path: format!("/var/lib/libvirt/images/{name}"),
                capacity_bytes,
                allocation_bytes: 0,
            })
        }

        fn define_domain(&mut self, _: &str) -> Result<DefinedDomain, DomainDefineError> {
            self.defines += 1;
            if matches!(
                self.failure,
                FailureMode::Define | FailureMode::DefineAndRollback
            ) {
                Err(DomainDefineError {
                    error: StorageError::Backend("define error".to_owned()),
                    domain_defined: false,
                })
            } else {
                Ok(DefinedDomain {
                    uuid: "test-uuid".to_owned(),
                    state: VmState::Shutoff,
                })
            }
        }

        fn delete_volume(&mut self, _: &str, _: &str) -> Result<(), StorageError> {
            self.deletes += 1;
            if matches!(self.failure, FailureMode::DefineAndRollback) {
                Err(StorageError::Backend("delete error".to_owned()))
            } else {
                Ok(())
            }
        }
    }

    fn profile() -> VmProfile {
        VmProfile {
            id: forge_core::ProfileId::new("fedora-lab").unwrap(),
            display_name: "Fedora Lab".to_owned(),
            kind: GuestProfileKind::FedoraLab,
            instance_kind: forge_core::InstanceKind::Lab,
            guest_family: forge_core::GuestFamily::Fedora,
            architecture: forge_core::GuestArchitecture::X86_64,
            firmware_machine: forge_core::FirmwareMachinePolicy::UefiQ35,
            resources: VmResources {
                cpu_ratio_per_mille: 250,
                min_vcpus: 1,
                max_vcpus: 4,
                memory_start_ratio_per_mille: 200,
                memory_max_ratio_per_mille: 250,
                min_memory_bytes: 2 * GIB,
                host_memory_reserve_bytes: 2 * GIB,
                disk_bytes: 64 * GIB,
            },
            image_source: forge_core::ImageSourcePolicy::FedoraCloudBase {
                release: "44".to_owned(),
            },
            image_verification: forge_core::ImageVerificationPolicy::SignedSha256Checksums,
            provisioning: forge_core::ProvisioningPolicy::NoCloud {
                default_user: "forge".to_owned(),
                guest_agent: true,
            },
            first_boot_success: forge_core::FirstBootSuccessPolicy::CloudInitManaged {
                expected_user: "forge".to_owned(),
                require_guest_agent: true,
            },
            network_policy: forge_core::NetworkPolicy::DefaultNat,
            graphics_policy: forge_core::GraphicsPolicy::Virtual,
            persistence: forge_core::PersistencePolicy::Persistent,
        }
    }

    fn resources() -> VmResourcePlan {
        VmResourcePlan {
            vcpus: 4,
            memory_start_bytes: 6 * GIB,
            memory_max_bytes: 8 * GIB,
            disk_bytes: 64 * GIB,
            network: NetworkMode::Nat,
            gpu: GpuMode::Virtual,
        }
    }

    #[test]
    fn prepares_fedora_lab_define_plan_without_mutation() {
        let mut backend = MockBackend::default();
        let plan = prepare(&mut backend, &profile(), &resources()).unwrap();
        assert_eq!(plan.domain_name, "fedora-lab");
        assert_eq!(plan.pool.name, "default");
        assert_eq!(plan.capacity_bytes, 64 * GIB);
        assert!(plan.xml.contains("fedora-lab.qcow2"));
        assert_eq!(
            (backend.creates, backend.defines, backend.deletes),
            (0, 0, 0)
        );
    }

    #[test]
    fn rejects_existing_domain() {
        let mut backend = MockBackend {
            domain_exists: true,
            ..Default::default()
        };
        assert!(matches!(
            prepare(&mut backend, &profile(), &resources()),
            Err(StorageError::AlreadyExists { resource, .. }) if resource == "domain"
        ));
    }

    #[test]
    fn rejects_existing_volume() {
        let mut backend = MockBackend {
            volume_exists: true,
            ..Default::default()
        };
        assert!(matches!(
            prepare(&mut backend, &profile(), &resources()),
            Err(StorageError::AlreadyExists { resource, .. }) if resource == "volume"
        ));
    }

    #[test]
    fn rolls_back_created_volume_after_define_error() {
        let mut backend = MockBackend {
            failure: FailureMode::Define,
            ..Default::default()
        };
        let plan = prepare(&mut backend, &profile(), &resources()).unwrap();
        let error = execute(&mut backend, &plan).unwrap_err();
        assert!(matches!(
            error,
            StorageError::DefineFailed { rollback: None, .. }
        ));
        assert_eq!(
            (backend.creates, backend.defines, backend.deletes),
            (1, 1, 1)
        );
    }

    #[test]
    fn reports_primary_and_rollback_errors() {
        let mut backend = MockBackend {
            failure: FailureMode::DefineAndRollback,
            ..Default::default()
        };
        let plan = prepare(&mut backend, &profile(), &resources()).unwrap();
        assert!(matches!(
            execute(&mut backend, &plan),
            Err(StorageError::DefineFailed {
                rollback: Some(_),
                ..
            })
        ));
    }

    #[test]
    fn rejects_non_fedora_lab_profile() {
        let mut backend = MockBackend::default();
        let mut other = profile();
        other.kind = GuestProfileKind::LunaLabFedora;
        assert_eq!(
            prepare(&mut backend, &other, &resources()),
            Err(StorageError::UnsupportedProfile)
        );
    }

    #[test]
    fn rejects_invalid_domain_specification_before_mutation() {
        let mut backend = MockBackend::default();
        let mut invalid = resources();
        invalid.vcpus = 0;
        assert!(matches!(
            prepare(&mut backend, &profile(), &invalid),
            Err(StorageError::InvalidDomain(DomainSpecError::ZeroVcpus))
        ));
        assert_eq!(backend.creates, 0);
    }

    #[test]
    fn successful_execution_records_context() {
        let mut backend = MockBackend::default();
        let plan = prepare(&mut backend, &profile(), &resources()).unwrap();
        let result = execute(&mut backend, &plan).unwrap();
        assert_eq!(
            result.context,
            ExecutionContext {
                volume_created: true,
                domain_defined: true
            }
        );
        assert_eq!(result.domain.state, VmState::Shutoff);
    }
}
