//! Built-in VM profiles and pure resource planning.

use forge_core::{
    FirmwareMachinePolicy, GpuMode, GraphicsPolicy, GuestArchitecture, GuestFamily,
    GuestProfileKind, HardwareInfo, ImageSourcePolicy, ImageVerificationPolicy, InstanceKind,
    InstanceName, NetworkMode, NetworkPolicy, PersistencePolicy, ProfileId, ProvisioningPolicy,
    ResourcePlanError, VmProfile, VmResourcePlan, VmResources,
};
use std::fmt;

const GIB: u64 = 1024 * 1024 * 1024;
const RATIO_SCALE: u64 = 1000;
const RATIO_SCALE_USIZE: usize = 1000;

#[must_use]
pub fn built_in_profiles() -> Vec<VmProfile> {
    vec![fedora_lab(), luna_dev_fedora(), luna_lab_fedora()]
}

#[must_use]
pub fn find(name: &str) -> Option<VmProfile> {
    built_in_profiles()
        .into_iter()
        .find(|profile| profile.id.as_str() == name)
}

#[must_use]
pub fn base_volume_name(profile: &VmProfile) -> String {
    match &profile.image_source {
        ImageSourcePolicy::FedoraCloudBase { release } => {
            format!("forge-base-fedora-{release}.qcow2")
        }
        ImageSourcePolicy::VerifiedQcow2 { source_id } => {
            format!("forge-base-{source_id}.qcow2")
        }
    }
}

#[must_use]
pub fn fedora_lab() -> VmProfile {
    profile(
        ProfileMetadata {
            id: "fedora-lab",
            display_name: "Fedora Lab",
            kind: GuestProfileKind::FedoraLab,
            instance_kind: InstanceKind::Lab,
            guest_family: GuestFamily::Fedora,
        },
        VmResources {
            cpu_ratio_per_mille: 250,
            min_vcpus: 1,
            max_vcpus: 4,
            memory_start_ratio_per_mille: 200,
            memory_max_ratio_per_mille: 250,
            min_memory_bytes: 2 * GIB,
            host_memory_reserve_bytes: 2 * GIB,
            disk_bytes: 64 * GIB,
        },
        ImagePolicy {
            source: ImageSourcePolicy::FedoraCloudBase {
                release: "44".to_owned(),
            },
            verification: ImageVerificationPolicy::SignedSha256Checksums,
        },
        ProvisioningPolicy::NoCloud {
            default_user: "forge".to_owned(),
            guest_agent: true,
        },
    )
}

#[must_use]
pub fn luna_dev_fedora() -> VmProfile {
    profile(
        ProfileMetadata {
            id: "luna-dev-fedora",
            display_name: "Luna Dev Fedora",
            kind: GuestProfileKind::LunaDevFedora,
            instance_kind: InstanceKind::Development,
            guest_family: GuestFamily::Fedora,
        },
        VmResources {
            cpu_ratio_per_mille: 500,
            min_vcpus: 2,
            max_vcpus: 16,
            memory_start_ratio_per_mille: 375,
            memory_max_ratio_per_mille: 500,
            min_memory_bytes: 4 * GIB,
            host_memory_reserve_bytes: 2 * GIB,
            disk_bytes: 160 * GIB,
        },
        ImagePolicy {
            source: ImageSourcePolicy::FedoraCloudBase {
                release: "44".to_owned(),
            },
            verification: ImageVerificationPolicy::SignedSha256Checksums,
        },
        ProvisioningPolicy::None,
    )
}

#[must_use]
pub fn luna_lab_fedora() -> VmProfile {
    profile(
        ProfileMetadata {
            id: "luna-lab-fedora",
            display_name: "Luna Lab Fedora",
            kind: GuestProfileKind::LunaLabFedora,
            instance_kind: InstanceKind::Lab,
            guest_family: GuestFamily::Fedora,
        },
        VmResources {
            cpu_ratio_per_mille: 250,
            min_vcpus: 2,
            max_vcpus: 8,
            memory_start_ratio_per_mille: 250,
            memory_max_ratio_per_mille: 375,
            min_memory_bytes: 4 * GIB,
            host_memory_reserve_bytes: 2 * GIB,
            disk_bytes: 96 * GIB,
        },
        ImagePolicy {
            source: ImageSourcePolicy::FedoraCloudBase {
                release: "44".to_owned(),
            },
            verification: ImageVerificationPolicy::SignedSha256Checksums,
        },
        ProvisioningPolicy::None,
    )
}

#[derive(Clone, Copy)]
struct ProfileMetadata {
    id: &'static str,
    display_name: &'static str,
    kind: GuestProfileKind,
    instance_kind: InstanceKind,
    guest_family: GuestFamily,
}

struct ImagePolicy {
    source: ImageSourcePolicy,
    verification: ImageVerificationPolicy,
}

fn profile(
    metadata: ProfileMetadata,
    resources: VmResources,
    image: ImagePolicy,
    provisioning: ProvisioningPolicy,
) -> VmProfile {
    VmProfile {
        id: ProfileId::new(metadata.id).expect("built-in profile ID must be valid"),
        display_name: metadata.display_name.to_owned(),
        kind: metadata.kind,
        instance_kind: metadata.instance_kind,
        guest_family: metadata.guest_family,
        architecture: GuestArchitecture::X86_64,
        firmware_machine: FirmwareMachinePolicy::UefiQ35,
        resources,
        image_source: image.source,
        image_verification: image.verification,
        provisioning,
        network_policy: NetworkPolicy::DefaultNat,
        graphics_policy: GraphicsPolicy::Virtual,
        persistence: PersistencePolicy::Persistent,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceIdentity {
    pub name: InstanceName,
    pub profile_id: ProfileId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImagePlan {
    pub source: ImageSourcePolicy,
    pub verification: ImageVerificationPolicy,
    pub base_volume_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoragePlan {
    pub overlay_volume_name: String,
    pub seed_volume_name: Option<String>,
    pub capacity_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecyclePlan {
    PersistentManaged { state_directory_name: String },
    DisposableUnimplemented,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstancePlan {
    pub identity: InstanceIdentity,
    pub resources: VmResourcePlan,
    pub image: ImagePlan,
    pub storage: StoragePlan,
    pub provisioning: ProvisioningPolicy,
    pub network: NetworkPolicy,
    pub graphics: GraphicsPolicy,
    pub lifecycle: LifecyclePlan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FactoryPlanError {
    ProfileIdentityMismatch,
    Resource(ResourcePlanError),
}

impl fmt::Display for FactoryPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProfileIdentityMismatch => {
                formatter.write_str("instance profile identity does not match selected profile")
            }
            Self::Resource(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for FactoryPlanError {}

/// Builds the complete mutation-free profile-to-instance factory plan.
///
/// # Errors
///
/// Refuses mismatched profile identity and unsatisfied resource policy.
pub fn plan_instance(
    hardware: &HardwareInfo,
    profile: &VmProfile,
    identity: InstanceIdentity,
) -> Result<InstancePlan, FactoryPlanError> {
    if identity.profile_id != profile.id {
        return Err(FactoryPlanError::ProfileIdentityMismatch);
    }
    let resources = plan(hardware, profile).map_err(FactoryPlanError::Resource)?;
    let instance = identity.name.to_string();
    let seed_volume_name = match profile.provisioning {
        ProvisioningPolicy::NoCloud { .. } => Some(format!("{instance}-seed.iso")),
        ProvisioningPolicy::None => None,
    };
    let base_volume_name = base_volume_name(profile);
    let lifecycle = match profile.persistence {
        PersistencePolicy::Persistent => LifecyclePlan::PersistentManaged {
            state_directory_name: instance.clone(),
        },
        PersistencePolicy::Disposable => LifecyclePlan::DisposableUnimplemented,
    };
    Ok(InstancePlan {
        identity,
        resources,
        image: ImagePlan {
            source: profile.image_source.clone(),
            verification: profile.image_verification,
            base_volume_name,
        },
        storage: StoragePlan {
            overlay_volume_name: format!("{instance}.qcow2"),
            seed_volume_name,
            capacity_bytes: resources.disk_bytes,
        },
        provisioning: profile.provisioning.clone(),
        network: profile.network_policy,
        graphics: profile.graphics_policy,
        lifecycle,
    })
}

/// Produces a resource proposal without modifying the host.
///
/// # Errors
///
/// Returns a domain error when the host cannot satisfy the profile minimums
/// while retaining the configured host memory reserve.
pub fn plan(
    hardware: &HardwareInfo,
    profile: &VmProfile,
) -> Result<VmResourcePlan, ResourcePlanError> {
    let policy = profile.resources;
    let available_cpus = hardware.cpu.logical_cores;
    if available_cpus < policy.min_vcpus {
        return Err(ResourcePlanError::InsufficientCpu {
            available: available_cpus,
            required: policy.min_vcpus,
        });
    }

    let vcpus = ratio_usize(available_cpus, policy.cpu_ratio_per_mille)
        .max(policy.min_vcpus)
        .min(policy.max_vcpus)
        .min(available_cpus);

    let available_memory = hardware
        .memory_bytes
        .saturating_sub(policy.host_memory_reserve_bytes);
    if available_memory < policy.min_memory_bytes {
        return Err(ResourcePlanError::InsufficientMemory {
            available_bytes: available_memory,
            required_bytes: policy.min_memory_bytes,
        });
    }

    let memory_max = ratio_u64(hardware.memory_bytes, policy.memory_max_ratio_per_mille)
        .max(policy.min_memory_bytes)
        .min(available_memory);
    let memory_start = ratio_u64(hardware.memory_bytes, policy.memory_start_ratio_per_mille)
        .max(policy.min_memory_bytes)
        .min(memory_max);

    Ok(VmResourcePlan {
        vcpus,
        memory_start_bytes: memory_start,
        memory_max_bytes: memory_max,
        disk_bytes: policy.disk_bytes,
        network: match profile.network_policy {
            NetworkPolicy::DefaultNat => NetworkMode::Nat,
            NetworkPolicy::Isolated => NetworkMode::Isolated,
        },
        gpu: match profile.graphics_policy {
            GraphicsPolicy::Virtual => GpuMode::Virtual,
        },
    })
}

fn ratio_u64(value: u64, ratio_per_mille: u16) -> u64 {
    value
        .saturating_mul(u64::from(ratio_per_mille))
        .checked_div(RATIO_SCALE)
        .unwrap_or_default()
}

fn ratio_usize(value: usize, ratio_per_mille: u16) -> usize {
    value
        .saturating_mul(usize::from(ratio_per_mille))
        .checked_div(RATIO_SCALE_USIZE)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use forge_core::{CpuInfo, KvmInfo};

    fn hardware(cpus: usize, memory_gib: u64) -> HardwareInfo {
        HardwareInfo {
            cpu: CpuInfo {
                model: "Test CPU".to_owned(),
                logical_cores: cpus,
                virtualization: true,
            },
            memory_bytes: memory_gib * GIB,
            gpus: vec![],
            storage: vec![],
            kvm: KvmInfo {
                present: true,
                accessible: true,
            },
        }
    }

    #[test]
    fn reference_host_gets_ratio_based_luna_dev_plan() {
        let plan = plan(&hardware(16, 32), &luna_dev_fedora()).unwrap();
        assert_eq!(plan.vcpus, 8);
        assert_eq!(plan.memory_start_bytes, 12 * GIB);
        assert_eq!(plan.memory_max_bytes, 16 * GIB);
        assert_eq!(plan.disk_bytes, 160 * GIB);
    }

    #[test]
    fn weaker_host_gets_smaller_valid_plan() {
        let plan = plan(&hardware(4, 8), &luna_dev_fedora()).unwrap();
        assert_eq!(plan.vcpus, 2);
        assert_eq!(plan.memory_start_bytes, 4 * GIB);
        assert_eq!(plan.memory_max_bytes, 4 * GIB);
    }

    #[test]
    fn host_below_minimum_returns_domain_error() {
        let error = plan(&hardware(1, 4), &luna_dev_fedora()).unwrap_err();
        assert!(matches!(error, ResourcePlanError::InsufficientCpu { .. }));
    }

    #[test]
    fn plan_never_exceeds_host_resources() {
        let host = hardware(64, 5);
        let plan = plan(&host, &fedora_lab()).unwrap();
        assert!(plan.vcpus <= host.cpu.logical_cores);
        assert!(plan.memory_max_bytes < host.memory_bytes);
        assert!(plan.memory_start_bytes <= plan.memory_max_bytes);
    }

    #[test]
    fn fedora_lab_has_expected_modes_and_limits() {
        let profile = fedora_lab();
        let plan = plan(&hardware(16, 32), &profile).unwrap();
        assert_eq!(profile.kind, GuestProfileKind::FedoraLab);
        assert_eq!(plan.vcpus, 4);
        assert_eq!(plan.network, NetworkMode::Nat);
        assert_eq!(plan.gpu, GpuMode::Virtual);
    }

    #[test]
    fn luna_lab_uses_its_own_policy() {
        let profile = luna_lab_fedora();
        let plan = plan(&hardware(16, 32), &profile).unwrap();
        assert_eq!(profile.kind, GuestProfileKind::LunaLabFedora);
        assert_eq!(plan.vcpus, 4);
        assert_eq!(plan.memory_start_bytes, 8 * GIB);
        assert_eq!(plan.memory_max_bytes, 12 * GIB);
    }

    #[test]
    fn built_in_profile_list_is_stable() {
        let names = built_in_profiles()
            .into_iter()
            .map(|profile| profile.id.to_string())
            .collect::<Vec<_>>();
        assert_eq!(names, ["fedora-lab", "luna-dev-fedora", "luna-lab-fedora"]);
    }

    #[test]
    fn one_profile_plans_isolated_instance_identities_and_state_paths() {
        let profile = fedora_lab();
        let first = plan_instance(
            &hardware(16, 32),
            &profile,
            InstanceIdentity {
                name: InstanceName::new("fedora-lab-01").unwrap(),
                profile_id: profile.id.clone(),
            },
        )
        .unwrap();
        let second = plan_instance(
            &hardware(16, 32),
            &profile,
            InstanceIdentity {
                name: InstanceName::new("fedora-lab-test").unwrap(),
                profile_id: profile.id.clone(),
            },
        )
        .unwrap();
        assert_ne!(first.identity.name, second.identity.name);
        assert_ne!(
            first.storage.overlay_volume_name,
            second.storage.overlay_volume_name
        );
        assert_ne!(first.lifecycle, second.lifecycle);
    }

    #[test]
    fn non_fedora_profile_uses_generic_planning_without_guest_provisioning() {
        let mut profile = fedora_lab();
        profile.id = ProfileId::new("mock-debian").unwrap();
        profile.display_name = "Mock Debian".to_owned();
        profile.guest_family = GuestFamily::Debian;
        profile.kind = GuestProfileKind::DebianClean;
        profile.image_source = ImageSourcePolicy::VerifiedQcow2 {
            source_id: "mock-debian-12".to_owned(),
        };
        profile.image_verification = ImageVerificationPolicy::Sha256Digest;
        profile.provisioning = ProvisioningPolicy::None;
        let plan = plan_instance(
            &hardware(16, 32),
            &profile,
            InstanceIdentity {
                name: InstanceName::new("debian-test").unwrap(),
                profile_id: profile.id.clone(),
            },
        )
        .unwrap();
        assert_eq!(plan.storage.seed_volume_name, None);
        assert_eq!(plan.provisioning, ProvisioningPolicy::None);
        assert_eq!(plan.identity.name.as_str(), "debian-test");
    }

    #[test]
    fn disposable_policy_never_receives_persistent_lifecycle() {
        let mut profile = fedora_lab();
        profile.persistence = PersistencePolicy::Disposable;
        let plan = plan_instance(
            &hardware(16, 32),
            &profile,
            InstanceIdentity {
                name: InstanceName::new("throwaway-test").unwrap(),
                profile_id: profile.id.clone(),
            },
        )
        .unwrap();
        assert_eq!(plan.lifecycle, LifecyclePlan::DisposableUnimplemented);
    }

    #[test]
    fn default_nat_and_isolated_are_typed_network_policies() {
        let profile = fedora_lab();
        assert_eq!(profile.network_policy, NetworkPolicy::DefaultNat);

        let mut isolated = profile;
        isolated.network_policy = NetworkPolicy::Isolated;
        let plan = plan_instance(
            &hardware(16, 32),
            &isolated,
            InstanceIdentity {
                name: InstanceName::new("offline-test").unwrap(),
                profile_id: isolated.id.clone(),
            },
        )
        .unwrap();
        assert_eq!(plan.network, NetworkPolicy::Isolated);
        assert_eq!(plan.resources.network, NetworkMode::Isolated);
    }

    #[test]
    fn profile_instance_mismatch_is_typed_conflict() {
        let profile = fedora_lab();
        let error = plan_instance(
            &hardware(16, 32),
            &profile,
            InstanceIdentity {
                name: InstanceName::new("fedora-lab").unwrap(),
                profile_id: ProfileId::new("different-profile").unwrap(),
            },
        )
        .unwrap_err();
        assert_eq!(error, FactoryPlanError::ProfileIdentityMismatch);
    }
}
