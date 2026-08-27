//! Built-in VM profiles and pure resource planning.

use forge_core::{
    GpuMode, GuestProfileKind, HardwareInfo, NetworkMode, ResourcePlanError, VmProfile,
    VmResourcePlan, VmResources,
};

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
        .find(|profile| profile.name == name)
}

#[must_use]
pub fn fedora_lab() -> VmProfile {
    profile(
        "fedora-lab",
        GuestProfileKind::FedoraLab,
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
    )
}

#[must_use]
pub fn luna_dev_fedora() -> VmProfile {
    profile(
        "luna-dev-fedora",
        GuestProfileKind::LunaDevFedora,
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
    )
}

#[must_use]
pub fn luna_lab_fedora() -> VmProfile {
    profile(
        "luna-lab-fedora",
        GuestProfileKind::LunaLabFedora,
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
    )
}

fn profile(name: &str, kind: GuestProfileKind, resources: VmResources) -> VmProfile {
    VmProfile {
        name: name.to_owned(),
        kind,
        resources,
        network: NetworkMode::Nat,
        gpu: GpuMode::Virtual,
    }
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
        network: profile.network,
        gpu: profile.gpu,
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
            .map(|profile| profile.name)
            .collect::<Vec<_>>();
        assert_eq!(names, ["fedora-lab", "luna-dev-fedora", "luna-lab-fedora"]);
    }
}
