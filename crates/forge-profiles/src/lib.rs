//! Built-in VM profiles and pure resource planning.

use forge_core::{
    FirmwareMachinePolicy, FirstBootSuccessPolicy, GenerationResourceNames, GpuMode,
    GraphicsPolicy, GuestArchitecture, GuestFamily, GuestProfileKind, HardwareInfo,
    ImageSourcePolicy, ImageVerificationPolicy, InstanceKind, InstanceName,
    LegacyProductClassification, NetworkMode, NetworkPolicy, PersistencePolicy,
    PointToPointEndpoint, ProductAvailability, ProfileId, ProvisioningPolicy, ResourcePlanError,
    UdpPointToPointLink, VmProfile, VmResourcePlan, VmResources, WhonixPairId,
};
use std::fmt;

const GIB: u64 = 1024 * 1024 * 1024;
const RATIO_SCALE: u64 = 1000;
const RATIO_SCALE_USIZE: usize = 1000;

#[must_use]
pub fn built_in_profiles() -> Vec<VmProfile> {
    vec![
        fedora_lab(),
        kali_lab(),
        whonix_gateway(),
        whonix_workstation(),
        luna_dev_fedora(),
        luna_lab_fedora(),
    ]
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
        ImageSourcePolicy::KaliQemuArchive { release } => {
            format!("forge-base-kali-{release}.qcow2")
        }
        ImageSourcePolicy::WhonixLibvirtBundle { release } => {
            let role = match profile.kind {
                GuestProfileKind::WhonixWorkstation => "workstation",
                _ => "gateway",
            };
            format!("forge-base-whonix-{role}-{release}.qcow2")
        }
        ImageSourcePolicy::VerifiedQcow2 { source_id } => {
            format!("forge-base-{source_id}.qcow2")
        }
    }
}

#[must_use]
///
/// # Panics
///
/// Panics only if Forge's built-in, compile-time Whonix pair identifier is invalid.
pub fn whonix_gateway() -> VmProfile {
    let mut profile = profile(
        ProfileMetadata {
            id: "whonix-gateway",
            display_name: "Whonix Gateway",
            kind: GuestProfileKind::WhonixGateway,
            instance_kind: InstanceKind::NetworkProvider,
            guest_family: GuestFamily::Whonix,
        },
        VmResources {
            cpu_ratio_per_mille: 0,
            min_vcpus: 1,
            max_vcpus: 1,
            memory_start_ratio_per_mille: 0,
            memory_max_ratio_per_mille: 0,
            min_memory_bytes: 2 * GIB,
            host_memory_reserve_bytes: 2 * GIB,
            disk_bytes: 100 * GIB,
        },
        ImagePolicy {
            source: ImageSourcePolicy::WhonixLibvirtBundle {
                release: "18.2.1.9".to_owned(),
            },
            verification: ImageVerificationPolicy::WhonixDetachedOpenPgp,
        },
        ProvisioningPolicy::None,
        FirstBootSuccessPolicy::ManualGuest,
    );
    profile.firmware_machine = FirmwareMachinePolicy::BiosQ35;
    profile.network_policy = NetworkPolicy::WhonixGateway(UdpPointToPointLink {
        pair_id: WhonixPairId::new("whonix-main-pair")
            .expect("built-in Whonix pair ID must be valid"),
        endpoint: PointToPointEndpoint::Gateway,
        local_port: 6688,
        remote_port: 5577,
    });
    profile
}

#[must_use]
///
/// # Panics
///
/// Panics only if the built-in pair identifier is invalid, which indicates a
/// programming error in the static profile definition.
pub fn whonix_workstation() -> VmProfile {
    let mut profile = profile(
        ProfileMetadata {
            id: "whonix-workstation",
            display_name: "Whonix Workstation",
            kind: GuestProfileKind::WhonixWorkstation,
            instance_kind: InstanceKind::NetworkConsumer,
            guest_family: GuestFamily::Whonix,
        },
        VmResources {
            cpu_ratio_per_mille: 0,
            min_vcpus: 1,
            max_vcpus: 1,
            memory_start_ratio_per_mille: 0,
            memory_max_ratio_per_mille: 0,
            min_memory_bytes: 2 * GIB,
            host_memory_reserve_bytes: 2 * GIB,
            disk_bytes: 100 * GIB,
        },
        ImagePolicy {
            source: ImageSourcePolicy::WhonixLibvirtBundle {
                release: "18.2.1.9".to_owned(),
            },
            verification: ImageVerificationPolicy::WhonixDetachedOpenPgp,
        },
        ProvisioningPolicy::None,
        FirstBootSuccessPolicy::ManualGuest,
    );
    profile.firmware_machine = FirmwareMachinePolicy::BiosQ35;
    profile.network_policy = NetworkPolicy::WhonixWorkstation(UdpPointToPointLink {
        pair_id: WhonixPairId::new("whonix-main-pair")
            .expect("built-in Whonix pair ID must be valid"),
        endpoint: PointToPointEndpoint::Workstation,
        local_port: 5577,
        remote_port: 6688,
    });
    profile
}

#[must_use]
pub fn kali_lab() -> VmProfile {
    let mut profile = profile(
        ProfileMetadata {
            id: "kali-lab",
            display_name: "Kali Lab",
            kind: GuestProfileKind::KaliLab,
            instance_kind: InstanceKind::Lab,
            guest_family: GuestFamily::Kali,
        },
        VmResources {
            cpu_ratio_per_mille: 250,
            min_vcpus: 2,
            max_vcpus: 4,
            memory_start_ratio_per_mille: 125,
            memory_max_ratio_per_mille: 250,
            min_memory_bytes: 2 * GIB,
            host_memory_reserve_bytes: 2 * GIB,
            disk_bytes: 86 * GIB,
        },
        ImagePolicy {
            source: ImageSourcePolicy::KaliQemuArchive {
                release: "2026.2".to_owned(),
            },
            verification: ImageVerificationPolicy::KaliDetachedSignedSha256Sums,
        },
        ProvisioningPolicy::None,
        FirstBootSuccessPolicy::ManualGuest,
    );
    profile.firmware_machine = FirmwareMachinePolicy::BiosQ35;
    profile
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
        FirstBootSuccessPolicy::CloudInitManaged {
            expected_user: "forge".to_owned(),
            require_guest_agent: true,
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
        FirstBootSuccessPolicy::ManualGuest,
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
        FirstBootSuccessPolicy::ManualGuest,
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
    first_boot_success: FirstBootSuccessPolicy,
) -> VmProfile {
    let availability = if matches!(image.source, ImageSourcePolicy::FedoraCloudBase { .. }) {
        ProductAvailability::LegacyCompatibility(
            LegacyProductClassification::LegacyFedoraCloudNoCloud,
        )
    } else {
        ProductAvailability::Supported
    };
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
        first_boot_success,
        network_policy: NetworkPolicy::DefaultNat,
        graphics_policy: GraphicsPolicy::Virtual,
        persistence: PersistencePolicy::Persistent,
        availability,
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
    pub first_boot_success: FirstBootSuccessPolicy,
    pub network: NetworkPolicy,
    pub graphics: GraphicsPolicy,
    pub lifecycle: LifecyclePlan,
    pub availability: ProductAvailability,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceImageFormat {
    Qcow2,
    SevenZipQcow2Archive,
    TarXzMultiArtifactBundle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrepareBaseStrategy {
    VerifiedQcow2,
    SevenZipSingleQcow2,
    WhonixBundleGateway,
    WhonixBundleWorkstation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedBaseImagePlan {
    pub source: ImageSourcePolicy,
    pub verification: ImageVerificationPolicy,
    pub source_format: SourceImageFormat,
    pub preparation: PrepareBaseStrategy,
    pub base_volume_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhonixPairEvidence {
    pub gateway_instance: InstanceName,
    pub gateway_generation: String,
    pub gateway_domain_uuid: String,
    pub gateway_link: UdpPointToPointLink,
    pub bundle_identity: String,
}

/// Immutable values captured during planning and required to match again
/// immediately before an execute transaction may mutate storage or libvirt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhonixPairSnapshot {
    pub gateway: WhonixPairEvidence,
    pub workstation_overlay: String,
    pub workstation_base_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WhonixPairPlanError {
    GatewayNotConsistent,
    GatewayIdentityMismatch,
    EndpointMismatch,
    BundleMismatch,
    SnapshotDrift,
}

impl fmt::Display for WhonixPairPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::GatewayNotConsistent => "Whonix Gateway must be present and Consistent",
            Self::GatewayIdentityMismatch => "Whonix Gateway identity does not match the pair",
            Self::EndpointMismatch => "Whonix endpoints are not exact complements",
            Self::BundleMismatch => {
                "Whonix Gateway and Workstation use different bundle identities"
            }
            Self::SnapshotDrift => "Whonix pair snapshot changed before execute",
        })
    }
}

impl std::error::Error for WhonixPairPlanError {}

/// Validates a Workstation plan against an already reconciled Gateway proof.
///
/// # Errors
///
/// Returns a typed refusal when the Gateway identity, endpoint complement, or
/// verified bundle identity does not match the Workstation plan.
pub fn validate_whonix_pair(
    evidence: &WhonixPairEvidence,
    workstation: &UdpPointToPointLink,
    workstation_bundle_identity: &str,
) -> Result<(), WhonixPairPlanError> {
    if evidence.gateway_instance.as_str() != "whonix-gateway"
        || evidence.gateway_generation.is_empty()
        || evidence.gateway_domain_uuid.is_empty()
    {
        return Err(WhonixPairPlanError::GatewayNotConsistent);
    }
    let expected_gateway = whonix_gateway();
    let NetworkPolicy::WhonixGateway(expected_link) = expected_gateway.network_policy else {
        unreachable!()
    };
    if evidence.gateway_link != expected_link {
        return Err(WhonixPairPlanError::GatewayIdentityMismatch);
    }
    if !evidence.gateway_link.is_complementary_to(workstation) {
        return Err(WhonixPairPlanError::EndpointMismatch);
    }
    if evidence.bundle_identity != workstation_bundle_identity {
        return Err(WhonixPairPlanError::BundleMismatch);
    }
    Ok(())
}

/// Refuses execution when any planning-bound Gateway or Workstation identity
/// changed during the plan-to-execute interval.
///
/// # Errors
///
/// Returns `SnapshotDrift` if any captured identity differs.
pub fn revalidate_whonix_snapshot(
    planned: &WhonixPairSnapshot,
    current: &WhonixPairSnapshot,
) -> Result<(), WhonixPairPlanError> {
    if planned == current {
        Ok(())
    } else {
        Err(WhonixPairPlanError::SnapshotDrift)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirstBootObservation {
    DomainRunning,
    DhcpAddress,
    GuestAgentAvailable,
    SshAuthenticated,
    CloudInitDone,
    ExpectedUserConfirmed,
    HostnameMatchesInstance,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenericCreatePlan {
    pub instance: InstancePlan,
    pub generation: GenerationResourceNames,
    pub prepared_base: PreparedBaseImagePlan,
    pub observations: Vec<FirstBootObservation>,
    pub auto_boot: bool,
    pub initial_state: &'static str,
    pub steps: Vec<&'static str>,
    pub mutation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FactoryPlanError {
    LegacyFedoraProductRetired,
    ProfileIdentityMismatch,
    IncompatibleProvisioningPolicy,
    GenerationResourceMismatch,
    Resource(ResourcePlanError),
}

impl fmt::Display for FactoryPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LegacyFedoraProductRetired => formatter.write_str(
                "Legacy Fedora Cloud/NoCloud is retired in Forge V2.5. Fedora Workstation support is being introduced through the new Workstation architecture.",
            ),
            Self::ProfileIdentityMismatch => {
                formatter.write_str("instance profile identity does not match selected profile")
            }
            Self::IncompatibleProvisioningPolicy => formatter
                .write_str("first-boot success policy is incompatible with provisioning policy"),
            Self::GenerationResourceMismatch => formatter.write_str(
                "generation resource roles do not match the selected provisioning policy",
            ),
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
    if profile.availability
        == ProductAvailability::LegacyCompatibility(
            LegacyProductClassification::LegacyFedoraCloudNoCloud,
        )
    {
        return Err(FactoryPlanError::LegacyFedoraProductRetired);
    }
    if identity.profile_id != profile.id {
        return Err(FactoryPlanError::ProfileIdentityMismatch);
    }
    if let FirstBootSuccessPolicy::CloudInitManaged {
        expected_user,
        require_guest_agent,
    } = &profile.first_boot_success
    {
        let ProvisioningPolicy::NoCloud {
            default_user,
            guest_agent,
        } = &profile.provisioning
        else {
            return Err(FactoryPlanError::IncompatibleProvisioningPolicy);
        };
        if expected_user != default_user || (*require_guest_agent && !guest_agent) {
            return Err(FactoryPlanError::IncompatibleProvisioningPolicy);
        }
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
        first_boot_success: profile.first_boot_success.clone(),
        network: profile.network_policy.clone(),
        graphics: profile.graphics_policy,
        lifecycle,
        availability: profile.availability,
    })
}

/// Extends an instance plan with generation-scoped creation and success policy.
/// The caller supplies names validated by the durable generation subsystem.
///
/// # Errors
///
/// Refuses a seed role that disagrees with the selected provisioning policy.
pub fn plan_create(
    instance: InstancePlan,
    generation: GenerationResourceNames,
) -> Result<GenericCreatePlan, FactoryPlanError> {
    if matches!(
        instance.availability,
        ProductAvailability::LegacyCompatibility(
            LegacyProductClassification::LegacyFedoraCloudNoCloud
        )
    ) {
        return Err(FactoryPlanError::LegacyFedoraProductRetired);
    }
    let seed_required = matches!(instance.provisioning, ProvisioningPolicy::NoCloud { .. });
    if seed_required != generation.seed.is_some() {
        return Err(FactoryPlanError::GenerationResourceMismatch);
    }
    let (auto_boot, observations) = match &instance.first_boot_success {
        FirstBootSuccessPolicy::CloudInitManaged {
            require_guest_agent,
            ..
        } => {
            let mut required = vec![
                FirstBootObservation::DomainRunning,
                FirstBootObservation::DhcpAddress,
            ];
            if *require_guest_agent {
                required.push(FirstBootObservation::GuestAgentAvailable);
            }
            required.extend([
                FirstBootObservation::SshAuthenticated,
                FirstBootObservation::CloudInitDone,
                FirstBootObservation::ExpectedUserConfirmed,
                FirstBootObservation::HostnameMatchesInstance,
            ]);
            (true, required)
        }
        FirstBootSuccessPolicy::BootOnly => (true, vec![FirstBootObservation::DomainRunning]),
        FirstBootSuccessPolicy::ManualGuest => (false, Vec::new()),
    };
    let mut steps = vec![
        "acquire source according to image policy",
        "verify source according to supply-chain policy",
        "prepare or prove the shared base",
        "create the generation overlay",
    ];
    if seed_required {
        steps.push("create the generation provisioning seed");
    }
    steps.extend([
        "persist exact Preparing ownership",
        "define the persistent domain",
    ]);
    if auto_boot {
        steps.extend([
            "boot according to profile policy",
            "collect only profile-required success evidence",
        ]);
    }
    steps.push("atomically activate the proven generation");
    Ok(GenericCreatePlan {
        prepared_base: PreparedBaseImagePlan {
            source: instance.image.source.clone(),
            verification: instance.image.verification,
            source_format: match &instance.image.source {
                ImageSourcePolicy::KaliQemuArchive { .. } => {
                    SourceImageFormat::SevenZipQcow2Archive
                }
                ImageSourcePolicy::WhonixLibvirtBundle { .. } => {
                    SourceImageFormat::TarXzMultiArtifactBundle
                }
                _ => SourceImageFormat::Qcow2,
            },
            preparation: match &instance.image.source {
                ImageSourcePolicy::KaliQemuArchive { .. } => {
                    PrepareBaseStrategy::SevenZipSingleQcow2
                }
                ImageSourcePolicy::WhonixLibvirtBundle { .. } => {
                    match instance.identity.profile_id.as_str() {
                        "whonix-workstation" => PrepareBaseStrategy::WhonixBundleWorkstation,
                        _ => PrepareBaseStrategy::WhonixBundleGateway,
                    }
                }
                _ => PrepareBaseStrategy::VerifiedQcow2,
            },
            base_volume_name: instance.image.base_volume_name.clone(),
        },
        instance,
        generation,
        observations,
        auto_boot,
        initial_state: "Preparing",
        steps,
        mutation: false,
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
            NetworkPolicy::WhonixGateway(_) => NetworkMode::WhonixGateway,
            NetworkPolicy::WhonixWorkstation(_) => NetworkMode::WhonixWorkstation,
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
    fn kali_lab_is_registered_as_persistent_manual_default_nat() {
        let profile = find("kali-lab").unwrap();
        assert_eq!(profile.guest_family, GuestFamily::Kali);
        assert_eq!(profile.kind, GuestProfileKind::KaliLab);
        assert_eq!(profile.instance_kind, InstanceKind::Lab);
        assert_eq!(profile.provisioning, ProvisioningPolicy::None);
        assert_eq!(
            profile.first_boot_success,
            FirstBootSuccessPolicy::ManualGuest
        );
        assert_eq!(profile.persistence, PersistencePolicy::Persistent);
        assert_eq!(profile.network_policy, NetworkPolicy::DefaultNat);
        assert_eq!(profile.firmware_machine, FirmwareMachinePolicy::BiosQ35);
    }

    #[test]
    fn kali_create_plan_is_manual_archive_without_seed_or_guest_requirements() {
        let profile = kali_lab();
        let instance = plan_instance(
            &hardware(16, 32),
            &profile,
            InstanceIdentity {
                name: InstanceName::new("kali-lab").unwrap(),
                profile_id: profile.id.clone(),
            },
        )
        .unwrap();
        let resources = generation("kali-lab", false);
        let plan = plan_create(instance, resources).unwrap();
        assert_eq!(
            plan.prepared_base.source_format,
            SourceImageFormat::SevenZipQcow2Archive
        );
        assert_eq!(
            plan.prepared_base.preparation,
            PrepareBaseStrategy::SevenZipSingleQcow2
        );
        assert!(plan.generation.seed.is_none());
        assert!(!plan.auto_boot);
        assert!(plan.observations.is_empty());
        assert_eq!(
            plan.instance.lifecycle,
            LifecyclePlan::PersistentManaged {
                state_directory_name: "kali-lab".to_owned()
            }
        );
    }

    #[test]
    fn kali_and_fedora_have_isolated_state_and_generation_resources() {
        let kali = generation("kali-lab", false);
        let fedora = generation("fedora-lab", true);
        assert_ne!(kali.overlay, fedora.overlay);
        assert_ne!(kali.seed, fedora.seed);
        assert_ne!("kali-lab", "fedora-lab");
    }

    #[test]
    fn whonix_gateway_is_registered_with_upstream_manual_policy() {
        let profile = find("whonix-gateway").unwrap();
        assert_eq!(profile.guest_family, GuestFamily::Whonix);
        assert_eq!(profile.kind, GuestProfileKind::WhonixGateway);
        assert_eq!(profile.instance_kind, InstanceKind::NetworkProvider);
        assert_eq!(profile.firmware_machine, FirmwareMachinePolicy::BiosQ35);
        assert_eq!(profile.provisioning, ProvisioningPolicy::None);
        assert_eq!(
            profile.first_boot_success,
            FirstBootSuccessPolicy::ManualGuest
        );
        assert_eq!(profile.persistence, PersistencePolicy::Persistent);
        let NetworkPolicy::WhonixGateway(link) = profile.network_policy else {
            panic!("Whonix Gateway must use its typed upstream network policy");
        };
        assert_eq!(link.endpoint, PointToPointEndpoint::Gateway);
        assert_eq!(link.pair_id.as_str(), "whonix-main-pair");
        assert_eq!((link.local_port, link.remote_port), (6688, 5577));
    }

    #[test]
    fn whonix_gateway_create_plan_has_bundle_no_seed_and_isolated_state() {
        let profile = whonix_gateway();
        let instance = plan_instance(
            &hardware(16, 32),
            &profile,
            InstanceIdentity {
                name: InstanceName::new("whonix-gateway").unwrap(),
                profile_id: profile.id.clone(),
            },
        )
        .unwrap();
        let plan = plan_create(instance, generation("whonix-gateway", false)).unwrap();
        assert_eq!(
            plan.prepared_base.source_format,
            SourceImageFormat::TarXzMultiArtifactBundle
        );
        assert_eq!(
            plan.prepared_base.preparation,
            PrepareBaseStrategy::WhonixBundleGateway
        );
        assert_eq!(
            plan.prepared_base.verification,
            ImageVerificationPolicy::WhonixDetachedOpenPgp
        );
        assert!(plan.generation.seed.is_none());
        assert!(!plan.auto_boot);
        assert!(plan.observations.is_empty());
        assert_ne!(
            plan.generation.overlay,
            generation("kali-lab", false).overlay
        );
        assert_eq!(
            plan.instance.lifecycle,
            LifecyclePlan::PersistentManaged {
                state_directory_name: "whonix-gateway".to_owned()
            }
        );
    }

    #[test]
    fn whonix_workstation_is_registered_with_complementary_manual_policy() {
        let profile = find("whonix-workstation").unwrap();
        assert_eq!(profile.guest_family, GuestFamily::Whonix);
        assert_eq!(profile.kind, GuestProfileKind::WhonixWorkstation);
        assert_eq!(profile.instance_kind, InstanceKind::NetworkConsumer);
        assert_eq!(profile.architecture, GuestArchitecture::X86_64);
        assert_eq!(profile.firmware_machine, FirmwareMachinePolicy::BiosQ35);
        assert_eq!(profile.provisioning, ProvisioningPolicy::None);
        assert_eq!(
            profile.first_boot_success,
            FirstBootSuccessPolicy::ManualGuest
        );
        assert_eq!(profile.persistence, PersistencePolicy::Persistent);
        let NetworkPolicy::WhonixWorkstation(link) = profile.network_policy else {
            panic!("Workstation must use its typed UDP policy");
        };
        assert_eq!(link.pair_id.as_str(), "whonix-main-pair");
        assert_eq!((link.local_port, link.remote_port), (5577, 6688));
    }

    #[test]
    fn whonix_workstation_plan_selects_same_bundle_workstation_role() {
        let profile = whonix_workstation();
        let instance = plan_instance(
            &hardware(16, 32),
            &profile,
            InstanceIdentity {
                name: InstanceName::new("whonix-workstation").unwrap(),
                profile_id: profile.id.clone(),
            },
        )
        .unwrap();
        let plan = plan_create(instance, generation("whonix-workstation", false)).unwrap();
        assert_eq!(
            plan.prepared_base.preparation,
            PrepareBaseStrategy::WhonixBundleWorkstation
        );
        assert_eq!(
            plan.prepared_base.base_volume_name,
            "forge-base-whonix-workstation-18.2.1.9.qcow2"
        );
        assert!(plan.generation.seed.is_none());
        assert!(!plan.auto_boot);
        assert!(plan.observations.is_empty());
    }

    #[test]
    fn whonix_pair_requires_exact_complement_and_shared_bundle() {
        let NetworkPolicy::WhonixGateway(gateway) = whonix_gateway().network_policy else {
            unreachable!()
        };
        let NetworkPolicy::WhonixWorkstation(workstation) = whonix_workstation().network_policy
        else {
            unreachable!()
        };
        let evidence = WhonixPairEvidence {
            gateway_instance: InstanceName::new("whonix-gateway").unwrap(),
            gateway_generation: "gen-123".to_owned(),
            gateway_domain_uuid: "uuid-123".to_owned(),
            gateway_link: gateway.clone(),
            bundle_identity: "bundle-1".to_owned(),
        };
        assert!(validate_whonix_pair(&evidence, &workstation, "bundle-1").is_ok());
        assert_eq!(
            validate_whonix_pair(&evidence, &workstation, "bundle-2"),
            Err(WhonixPairPlanError::BundleMismatch)
        );
        let mut wrong = workstation.clone();
        wrong.local_port = 6688;
        assert_eq!(
            validate_whonix_pair(&evidence, &wrong, "bundle-1"),
            Err(WhonixPairPlanError::EndpointMismatch)
        );
        let mut wrong_gateway = evidence.clone();
        wrong_gateway.gateway_link.pair_id = WhonixPairId::new("other-pair").unwrap();
        assert_eq!(
            validate_whonix_pair(&wrong_gateway, &workstation, "bundle-1"),
            Err(WhonixPairPlanError::GatewayIdentityMismatch)
        );
        let absent = WhonixPairEvidence {
            gateway_generation: String::new(),
            ..evidence.clone()
        };
        assert_eq!(
            validate_whonix_pair(&absent, &workstation, "bundle-1"),
            Err(WhonixPairPlanError::GatewayNotConsistent)
        );

        let planned = WhonixPairSnapshot {
            gateway: evidence.clone(),
            workstation_overlay: "whonix-workstation-gen.qcow2".to_owned(),
            workstation_base_digest: "workstation-digest".to_owned(),
        };
        assert!(revalidate_whonix_snapshot(&planned, &planned).is_ok());
        for changed in [
            {
                let mut value = planned.clone();
                value.gateway.gateway_generation = "gen-456".to_owned();
                value
            },
            {
                let mut value = planned.clone();
                value.gateway.gateway_link.local_port = 7000;
                value
            },
            {
                let mut value = planned.clone();
                value.gateway.gateway_domain_uuid = "uuid-456".to_owned();
                value
            },
            {
                let mut value = planned.clone();
                value.gateway.gateway_link.pair_id = WhonixPairId::new("other-pair").unwrap();
                value
            },
            {
                let mut value = planned.clone();
                value.gateway.bundle_identity = "bundle-2".to_owned();
                value
            },
            {
                let mut value = planned.clone();
                value.workstation_overlay = "other-overlay.qcow2".to_owned();
                value
            },
            {
                let mut value = planned.clone();
                value.workstation_base_digest = "other-digest".to_owned();
                value
            },
        ] {
            assert_eq!(
                revalidate_whonix_snapshot(&planned, &changed),
                Err(WhonixPairPlanError::SnapshotDrift)
            );
        }
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
        assert_eq!(
            names,
            [
                "fedora-lab",
                "kali-lab",
                "whonix-gateway",
                "whonix-workstation",
                "luna-dev-fedora",
                "luna-lab-fedora"
            ]
        );
    }

    // Exercises retained compatibility primitives without making the built-in
    // legacy profile selectable as a new V2.5 product.
    fn legacy_runtime_fixture() -> VmProfile {
        let mut profile = fedora_lab();
        profile.availability = ProductAvailability::Supported;
        profile
    }

    #[test]
    fn legacy_fedora_is_typed_compatibility_and_new_planning_refuses() {
        let profile = fedora_lab();
        assert_eq!(
            profile.availability,
            ProductAvailability::LegacyCompatibility(
                LegacyProductClassification::LegacyFedoraCloudNoCloud
            )
        );
        let error = plan_instance(
            &hardware(16, 32),
            &profile,
            InstanceIdentity {
                name: InstanceName::new("not-named-fedora").unwrap(),
                profile_id: profile.id.clone(),
            },
        )
        .unwrap_err();
        assert_eq!(error, FactoryPlanError::LegacyFedoraProductRetired);
    }

    #[test]
    fn one_profile_plans_isolated_instance_identities_and_state_paths() {
        let profile = legacy_runtime_fixture();
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
        let mut profile = legacy_runtime_fixture();
        profile.id = ProfileId::new("mock-debian").unwrap();
        profile.display_name = "Mock Debian".to_owned();
        profile.guest_family = GuestFamily::Debian;
        profile.kind = GuestProfileKind::DebianClean;
        profile.image_source = ImageSourcePolicy::VerifiedQcow2 {
            source_id: "mock-debian-12".to_owned(),
        };
        profile.image_verification = ImageVerificationPolicy::Sha256Digest;
        profile.provisioning = ProvisioningPolicy::None;
        profile.first_boot_success = FirstBootSuccessPolicy::ManualGuest;
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
        let mut profile = legacy_runtime_fixture();
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
        let profile = legacy_runtime_fixture();
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
        let profile = legacy_runtime_fixture();
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

    fn generation(instance: &str, with_seed: bool) -> GenerationResourceNames {
        GenerationResourceNames {
            generation_id: "gen-123e4567-e89b-42d3-a456-426614174000".to_owned(),
            overlay: format!("{instance}-123e4567-e89b-42d3-a456-426614174000.qcow2"),
            seed: with_seed
                .then(|| format!("{instance}-123e4567-e89b-42d3-a456-426614174000-seed.iso")),
        }
    }

    #[test]
    fn fedora_create_plan_keeps_full_verified_nocloud_policy() {
        let profile = legacy_runtime_fixture();
        let instance = plan_instance(
            &hardware(16, 32),
            &profile,
            InstanceIdentity {
                name: InstanceName::new("fedora-factory-test").unwrap(),
                profile_id: profile.id.clone(),
            },
        )
        .unwrap();
        let plan = plan_create(instance, generation("fedora-factory-test", true)).unwrap();
        assert_eq!(
            plan.prepared_base.verification,
            ImageVerificationPolicy::SignedSha256Checksums
        );
        assert!(matches!(
            plan.instance.provisioning,
            ProvisioningPolicy::NoCloud { .. }
        ));
        assert!(plan.auto_boot);
        assert_eq!(plan.observations.len(), 7);
        assert!(
            plan.observations
                .contains(&FirstBootObservation::GuestAgentAvailable)
        );
    }

    #[test]
    fn manual_guest_has_no_seed_boot_or_guest_observations() {
        let mut profile = legacy_runtime_fixture();
        profile.id = ProfileId::new("mock-manual").unwrap();
        profile.guest_family = GuestFamily::Debian;
        profile.provisioning = ProvisioningPolicy::None;
        profile.first_boot_success = FirstBootSuccessPolicy::ManualGuest;
        let instance = plan_instance(
            &hardware(16, 32),
            &profile,
            InstanceIdentity {
                name: InstanceName::new("manual-one").unwrap(),
                profile_id: profile.id.clone(),
            },
        )
        .unwrap();
        assert!(instance.storage.seed_volume_name.is_none());
        let plan = plan_create(instance, generation("manual-one", false)).unwrap();
        assert!(plan.generation.seed.is_none());
        assert!(!plan.auto_boot);
        assert!(plan.observations.is_empty());
    }

    #[test]
    fn generation_resources_are_isolated_between_instances() {
        let first = generation("factory-one", true);
        let second = generation("factory-two", true);
        assert_ne!(first.overlay, second.overlay);
        assert_ne!(first.seed, second.seed);
    }

    #[test]
    fn create_refuses_seed_role_mismatch_and_incoherent_cloud_policy() {
        let profile = legacy_runtime_fixture();
        let instance = plan_instance(
            &hardware(16, 32),
            &profile,
            InstanceIdentity {
                name: InstanceName::new("fedora-factory-test").unwrap(),
                profile_id: profile.id.clone(),
            },
        )
        .unwrap();
        assert_eq!(
            plan_create(instance, generation("fedora-factory-test", false)).unwrap_err(),
            FactoryPlanError::GenerationResourceMismatch
        );

        let mut invalid = profile;
        invalid.provisioning = ProvisioningPolicy::None;
        assert_eq!(
            plan_instance(
                &hardware(16, 32),
                &invalid,
                InstanceIdentity {
                    name: InstanceName::new("invalid-cloud").unwrap(),
                    profile_id: invalid.id.clone(),
                },
            )
            .unwrap_err(),
            FactoryPlanError::IncompatibleProvisioningPolicy
        );
    }
}
