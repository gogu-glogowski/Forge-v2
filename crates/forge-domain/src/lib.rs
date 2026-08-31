//! Pure VM domain specification, validation, and deterministic libvirt XML.

use forge_core::{
    FirmwareMachinePolicy, GpuMode, GraphicsPolicy, GuestProfileKind, NetworkMode, NetworkPolicy,
    PointToPointEndpoint, ProvisioningPolicy, UdpPointToPointLink, VmProfile, VmResourcePlan,
};
use std::fmt;

const MIB: u64 = 1024 * 1024;
const MEMORY_STEP_BYTES: u64 = 256 * MIB;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirmwareMode {
    Uefi,
    Bios,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    X86_64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineType {
    Q35,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuMode {
    HostPassthrough,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskFormat {
    Qcow2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskBus {
    Virtio,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphicsMode {
    Virtual,
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskSpec {
    pub source_file: String,
    pub format: DiskFormat,
    pub bus: DiskBus,
    pub capacity_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkInterfaceSpec {
    LibvirtNetwork {
        mode: NetworkMode,
        source_network: String,
    },
    PasstUplink,
    UdpPointToPoint(UdpPointToPointLink),
}

impl fmt::Display for NetworkInterfaceSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LibvirtNetwork {
                mode,
                source_network,
            } => write!(formatter, "{mode}:{source_network}"),
            Self::PasstUplink => formatter.write_str("passt-uplink"),
            Self::UdpPointToPoint(link) => write!(
                formatter,
                "udp-p2p:{}:{}->{}",
                link.pair_id, link.local_port, link.remote_port
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelTransport {
    Unix,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelTarget {
    Virtio,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelSpec {
    pub transport: ChannelTransport,
    pub target: ChannelTarget,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainMetadata {
    pub name: String,
    pub disk_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainSpec {
    pub name: String,
    pub uuid: Option<String>,
    pub architecture: Architecture,
    pub machine: MachineType,
    pub firmware: FirmwareMode,
    pub cpu_mode: CpuMode,
    pub vcpus: usize,
    pub memory_start_bytes: u64,
    pub memory_max_bytes: u64,
    pub disks: Vec<DiskSpec>,
    pub network_interfaces: Vec<NetworkInterfaceSpec>,
    pub network_policy: NetworkPolicy,
    pub channels: Vec<ChannelSpec>,
    pub guest_agent_required: bool,
    pub graphics: GraphicsMode,
    pub host_filesystems: Vec<String>,
    pub host_devices: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainSpecError {
    UnsupportedProfile(GuestProfileKind),
    InvalidName,
    InvalidUuid,
    InvalidDiskPath,
    ZeroVcpus,
    ZeroMemory,
    StartMemoryExceedsMaximum,
    UnalignedMemory,
    GpuPolicyMismatch,
    NetworkPolicyMismatch,
    HostFilesystemPassthrough,
    HostDevicePassthrough,
    InvalidDisk,
    InvalidNetworkInterface,
    GuestAgentChannelPolicy,
}

impl fmt::Display for DomainSpecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UnsupportedProfile(_) => "domain profile policy is unsupported",
            Self::InvalidName => "domain name must not be empty",
            Self::InvalidUuid => "domain UUID is invalid",
            Self::InvalidDiskPath => "disk path must be an absolute file path",
            Self::ZeroVcpus => "domain must have at least one vCPU",
            Self::ZeroMemory => "domain memory must be greater than zero",
            Self::StartMemoryExceedsMaximum => "initial memory exceeds maximum memory",
            Self::UnalignedMemory => "domain memory must be aligned to 256 MiB",
            Self::GpuPolicyMismatch => "domain graphics do not match profile policy",
            Self::NetworkPolicyMismatch => "domain network topology does not match profile policy",
            Self::HostFilesystemPassthrough => "host filesystem passthrough is forbidden",
            Self::HostDevicePassthrough => "host device passthrough is forbidden",
            Self::InvalidDisk => "domain requires one qcow2 file disk on virtio",
            Self::InvalidNetworkInterface => "network interface source is invalid",
            Self::GuestAgentChannelPolicy => {
                "domain guest-agent channel does not match provisioning policy"
            }
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for DomainSpecError {}

/// Builds the Fedora-Lab v1 domain specification without performing I/O.
///
/// # Errors
///
/// Returns a typed validation error when profile, plan, or metadata violates
/// the Fedora-Lab policy.
pub fn fedora_lab_spec(
    profile: &VmProfile,
    plan: &VmResourcePlan,
    metadata: DomainMetadata,
) -> Result<DomainSpec, DomainSpecError> {
    if profile.kind != GuestProfileKind::FedoraLab {
        return Err(DomainSpecError::UnsupportedProfile(profile.kind));
    }
    profile_spec(profile, plan, metadata)
}

/// Builds a domain specification from typed profile and instance policy.
///
/// # Errors
///
/// Returns a typed validation error when the resource plan or topology differs
/// from the selected profile.
pub fn profile_spec(
    profile: &VmProfile,
    plan: &VmResourcePlan,
    metadata: DomainMetadata,
) -> Result<DomainSpec, DomainSpecError> {
    let topology_role_valid = match profile.kind {
        GuestProfileKind::WhonixGateway => {
            matches!(profile.network_policy, NetworkPolicy::WhonixGateway(_))
        }
        GuestProfileKind::WhonixWorkstation => {
            matches!(profile.network_policy, NetworkPolicy::WhonixWorkstation(_))
        }
        _ => !matches!(
            profile.network_policy,
            NetworkPolicy::WhonixGateway(_) | NetworkPolicy::WhonixWorkstation(_)
        ),
    };
    if !topology_role_valid {
        return Err(DomainSpecError::NetworkPolicyMismatch);
    }
    let expected_gpu = match profile.graphics_policy {
        GraphicsPolicy::Virtual => GpuMode::Virtual,
    };
    if plan.gpu != expected_gpu {
        return Err(DomainSpecError::GpuPolicyMismatch);
    }
    let expected_network = match &profile.network_policy {
        NetworkPolicy::DefaultNat => NetworkMode::Nat,
        NetworkPolicy::Isolated => NetworkMode::Isolated,
        NetworkPolicy::WhonixGateway(_) => NetworkMode::WhonixGateway,
        NetworkPolicy::WhonixWorkstation(_) => NetworkMode::WhonixWorkstation,
    };
    if plan.network != expected_network {
        return Err(DomainSpecError::NetworkPolicyMismatch);
    }
    if metadata.name.trim().is_empty() {
        return Err(DomainSpecError::InvalidName);
    }
    if !metadata.disk_path.starts_with('/') {
        return Err(DomainSpecError::InvalidDiskPath);
    }

    let network_interfaces = match &profile.network_policy {
        NetworkPolicy::DefaultNat => vec![NetworkInterfaceSpec::LibvirtNetwork {
            mode: NetworkMode::Nat,
            source_network: "default".to_owned(),
        }],
        NetworkPolicy::Isolated => vec![],
        NetworkPolicy::WhonixGateway(link) => vec![
            NetworkInterfaceSpec::PasstUplink,
            NetworkInterfaceSpec::UdpPointToPoint(link.clone()),
        ],
        NetworkPolicy::WhonixWorkstation(link) => {
            vec![NetworkInterfaceSpec::UdpPointToPoint(link.clone())]
        }
    };
    let guest_agent_required = matches!(
        profile.provisioning,
        ProvisioningPolicy::NoCloud {
            guest_agent: true,
            ..
        }
    );
    let channels = if guest_agent_required {
        vec![ChannelSpec {
            transport: ChannelTransport::Unix,
            target: ChannelTarget::Virtio,
            name: "org.qemu.guest_agent.0".to_owned(),
        }]
    } else {
        vec![]
    };
    let spec = DomainSpec {
        name: metadata.name,
        uuid: None,
        architecture: Architecture::X86_64,
        machine: MachineType::Q35,
        firmware: match profile.firmware_machine {
            FirmwareMachinePolicy::UefiQ35 => FirmwareMode::Uefi,
            FirmwareMachinePolicy::BiosQ35 => FirmwareMode::Bios,
        },
        cpu_mode: CpuMode::HostPassthrough,
        vcpus: plan.vcpus,
        memory_start_bytes: round_memory_down(plan.memory_start_bytes),
        memory_max_bytes: round_memory_down(plan.memory_max_bytes),
        disks: vec![DiskSpec {
            source_file: metadata.disk_path,
            format: DiskFormat::Qcow2,
            bus: DiskBus::Virtio,
            capacity_bytes: plan.disk_bytes,
        }],
        network_interfaces,
        network_policy: profile.network_policy.clone(),
        channels,
        guest_agent_required,
        graphics: GraphicsMode::Virtual,
        host_filesystems: vec![],
        host_devices: vec![],
    };
    validate(&spec)?;
    Ok(spec)
}

/// Validates all local Fedora-Lab v1 invariants.
///
/// # Errors
///
/// Returns the first violated invariant.
pub fn validate(spec: &DomainSpec) -> Result<(), DomainSpecError> {
    if spec.name.trim().is_empty() {
        return Err(DomainSpecError::InvalidName);
    }
    if spec.uuid.as_deref().is_some_and(|uuid| {
        uuid.len() != 36
            || !uuid
                .chars()
                .all(|character| character.is_ascii_hexdigit() || character == '-')
    }) {
        return Err(DomainSpecError::InvalidUuid);
    }
    if spec.vcpus == 0 {
        return Err(DomainSpecError::ZeroVcpus);
    }
    if spec.memory_start_bytes == 0 || spec.memory_max_bytes == 0 {
        return Err(DomainSpecError::ZeroMemory);
    }
    if spec.memory_start_bytes > spec.memory_max_bytes {
        return Err(DomainSpecError::StartMemoryExceedsMaximum);
    }
    if !spec.memory_start_bytes.is_multiple_of(MEMORY_STEP_BYTES)
        || !spec.memory_max_bytes.is_multiple_of(MEMORY_STEP_BYTES)
    {
        return Err(DomainSpecError::UnalignedMemory);
    }
    if spec.graphics != GraphicsMode::Virtual {
        return Err(DomainSpecError::GpuPolicyMismatch);
    }
    if !spec.host_filesystems.is_empty() {
        return Err(DomainSpecError::HostFilesystemPassthrough);
    }
    if !spec.host_devices.is_empty() {
        return Err(DomainSpecError::HostDevicePassthrough);
    }
    if spec.disks.len() != 1
        || spec.disks[0].format != DiskFormat::Qcow2
        || spec.disks[0].bus != DiskBus::Virtio
        || spec.disks[0].capacity_bytes == 0
        || !spec.disks[0].source_file.starts_with('/')
    {
        return Err(DomainSpecError::InvalidDisk);
    }
    let network_valid = match &spec.network_policy {
        NetworkPolicy::DefaultNat => {
            spec.network_interfaces.len() == 1
                && matches!(
                    &spec.network_interfaces[0],
                    NetworkInterfaceSpec::LibvirtNetwork { mode: NetworkMode::Nat, source_network }
                        if source_network == "default"
                )
        }
        NetworkPolicy::Isolated => spec.network_interfaces.is_empty(),
        NetworkPolicy::WhonixGateway(expected) => {
            expected.endpoint == PointToPointEndpoint::Gateway
                && expected.is_valid()
                && spec.network_interfaces
                    == [
                        NetworkInterfaceSpec::PasstUplink,
                        NetworkInterfaceSpec::UdpPointToPoint(expected.clone()),
                    ]
        }
        NetworkPolicy::WhonixWorkstation(expected) => {
            expected.endpoint == PointToPointEndpoint::Workstation
                && expected.is_valid()
                && spec.network_interfaces
                    == [NetworkInterfaceSpec::UdpPointToPoint(expected.clone())]
        }
    };
    if !network_valid {
        return Err(DomainSpecError::NetworkPolicyMismatch);
    }
    let guest_agent_valid = if spec.guest_agent_required {
        spec.channels.len() == 1
            && spec.channels[0].transport == ChannelTransport::Unix
            && spec.channels[0].target == ChannelTarget::Virtio
            && spec.channels[0].name == "org.qemu.guest_agent.0"
    } else {
        spec.channels.is_empty()
    };
    if !guest_agent_valid {
        return Err(DomainSpecError::GuestAgentChannelPolicy);
    }
    Ok(())
}

/// Renders deterministic libvirt domain XML after validation.
///
/// # Errors
///
/// Returns a typed validation error and produces no XML when an invariant is
/// violated.
pub fn render_xml(spec: &DomainSpec) -> Result<String, DomainSpecError> {
    validate(spec)?;
    let disk = &spec.disks[0];
    let mut xml = XmlWriter::default();
    xml.line(0, "<domain type='kvm'>");
    xml.text_element(1, "name", &spec.name);
    if let Some(uuid) = &spec.uuid {
        xml.text_element(1, "uuid", uuid);
    }
    xml.line(
        1,
        &format!(
            "<memory unit='MiB'>{}</memory>",
            spec.memory_max_bytes / MIB
        ),
    );
    xml.line(
        1,
        &format!(
            "<currentMemory unit='MiB'>{}</currentMemory>",
            spec.memory_start_bytes / MIB
        ),
    );
    xml.line(
        1,
        &format!("<vcpu placement='static'>{}</vcpu>", spec.vcpus),
    );
    match spec.firmware {
        FirmwareMode::Uefi => {
            xml.line(1, "<os firmware='efi'>");
            xml.line(2, "<type arch='x86_64' machine='q35'>hvm</type>");
            xml.line(2, "<firmware>");
            xml.line(3, "<feature enabled='no' name='secure-boot'/>");
            xml.line(3, "<feature enabled='no' name='enrolled-keys'/>");
            xml.line(2, "</firmware>");
            xml.line(1, "</os>");
        }
        FirmwareMode::Bios => {
            xml.line(1, "<os>");
            xml.line(2, "<type arch='x86_64' machine='q35'>hvm</type>");
            xml.line(1, "</os>");
        }
    }
    xml.line(1, "<features>");
    xml.line(2, "<acpi/>");
    xml.line(2, "<apic/>");
    xml.line(1, "</features>");
    xml.line(1, "<cpu mode='host-passthrough'/>");
    xml.line(1, "<devices>");
    xml.line(2, "<disk type='file' device='disk'>");
    xml.line(3, "<driver name='qemu' type='qcow2'/>");
    xml.empty_element_with_attr(3, "source", "file", &disk.source_file);
    xml.line(3, "<target dev='vda' bus='virtio'/>");
    xml.line(2, "</disk>");
    for network in &spec.network_interfaces {
        match network {
            NetworkInterfaceSpec::LibvirtNetwork { source_network, .. } => {
                xml.line(2, "<interface type='network'>");
                xml.empty_element_with_attr(3, "source", "network", source_network);
                xml.line(3, "<model type='virtio'/>");
                xml.line(2, "</interface>");
            }
            NetworkInterfaceSpec::PasstUplink => {
                xml.line(2, "<interface type='user'>");
                xml.line(3, "<backend type='passt'/>");
                xml.line(3, "<model type='virtio'/>");
                xml.line(2, "</interface>");
            }
            NetworkInterfaceSpec::UdpPointToPoint(link) => {
                xml.line(2, "<interface type='udp'>");
                xml.line(
                    3,
                    &format!("<source address='127.0.0.1' port='{}'>", link.remote_port),
                );
                xml.line(
                    4,
                    &format!("<local address='127.0.0.1' port='{}'/>", link.local_port),
                );
                xml.line(3, "</source>");
                xml.line(3, "<model type='virtio'/>");
                xml.line(2, "</interface>");
            }
        }
    }
    for channel in &spec.channels {
        xml.line(2, "<channel type='unix'>");
        xml.line(
            3,
            &format!("<target type='virtio' name='{}'/>", channel.name),
        );
        xml.line(2, "</channel>");
    }
    xml.line(2, "<graphics type='spice' autoport='yes'/>");
    xml.line(2, "<video>");
    xml.line(3, "<model type='virtio' heads='1' primary='yes'/>");
    xml.line(2, "</video>");
    xml.line(1, "</devices>");
    xml.line(0, "</domain>");
    Ok(xml.finish())
}

#[derive(Default)]
struct XmlWriter {
    output: String,
}

impl XmlWriter {
    fn line(&mut self, indentation: usize, value: &str) {
        self.output.push_str(&"  ".repeat(indentation));
        self.output.push_str(value);
        self.output.push('\n');
    }

    fn text_element(&mut self, indentation: usize, name: &str, value: &str) {
        self.line(
            indentation,
            &format!("<{name}>{}</{name}>", escape_xml(value)),
        );
    }

    fn empty_element_with_attr(
        &mut self,
        indentation: usize,
        name: &str,
        attribute: &str,
        value: &str,
    ) {
        self.line(
            indentation,
            &format!("<{name} {attribute}='{}'/>", escape_xml(value)),
        );
    }

    fn finish(self) -> String {
        self.output
    }
}

fn escape_xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

const fn round_memory_down(bytes: u64) -> u64 {
    bytes / MEMORY_STEP_BYTES * MEMORY_STEP_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;
    use forge_core::{
        FirmwareMachinePolicy, GraphicsPolicy, GuestArchitecture, GuestFamily, ImageSourcePolicy,
        ImageVerificationPolicy, NetworkPolicy, PersistencePolicy, PointToPointEndpoint, ProfileId,
        ProvisioningPolicy, UdpPointToPointLink, VmResources, WhonixPairId,
    };

    const GIB: u64 = 1024 * 1024 * 1024;
    const UPSTREAM_GATEWAY_INTERFACES: &str =
        include_str!("../tests/fixtures/whonix-gateway-interfaces.xml");
    const UPSTREAM_WORKSTATION_INTERFACES: &str =
        include_str!("../tests/fixtures/whonix-workstation-interfaces.xml");

    fn profile() -> VmProfile {
        VmProfile {
            id: ProfileId::new("fedora-lab").unwrap(),
            display_name: "Fedora Lab".to_owned(),
            kind: GuestProfileKind::FedoraLab,
            instance_kind: forge_core::InstanceKind::Lab,
            guest_family: GuestFamily::Fedora,
            architecture: GuestArchitecture::X86_64,
            firmware_machine: FirmwareMachinePolicy::UefiQ35,
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
            image_source: ImageSourcePolicy::FedoraCloudBase {
                release: "44".to_owned(),
            },
            image_verification: ImageVerificationPolicy::SignedSha256Checksums,
            provisioning: ProvisioningPolicy::NoCloud {
                default_user: "forge".to_owned(),
                guest_agent: true,
            },
            first_boot_success: forge_core::FirstBootSuccessPolicy::CloudInitManaged {
                expected_user: "forge".to_owned(),
                require_guest_agent: true,
            },
            network_policy: NetworkPolicy::DefaultNat,
            graphics_policy: GraphicsPolicy::Virtual,
            persistence: PersistencePolicy::Persistent,
            availability: forge_core::ProductAvailability::Supported,
        }
    }

    fn plan() -> VmResourcePlan {
        VmResourcePlan {
            vcpus: 4,
            memory_start_bytes: 6 * GIB,
            memory_max_bytes: 8 * GIB,
            disk_bytes: 64 * GIB,
            network: NetworkMode::Nat,
            gpu: GpuMode::Virtual,
        }
    }

    fn whonix_link(endpoint: PointToPointEndpoint) -> UdpPointToPointLink {
        let gateway = UdpPointToPointLink {
            pair_id: WhonixPairId::new("whonix-pair-one").unwrap(),
            endpoint: PointToPointEndpoint::Gateway,
            local_port: 6688,
            remote_port: 5577,
        };
        match endpoint {
            PointToPointEndpoint::Gateway => gateway,
            PointToPointEndpoint::Workstation => gateway.complement(),
        }
    }

    fn whonix_spec(endpoint: PointToPointEndpoint) -> DomainSpec {
        let mut profile = profile();
        profile.provisioning = ProvisioningPolicy::None;
        profile.kind = match endpoint {
            PointToPointEndpoint::Gateway => GuestProfileKind::WhonixGateway,
            PointToPointEndpoint::Workstation => GuestProfileKind::WhonixWorkstation,
        };
        profile.network_policy = match endpoint {
            PointToPointEndpoint::Gateway => NetworkPolicy::WhonixGateway(whonix_link(endpoint)),
            PointToPointEndpoint::Workstation => {
                NetworkPolicy::WhonixWorkstation(whonix_link(endpoint))
            }
        };
        let mut resources = plan();
        resources.network = match endpoint {
            PointToPointEndpoint::Gateway => NetworkMode::WhonixGateway,
            PointToPointEndpoint::Workstation => NetworkMode::WhonixWorkstation,
        };
        profile_spec(
            &profile,
            &resources,
            DomainMetadata {
                name: match endpoint {
                    PointToPointEndpoint::Gateway => "gateway-test",
                    PointToPointEndpoint::Workstation => "workstation-test",
                }
                .to_owned(),
                disk_path: "/pool/whonix.qcow2".to_owned(),
            },
        )
        .unwrap()
    }

    fn spec() -> DomainSpec {
        fedora_lab_spec(
            &profile(),
            &plan(),
            DomainMetadata {
                name: "fedora-lab".to_owned(),
                disk_path: "/var/lib/libvirt/images/fedora-lab.qcow2".to_owned(),
            },
        )
        .unwrap()
    }

    #[test]
    fn fedora_lab_xml_is_deterministic() {
        let expected = "<domain type='kvm'>\n  <name>fedora-lab</name>\n  <memory unit='MiB'>8192</memory>\n  <currentMemory unit='MiB'>6144</currentMemory>\n  <vcpu placement='static'>4</vcpu>\n  <os firmware='efi'>\n    <type arch='x86_64' machine='q35'>hvm</type>\n    <firmware>\n      <feature enabled='no' name='secure-boot'/>\n      <feature enabled='no' name='enrolled-keys'/>\n    </firmware>\n  </os>\n  <features>\n    <acpi/>\n    <apic/>\n  </features>\n  <cpu mode='host-passthrough'/>\n  <devices>\n    <disk type='file' device='disk'>\n      <driver name='qemu' type='qcow2'/>\n      <source file='/var/lib/libvirt/images/fedora-lab.qcow2'/>\n      <target dev='vda' bus='virtio'/>\n    </disk>\n    <interface type='network'>\n      <source network='default'/>\n      <model type='virtio'/>\n    </interface>\n    <channel type='unix'>\n      <target type='virtio' name='org.qemu.guest_agent.0'/>\n    </channel>\n    <graphics type='spice' autoport='yes'/>\n    <video>\n      <model type='virtio' heads='1' primary='yes'/>\n    </video>\n  </devices>\n</domain>\n";
        assert_eq!(render_xml(&spec()).unwrap(), expected);
        assert_eq!(render_xml(&spec()).unwrap(), expected);
    }

    #[test]
    fn spec_uses_resources_from_plan() {
        let spec = spec();
        assert_eq!(spec.vcpus, 4);
        assert_eq!(spec.memory_start_bytes, 6 * GIB);
        assert_eq!(spec.memory_max_bytes, 8 * GIB);
        assert_eq!(spec.disks[0].capacity_bytes, 64 * GIB);
    }

    #[test]
    fn memory_is_rounded_down_without_exceeding_plan() {
        let mut unaligned_plan = plan();
        unaligned_plan.memory_start_bytes = 6 * GIB + 200 * MIB;
        unaligned_plan.memory_max_bytes = 8 * GIB + 200 * MIB;
        let spec = fedora_lab_spec(
            &profile(),
            &unaligned_plan,
            DomainMetadata {
                name: "fedora-lab".to_owned(),
                disk_path: "/var/lib/libvirt/images/fedora-lab.qcow2".to_owned(),
            },
        )
        .unwrap();
        assert_eq!(spec.memory_start_bytes, 6 * GIB);
        assert_eq!(spec.memory_max_bytes, 8 * GIB);
        assert!(spec.memory_start_bytes <= unaligned_plan.memory_start_bytes);
        assert!(spec.memory_max_bytes <= unaligned_plan.memory_max_bytes);
        assert!(spec.memory_start_bytes <= spec.memory_max_bytes);
    }

    #[test]
    fn xml_has_q35_uefi_virtio_nat_and_virtual_gpu() {
        let xml = render_xml(&spec()).unwrap();
        for fragment in [
            "<os firmware='efi'>",
            "machine='q35'",
            "<cpu mode='host-passthrough'/>",
            "type='qcow2'",
            "bus='virtio'",
            "<source network='default'/>",
            "<video>",
            "<model type='virtio' heads='1' primary='yes'/>",
        ] {
            assert!(xml.contains(fragment), "missing XML fragment: {fragment}");
        }
    }

    #[test]
    fn xml_has_no_host_mount_or_device_passthrough() {
        let xml = render_xml(&spec()).unwrap();
        assert!(!xml.contains("<filesystem"));
        assert!(!xml.contains("<hostdev"));
        assert!(!xml.contains("type='block'"));
    }

    #[test]
    fn xml_has_exactly_one_virtio_guest_agent_channel() {
        let valid_spec = spec();
        let xml = render_xml(&valid_spec).unwrap();
        assert_eq!(xml.matches("<channel type='unix'>").count(), 1);
        assert_eq!(
            xml.matches("<target type='virtio' name='org.qemu.guest_agent.0'/>")
                .count(),
            1
        );
        assert!(!xml.contains("<filesystem"));
        assert!(!xml.contains("<hostdev"));

        let mut missing = valid_spec.clone();
        missing.channels.clear();
        assert_eq!(
            validate(&missing),
            Err(DomainSpecError::GuestAgentChannelPolicy)
        );

        let mut duplicate = valid_spec;
        duplicate.channels.push(duplicate.channels[0].clone());
        assert_eq!(
            validate(&duplicate),
            Err(DomainSpecError::GuestAgentChannelPolicy)
        );
    }

    #[test]
    fn rejects_invalid_resource_plan() {
        let mut plan = plan();
        plan.vcpus = 0;
        let error = fedora_lab_spec(
            &profile(),
            &plan,
            DomainMetadata {
                name: "fedora-lab".to_owned(),
                disk_path: "/var/lib/libvirt/images/fedora-lab.qcow2".to_owned(),
            },
        )
        .unwrap_err();
        assert_eq!(error, DomainSpecError::ZeroVcpus);
    }

    #[test]
    fn rejects_network_policy_mismatch() {
        let mut plan = plan();
        plan.network = NetworkMode::Isolated;
        let error = fedora_lab_spec(
            &profile(),
            &plan,
            DomainMetadata {
                name: "fedora-lab".to_owned(),
                disk_path: "/var/lib/libvirt/images/fedora-lab.qcow2".to_owned(),
            },
        )
        .unwrap_err();
        assert_eq!(error, DomainSpecError::NetworkPolicyMismatch);
    }

    #[test]
    fn rejects_non_virtual_graphics_and_host_extensions() {
        let mut invalid_spec = spec();
        invalid_spec.graphics = GraphicsMode::Disabled;
        assert_eq!(
            validate(&invalid_spec),
            Err(DomainSpecError::GpuPolicyMismatch)
        );

        let mut invalid_spec = spec();
        invalid_spec
            .host_devices
            .push("pci:0000:01:00.0".to_owned());
        assert_eq!(
            validate(&invalid_spec),
            Err(DomainSpecError::HostDevicePassthrough)
        );

        let mut invalid_spec = spec();
        invalid_spec.host_filesystems.push("/home".to_owned());
        assert_eq!(
            validate(&invalid_spec),
            Err(DomainSpecError::HostFilesystemPassthrough)
        );
    }

    #[test]
    fn generic_non_fedora_profile_builds_without_nocloud_assumptions() {
        let mut profile = profile();
        profile.id = ProfileId::new("mock-debian").unwrap();
        profile.kind = GuestProfileKind::DebianClean;
        profile.guest_family = GuestFamily::Debian;
        profile.provisioning = ProvisioningPolicy::None;
        profile.network_policy = NetworkPolicy::Isolated;
        let mut resources = plan();
        resources.network = NetworkMode::Isolated;
        let spec = profile_spec(
            &profile,
            &resources,
            DomainMetadata {
                name: "debian-test".to_owned(),
                disk_path: "/pool/debian-test.qcow2".to_owned(),
            },
        )
        .unwrap();
        assert!(spec.network_interfaces.is_empty());
        assert!(spec.channels.is_empty());
        let xml = render_xml(&spec).unwrap();
        assert!(!xml.contains("<interface"));
        assert!(!xml.contains("<channel"));
    }

    #[test]
    fn kali_manual_guest_uses_bios_q35_without_guest_agent_channel() {
        let profile = forge_profiles::kali_lab();
        let resources = forge_profiles::plan(
            &forge_core::HardwareInfo {
                cpu: forge_core::CpuInfo {
                    model: "test".to_owned(),
                    logical_cores: 8,
                    virtualization: true,
                },
                memory_bytes: 16 * 1024 * 1024 * 1024,
                gpus: vec![],
                storage: vec![],
                kvm: forge_core::KvmInfo {
                    present: true,
                    accessible: true,
                },
            },
            &profile,
        )
        .unwrap();
        let spec = profile_spec(
            &profile,
            &resources,
            DomainMetadata {
                name: "kali-lab".to_owned(),
                disk_path: "/pool/kali.qcow2".to_owned(),
            },
        )
        .unwrap();
        assert_eq!(spec.firmware, FirmwareMode::Bios);
        assert!(!spec.guest_agent_required);
        assert!(spec.channels.is_empty());
        let xml = render_xml(&spec).unwrap();
        assert!(!xml.contains("firmware='efi'"));
        assert!(!xml.contains("org.qemu.guest_agent.0"));
    }

    #[test]
    fn whonix_gateway_profile_renders_exact_upstream_critical_topology() {
        let profile = forge_profiles::whonix_gateway();
        let resources = forge_profiles::plan(
            &forge_core::HardwareInfo {
                cpu: forge_core::CpuInfo {
                    model: "test".to_owned(),
                    logical_cores: 8,
                    virtualization: true,
                },
                memory_bytes: 16 * GIB,
                gpus: vec![],
                storage: vec![],
                kvm: forge_core::KvmInfo {
                    present: true,
                    accessible: true,
                },
            },
            &profile,
        )
        .unwrap();
        let spec = profile_spec(
            &profile,
            &resources,
            DomainMetadata {
                name: "whonix-gateway".to_owned(),
                disk_path: "/pool/whonix-gateway.qcow2".to_owned(),
            },
        )
        .unwrap();
        assert_eq!(spec.firmware, FirmwareMode::Bios);
        assert_eq!(spec.machine, MachineType::Q35);
        assert_eq!(spec.disks[0].bus, DiskBus::Virtio);
        assert_eq!(spec.network_interfaces.len(), 2);
        assert_eq!(
            spec.network_interfaces[0],
            NetworkInterfaceSpec::PasstUplink
        );
        assert!(matches!(
            &spec.network_interfaces[1],
            NetworkInterfaceSpec::UdpPointToPoint(link)
                if link.endpoint == PointToPointEndpoint::Gateway
                    && link.local_port == 6688
                    && link.remote_port == 5577
        ));
        assert!(!spec.guest_agent_required);
        assert!(spec.channels.is_empty());
        let xml = render_xml(&spec).unwrap();
        assert!(xml.contains("<interface type='user'>"));
        assert!(xml.contains("<backend type='passt'/>"));
        assert!(xml.contains("<interface type='udp'>"));
        assert!(!xml.contains("source network='default'"));
        assert!(!xml.contains("org.qemu.guest_agent.0"));
    }

    #[test]
    fn whonix_workstation_profile_renders_only_complementary_udp_topology() {
        let profile = forge_profiles::whonix_workstation();
        let resources = forge_profiles::plan(
            &forge_core::HardwareInfo {
                cpu: forge_core::CpuInfo {
                    model: "test".to_owned(),
                    logical_cores: 8,
                    virtualization: true,
                },
                memory_bytes: 16 * GIB,
                gpus: vec![],
                storage: vec![],
                kvm: forge_core::KvmInfo {
                    present: true,
                    accessible: true,
                },
            },
            &profile,
        )
        .unwrap();
        let spec = profile_spec(
            &profile,
            &resources,
            DomainMetadata {
                name: "whonix-workstation".to_owned(),
                disk_path: "/pool/whonix-workstation.qcow2".to_owned(),
            },
        )
        .unwrap();
        assert_eq!(spec.network_interfaces.len(), 1);
        assert!(matches!(
            &spec.network_interfaces[0],
            NetworkInterfaceSpec::UdpPointToPoint(link)
                if link.endpoint == PointToPointEndpoint::Workstation
                    && link.pair_id.as_str() == "whonix-main-pair"
                    && link.local_port == 5577
                    && link.remote_port == 6688
        ));
        assert!(!spec.guest_agent_required);
        assert!(spec.channels.is_empty());
        let xml = render_xml(&spec).unwrap();
        assert_eq!(xml.matches("<interface").count(), 1);
        assert!(xml.contains("<interface type='udp'>"));
        assert!(xml.contains("port='6688'>"));
        assert!(xml.contains("<local address='127.0.0.1' port='5577'/>"));
        assert!(!xml.contains("type='user'"));
        assert!(!xml.contains("type='network'"));
        assert!(!xml.contains("source network='default'"));
    }

    #[test]
    fn manual_topology_change_is_typed_drift_not_absorbed() {
        let mut changed = spec();
        changed.network_interfaces[0] = NetworkInterfaceSpec::LibvirtNetwork {
            mode: NetworkMode::Nat,
            source_network: "manually-edited".to_owned(),
        };
        assert_eq!(
            validate(&changed),
            Err(DomainSpecError::NetworkPolicyMismatch)
        );
    }

    #[test]
    fn upstream_gateway_fixture_has_passt_then_exact_udp_link() {
        let spec = whonix_spec(PointToPointEndpoint::Gateway);
        assert_eq!(
            spec.network_interfaces,
            [
                NetworkInterfaceSpec::PasstUplink,
                NetworkInterfaceSpec::UdpPointToPoint(whonix_link(PointToPointEndpoint::Gateway)),
            ]
        );
        let xml = render_xml(&spec).unwrap();
        assert!(UPSTREAM_GATEWAY_INTERFACES.contains("<interface type='user'>"));
        assert!(UPSTREAM_GATEWAY_INTERFACES.contains("port='5577'>"));
        assert!(UPSTREAM_GATEWAY_INTERFACES.contains("port='6688'/>"));
        assert!(xml.contains("<interface type='user'>\n      <backend type='passt'/>"));
        assert!(xml.contains(
            "<interface type='udp'>\n      <source address='127.0.0.1' port='5577'>\n        <local address='127.0.0.1' port='6688'/>"
        ));
        assert!(!xml.contains("source network='default'"));
    }

    #[test]
    fn upstream_workstation_fixture_is_complementary_and_has_no_uplink() {
        let gateway = whonix_link(PointToPointEndpoint::Gateway);
        let workstation = whonix_spec(PointToPointEndpoint::Workstation);
        let NetworkInterfaceSpec::UdpPointToPoint(workstation_link) =
            &workstation.network_interfaces[0]
        else {
            panic!("workstation must have exactly one UDP point-to-point link");
        };
        assert!(gateway.is_complementary_to(workstation_link));
        let xml = render_xml(&workstation).unwrap();
        assert!(!UPSTREAM_WORKSTATION_INTERFACES.contains("type='user'"));
        assert!(UPSTREAM_WORKSTATION_INTERFACES.contains("port='6688'>"));
        assert!(UPSTREAM_WORKSTATION_INTERFACES.contains("port='5577'/>"));
        assert_eq!(xml.matches("<interface").count(), 1);
        assert!(xml.contains("port='6688'>\n        <local address='127.0.0.1' port='5577'/"));
        assert!(!xml.contains("type='user'"));
        assert!(!xml.contains("type='network'"));
    }

    #[test]
    fn whonix_topology_drift_and_extra_interfaces_are_refused() {
        let mut changed_ports = whonix_spec(PointToPointEndpoint::Gateway);
        changed_ports.network_interfaces[1] =
            NetworkInterfaceSpec::UdpPointToPoint(UdpPointToPointLink {
                remote_port: 7788,
                ..whonix_link(PointToPointEndpoint::Gateway)
            });
        assert_eq!(
            validate(&changed_ports),
            Err(DomainSpecError::NetworkPolicyMismatch)
        );

        let mut wrong_transport = whonix_spec(PointToPointEndpoint::Gateway);
        wrong_transport.network_interfaces[1] = NetworkInterfaceSpec::LibvirtNetwork {
            mode: NetworkMode::Nat,
            source_network: "default".to_owned(),
        };
        assert_eq!(
            validate(&wrong_transport),
            Err(DomainSpecError::NetworkPolicyMismatch)
        );

        let mut extra = whonix_spec(PointToPointEndpoint::Workstation);
        extra
            .network_interfaces
            .push(NetworkInterfaceSpec::PasstUplink);
        assert_eq!(
            validate(&extra),
            Err(DomainSpecError::NetworkPolicyMismatch)
        );

        let mut nat_fallback = whonix_spec(PointToPointEndpoint::Workstation);
        nat_fallback.network_policy = NetworkPolicy::DefaultNat;
        assert_eq!(
            validate(&nat_fallback),
            Err(DomainSpecError::NetworkPolicyMismatch)
        );

        let mut workstation_profile = profile();
        workstation_profile.kind = GuestProfileKind::WhonixWorkstation;
        assert_eq!(
            profile_spec(
                &workstation_profile,
                &plan(),
                DomainMetadata {
                    name: "workstation-with-nat".to_owned(),
                    disk_path: "/pool/whonix.qcow2".to_owned(),
                }
            ),
            Err(DomainSpecError::NetworkPolicyMismatch)
        );
    }

    #[test]
    fn escapes_domain_metadata_in_xml() {
        let mut spec = spec();
        spec.name = "fedora<&'lab".to_owned();
        let xml = render_xml(&spec).unwrap();
        assert!(xml.contains("<name>fedora&lt;&amp;&apos;lab</name>"));
    }
}
