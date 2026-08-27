//! Pure VM domain specification, validation, and deterministic libvirt XML.

use forge_core::{GpuMode, GuestProfileKind, NetworkMode, VmProfile, VmResourcePlan};
use std::fmt;

const MIB: u64 = 1024 * 1024;
const MEMORY_STEP_BYTES: u64 = 256 * MIB;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirmwareMode {
    Uefi,
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
pub struct NetworkInterfaceSpec {
    pub mode: NetworkMode,
    pub source_network: String,
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
}

impl fmt::Display for DomainSpecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UnsupportedProfile(_) => "only the fedora-lab domain profile is supported",
            Self::InvalidName => "domain name must not be empty",
            Self::InvalidUuid => "domain UUID is invalid",
            Self::InvalidDiskPath => "disk path must be an absolute file path",
            Self::ZeroVcpus => "domain must have at least one vCPU",
            Self::ZeroMemory => "domain memory must be greater than zero",
            Self::StartMemoryExceedsMaximum => "initial memory exceeds maximum memory",
            Self::UnalignedMemory => "domain memory must be aligned to 256 MiB",
            Self::GpuPolicyMismatch => "fedora-lab requires virtual graphics",
            Self::NetworkPolicyMismatch => "fedora-lab requires one NAT network interface",
            Self::HostFilesystemPassthrough => "host filesystem passthrough is forbidden",
            Self::HostDevicePassthrough => "host device passthrough is forbidden",
            Self::InvalidDisk => "fedora-lab requires one qcow2 file disk on virtio",
            Self::InvalidNetworkInterface => "network interface source is invalid",
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
    if profile.gpu != GpuMode::Virtual || plan.gpu != profile.gpu {
        return Err(DomainSpecError::GpuPolicyMismatch);
    }
    if profile.network != NetworkMode::Nat || plan.network != profile.network {
        return Err(DomainSpecError::NetworkPolicyMismatch);
    }
    if metadata.name.trim().is_empty() {
        return Err(DomainSpecError::InvalidName);
    }
    if !metadata.disk_path.starts_with('/') {
        return Err(DomainSpecError::InvalidDiskPath);
    }

    let spec = DomainSpec {
        name: metadata.name,
        uuid: None,
        architecture: Architecture::X86_64,
        machine: MachineType::Q35,
        firmware: FirmwareMode::Uefi,
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
        network_interfaces: vec![NetworkInterfaceSpec {
            mode: NetworkMode::Nat,
            source_network: "default".to_owned(),
        }],
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
    if spec.network_interfaces.len() != 1
        || spec.network_interfaces[0].mode != NetworkMode::Nat
        || spec.network_interfaces[0].source_network != "default"
    {
        return Err(DomainSpecError::NetworkPolicyMismatch);
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
    let network = &spec.network_interfaces[0];
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
    xml.line(1, "<os firmware='efi'>");
    xml.line(2, "<type arch='x86_64' machine='q35'>hvm</type>");
    xml.line(2, "<firmware>");
    xml.line(3, "<feature enabled='no' name='secure-boot'/>");
    xml.line(3, "<feature enabled='no' name='enrolled-keys'/>");
    xml.line(2, "</firmware>");
    xml.line(1, "</os>");
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
    xml.line(2, "<interface type='network'>");
    xml.empty_element_with_attr(3, "source", "network", &network.source_network);
    xml.line(3, "<model type='virtio'/>");
    xml.line(2, "</interface>");
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
    use forge_core::VmResources;

    const GIB: u64 = 1024 * 1024 * 1024;

    fn profile() -> VmProfile {
        VmProfile {
            name: "fedora-lab".to_owned(),
            kind: GuestProfileKind::FedoraLab,
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
            network: NetworkMode::Nat,
            gpu: GpuMode::Virtual,
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
        let expected = "<domain type='kvm'>\n  <name>fedora-lab</name>\n  <memory unit='MiB'>8192</memory>\n  <currentMemory unit='MiB'>6144</currentMemory>\n  <vcpu placement='static'>4</vcpu>\n  <os firmware='efi'>\n    <type arch='x86_64' machine='q35'>hvm</type>\n    <firmware>\n      <feature enabled='no' name='secure-boot'/>\n      <feature enabled='no' name='enrolled-keys'/>\n    </firmware>\n  </os>\n  <features>\n    <acpi/>\n    <apic/>\n  </features>\n  <cpu mode='host-passthrough'/>\n  <devices>\n    <disk type='file' device='disk'>\n      <driver name='qemu' type='qcow2'/>\n      <source file='/var/lib/libvirt/images/fedora-lab.qcow2'/>\n      <target dev='vda' bus='virtio'/>\n    </disk>\n    <interface type='network'>\n      <source network='default'/>\n      <model type='virtio'/>\n    </interface>\n    <graphics type='spice' autoport='yes'/>\n    <video>\n      <model type='virtio' heads='1' primary='yes'/>\n    </video>\n  </devices>\n</domain>\n";
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
    fn escapes_domain_metadata_in_xml() {
        let mut spec = spec();
        spec.name = "fedora<&'lab".to_owned();
        let xml = render_xml(&spec).unwrap();
        assert!(xml.contains("<name>fedora&lt;&amp;&apos;lab</name>"));
    }
}
