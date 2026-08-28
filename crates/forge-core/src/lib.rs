//! Domain models shared by forge-virt crates.
//! This crate deliberately performs no I/O and starts no processes.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProfileId(String);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InstanceName(String);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityError {
    Empty,
    InvalidCharacter,
}

fn validate_identity(value: &str) -> Result<(), IdentityError> {
    if value.is_empty() {
        return Err(IdentityError::Empty);
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || !value.as_bytes()[0].is_ascii_lowercase()
    {
        return Err(IdentityError::InvalidCharacter);
    }
    Ok(())
}

macro_rules! identity_type {
    ($type:ident) => {
        impl $type {
            /// Creates a validated Forge identity.
            ///
            /// # Errors
            ///
            /// Rejects empty values and values outside lower-case DNS-label syntax.
            pub fn new(value: impl Into<String>) -> Result<Self, IdentityError> {
                let value = value.into();
                validate_identity(&value)?;
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $type {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

identity_type!(ProfileId);
identity_type!(InstanceName);

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("identity must not be empty"),
            Self::InvalidCharacter => formatter.write_str(
                "identity must start with a lower-case letter and contain only lower-case ASCII letters, digits, or hyphens",
            ),
        }
    }
}

impl std::error::Error for IdentityError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostState {
    Unsupported,
    Incomplete,
    Ready,
    Degraded,
}

impl fmt::Display for HostState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentState {
    Ready,
    Missing,
    Inactive,
    Unknown,
}

impl fmt::Display for ComponentState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpuInfo {
    pub model: String,
    pub logical_cores: usize,
    pub virtualization: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuInfo {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageDevice {
    pub name: String,
    pub size_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KvmInfo {
    pub present: bool,
    pub accessible: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardwareInfo {
    pub cpu: CpuInfo,
    pub memory_bytes: u64,
    pub gpus: Vec<GpuInfo>,
    pub storage: Vec<StorageDevice>,
    pub kvm: KvmInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistributionInfo {
    pub id: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
    pub is_fedora: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostComponents {
    pub kvm: ComponentState,
    pub libvirt: ComponentState,
    pub selinux: ComponentState,
    pub firewalld: ComponentState,
    pub virt_manager: ComponentState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostInfo {
    pub distribution: DistributionInfo,
    pub components: HostComponents,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorReport {
    pub state: HostState,
    pub hardware: HardwareInfo,
    pub host: HostInfo,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMode {
    Nat,
    Isolated,
    NoNetwork,
    WhonixInternal,
}

impl fmt::Display for NetworkMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Nat => "nat",
            Self::Isolated => "isolated",
            Self::NoNetwork => "none",
            Self::WhonixInternal => "whonix-internal",
        };
        formatter.write_str(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuMode {
    Virtual,
}

impl fmt::Display for GpuMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("virtual")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestProfileKind {
    LunaDevFedora,
    LunaLabFedora,
    FedoraLab,
    DebianClean,
    KaliLab,
    TsurugiLab,
    WhonixGateway,
    WhonixWorkstation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstanceKind {
    Lab,
    Development,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestFamily {
    Fedora,
    Debian,
    Kali,
    Other,
}

impl fmt::Display for GuestFamily {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}",
            match self {
                Self::Fedora => "fedora",
                Self::Debian => "debian",
                Self::Kali => "kali",
                Self::Other => "other",
            }
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestArchitecture {
    X86_64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirmwareMachinePolicy {
    UefiQ35,
    BiosQ35,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageSourcePolicy {
    FedoraCloudBase { release: String },
    KaliQemuArchive { release: String },
    VerifiedQcow2 { source_id: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageVerificationPolicy {
    SignedSha256Checksums,
    KaliDetachedSignedSha256Sums,
    Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvisioningPolicy {
    NoCloud {
        default_user: String,
        guest_agent: bool,
    },
    None,
}

/// Evidence required before a newly created generation may become Active.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirstBootSuccessPolicy {
    /// Boot and require the complete managed cloud-init observation flow.
    CloudInitManaged {
        expected_user: String,
        require_guest_agent: bool,
    },
    /// Boot and prove only that the domain reached the running state.
    BootOnly,
    /// Define a persistent guest for explicit operation through tools such as Virt-Manager.
    ManualGuest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkPolicy {
    DefaultNat,
    Isolated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphicsPolicy {
    Virtual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistencePolicy {
    Persistent,
    Disposable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmResources {
    pub cpu_ratio_per_mille: u16,
    pub min_vcpus: usize,
    pub max_vcpus: usize,
    pub memory_start_ratio_per_mille: u16,
    pub memory_max_ratio_per_mille: u16,
    pub min_memory_bytes: u64,
    pub host_memory_reserve_bytes: u64,
    pub disk_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmProfile {
    pub id: ProfileId,
    pub display_name: String,
    pub kind: GuestProfileKind,
    pub instance_kind: InstanceKind,
    pub guest_family: GuestFamily,
    pub architecture: GuestArchitecture,
    pub firmware_machine: FirmwareMachinePolicy,
    pub resources: VmResources,
    pub image_source: ImageSourcePolicy,
    pub image_verification: ImageVerificationPolicy,
    pub provisioning: ProvisioningPolicy,
    pub first_boot_success: FirstBootSuccessPolicy,
    pub network_policy: NetworkPolicy,
    pub graphics_policy: GraphicsPolicy,
    pub persistence: PersistencePolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerationResourceNames {
    pub generation_id: String,
    pub overlay: String,
    pub seed: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmResourcePlan {
    pub vcpus: usize,
    pub memory_start_bytes: u64,
    pub memory_max_bytes: u64,
    pub disk_bytes: u64,
    pub network: NetworkMode,
    pub gpu: GpuMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourcePlanError {
    InsufficientCpu {
        available: usize,
        required: usize,
    },
    InsufficientMemory {
        available_bytes: u64,
        required_bytes: u64,
    },
}

impl fmt::Display for ResourcePlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientCpu {
                available,
                required,
            } => write!(
                formatter,
                "host has {available} logical CPUs, profile requires at least {required}"
            ),
            Self::InsufficientMemory {
                available_bytes,
                required_bytes,
            } => write!(
                formatter,
                "host has {available_bytes} bytes available after reserve, profile requires at least {required_bytes}"
            ),
        }
    }
}

impl std::error::Error for ResourcePlanError {}

#[cfg(test)]
mod identity_tests {
    use super::*;

    #[test]
    fn profile_and_instance_are_distinct_validated_identities() {
        let profile = ProfileId::new("fedora-lab").unwrap();
        let instance = InstanceName::new("fedora-lab-01").unwrap();
        assert_eq!(profile.as_str(), "fedora-lab");
        assert_eq!(instance.as_str(), "fedora-lab-01");
        assert_eq!(
            InstanceName::new("Fedora Lab"),
            Err(IdentityError::InvalidCharacter)
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VmState {
    Running,
    Shutoff,
    Paused,
    Crashed,
    Unknown,
}

impl fmt::Display for VmState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Running => "running",
            Self::Shutoff => "shutoff",
            Self::Paused => "paused",
            Self::Crashed => "crashed",
            Self::Unknown => "unknown",
        };
        formatter.write_str(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainSummary {
    pub name: String,
    pub uuid: String,
    pub state: VmState,
    pub persistent: bool,
}

impl fmt::Display for DomainSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}\t{}\t{}\t{}",
            self.name,
            self.state,
            self.uuid,
            if self.persistent {
                "persistent"
            } else {
                "transient"
            }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCapabilities {
    pub cpu_model: String,
    pub logical_cpus: u32,
    pub memory_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibvirtInfo {
    pub uri: String,
    pub libvirt_version: String,
    pub hypervisor_version: String,
    pub hypervisor_type: String,
    pub alive: bool,
    pub capabilities: HostCapabilities,
    pub domains: Vec<DomainSummary>,
}
