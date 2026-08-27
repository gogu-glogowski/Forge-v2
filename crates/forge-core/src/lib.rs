//! Domain models shared by forge-virt crates.
//! This crate deliberately performs no I/O and starts no processes.

use std::fmt;

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
    pub name: String,
    pub kind: GuestProfileKind,
    pub resources: VmResources,
    pub network: NetworkMode,
    pub gpu: GpuMode,
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
