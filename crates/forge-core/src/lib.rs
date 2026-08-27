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
