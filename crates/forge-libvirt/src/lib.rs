//! Read-only adapter for the local libvirt API.

use forge_core::{DomainSummary, HostCapabilities, LibvirtInfo, VmState};
use std::fmt;
use virt::connect::Connect;
use virt::domain::Domain;
use virt::error::Error as VirtError;
use virt::sys;

pub const LOCAL_QEMU_URI: &str = "qemu:///system";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LibvirtError {
    Connection { uri: String, message: String },
    Query { operation: String, message: String },
    UnsupportedDomainState(u32),
    Mapping { field: String, message: String },
}

impl fmt::Display for LibvirtError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connection { uri, message } => {
                write!(formatter, "cannot connect to libvirt at {uri}: {message}")
            }
            Self::Query { operation, message } => {
                write!(formatter, "libvirt query {operation} failed: {message}")
            }
            Self::UnsupportedDomainState(state) => {
                write!(formatter, "unsupported libvirt domain state: {state}")
            }
            Self::Mapping { field, message } => {
                write!(formatter, "cannot map libvirt field {field}: {message}")
            }
        }
    }
}

impl std::error::Error for LibvirtError {}

/// Discovers the system libvirt/QEMU connection using read-only API calls.
///
/// # Errors
///
/// Returns a structured integration error when connecting, querying libvirt,
/// or mapping a domain state fails.
pub fn discover_local() -> Result<LibvirtInfo, LibvirtError> {
    discover(LOCAL_QEMU_URI)
}

/// Discovers a libvirt URI using an explicitly read-only connection.
///
/// # Errors
///
/// Returns a structured integration error when connecting, querying libvirt,
/// or mapping a domain state fails.
pub fn discover(uri: &str) -> Result<LibvirtInfo, LibvirtError> {
    let connection =
        Connect::open_read_only(Some(uri)).map_err(|error| LibvirtError::Connection {
            uri: uri.to_owned(),
            message: error.to_string(),
        })?;

    let active_uri = query("get URI", connection.get_uri())?;
    let libvirt_version =
        format_version(query("get libvirt version", connection.get_lib_version())?);
    let hypervisor_version = format_version(query(
        "get hypervisor version",
        connection.get_hyp_version(),
    )?);
    let hypervisor_type = query("get hypervisor type", connection.get_type())?;
    let alive = query("check connection", connection.is_alive())?;
    let node = query("get node capabilities", connection.get_node_info())?;
    let memory_bytes = node
        .memory
        .checked_mul(1024)
        .ok_or_else(|| LibvirtError::Mapping {
            field: "node memory".to_owned(),
            message: "KiB to bytes conversion overflowed".to_owned(),
        })?;
    let domains = query("list all domains", connection.list_all_domains(0))?
        .iter()
        .map(domain_summary)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(LibvirtInfo {
        uri: active_uri,
        libvirt_version,
        hypervisor_version,
        hypervisor_type,
        alive,
        capabilities: HostCapabilities {
            cpu_model: node.model,
            logical_cpus: node.cpus,
            memory_bytes,
        },
        domains: sorted_domains(domains),
    })
}

fn domain_summary(domain: &Domain) -> Result<DomainSummary, LibvirtError> {
    let name = query("get domain name", domain.get_name())?;
    let uuid = query("get domain UUID", domain.get_uuid_string())?;
    let (raw_state, _) = query("get domain state", domain.get_state())?;
    let persistent = query("get domain persistence", domain.is_persistent())?;
    Ok(DomainSummary {
        name,
        uuid,
        state: map_domain_state(raw_state)?,
        persistent,
    })
}

fn query<T>(operation: &str, result: Result<T, VirtError>) -> Result<T, LibvirtError> {
    result.map_err(|error| LibvirtError::Query {
        operation: operation.to_owned(),
        message: error.to_string(),
    })
}

/// Maps libvirt state constants to stable Forge domain values.
///
/// # Errors
///
/// Returns `UnsupportedDomainState` when a newer or invalid raw value is not
/// represented by the binding known to this adapter.
pub fn map_domain_state(state: sys::virDomainState) -> Result<VmState, LibvirtError> {
    match state {
        sys::VIR_DOMAIN_NOSTATE => Ok(VmState::Unknown),
        sys::VIR_DOMAIN_RUNNING | sys::VIR_DOMAIN_BLOCKED => Ok(VmState::Running),
        sys::VIR_DOMAIN_PAUSED | sys::VIR_DOMAIN_PMSUSPENDED => Ok(VmState::Paused),
        sys::VIR_DOMAIN_SHUTDOWN | sys::VIR_DOMAIN_SHUTOFF => Ok(VmState::Shutoff),
        sys::VIR_DOMAIN_CRASHED => Ok(VmState::Crashed),
        other => Err(LibvirtError::UnsupportedDomainState(other)),
    }
}

#[must_use]
pub fn sorted_domains(mut domains: Vec<DomainSummary>) -> Vec<DomainSummary> {
    domains.sort_by(|left, right| {
        left.name
            .to_lowercase()
            .cmp(&right.name.to_lowercase())
            .then_with(|| left.uuid.cmp(&right.uuid))
    });
    domains
}

#[must_use]
pub fn format_version(version: u32) -> String {
    let major = version / 1_000_000;
    let minor = version / 1_000 % 1_000;
    let release = version % 1_000;
    format!("{major}.{minor}.{release}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain(name: &str, uuid: &str) -> DomainSummary {
        DomainSummary {
            name: name.to_owned(),
            uuid: uuid.to_owned(),
            state: VmState::Shutoff,
            persistent: true,
        }
    }

    #[test]
    fn maps_known_libvirt_states() {
        assert_eq!(
            map_domain_state(sys::VIR_DOMAIN_RUNNING),
            Ok(VmState::Running)
        );
        assert_eq!(
            map_domain_state(sys::VIR_DOMAIN_PAUSED),
            Ok(VmState::Paused)
        );
        assert_eq!(
            map_domain_state(sys::VIR_DOMAIN_SHUTOFF),
            Ok(VmState::Shutoff)
        );
        assert_eq!(
            map_domain_state(sys::VIR_DOMAIN_CRASHED),
            Ok(VmState::Crashed)
        );
        assert_eq!(
            map_domain_state(sys::VIR_DOMAIN_NOSTATE),
            Ok(VmState::Unknown)
        );
    }

    #[test]
    fn rejects_unknown_libvirt_state() {
        assert_eq!(
            map_domain_state(999),
            Err(LibvirtError::UnsupportedDomainState(999))
        );
    }

    #[test]
    fn sorts_domain_summaries_by_name_then_uuid() {
        let domains = vec![
            domain("zeta", "2"),
            domain("Alpha", "2"),
            domain("alpha", "1"),
        ];
        let sorted = sorted_domains(domains);
        let uuids = sorted
            .iter()
            .map(|domain| domain.uuid.as_str())
            .collect::<Vec<_>>();
        assert_eq!(uuids, ["1", "2", "2"]);
    }

    #[test]
    fn formats_domain_summary_readably() {
        assert_eq!(
            domain("fedora", "example-uuid").to_string(),
            "fedora\tshutoff\texample-uuid\tpersistent"
        );
    }

    #[test]
    fn formats_encoded_libvirt_version() {
        assert_eq!(format_version(12_003_004), "12.3.4");
    }
}
