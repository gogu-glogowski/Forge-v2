//! Aggregation and classification for `forge doctor`.

use forge_core::{ComponentState, DoctorReport, HardwareInfo, HostInfo, HostState};
use std::io;

/// Collects and evaluates the current host snapshot.
///
/// # Errors
///
/// Returns an I/O error when required hardware information cannot be read.
pub fn run() -> io::Result<DoctorReport> {
    let hardware = forge_hardware::collect()?;
    let host = forge_host::inspect();
    Ok(evaluate(hardware, host))
}

#[must_use]
pub fn evaluate(hardware: HardwareInfo, host: HostInfo) -> DoctorReport {
    let components = &host.components;
    let state = if !host.distribution.is_fedora {
        HostState::Unsupported
    } else if !hardware.cpu.virtualization
        || !hardware.kvm.present
        || components.kvm == ComponentState::Missing
        || components.libvirt == ComponentState::Missing
    {
        HostState::Incomplete
    } else if !hardware.kvm.accessible
        || components.kvm != ComponentState::Ready
        || components.libvirt != ComponentState::Ready
        || components.selinux != ComponentState::Ready
        || components.firewalld != ComponentState::Ready
        || components.virt_manager != ComponentState::Ready
    {
        HostState::Degraded
    } else {
        HostState::Ready
    };

    let notes = notes_for(state, &hardware, &host);
    DoctorReport {
        state,
        hardware,
        host,
        notes,
    }
}

fn notes_for(state: HostState, hardware: &HardwareInfo, host: &HostInfo) -> Vec<String> {
    let mut notes = Vec::new();
    if state == HostState::Unsupported {
        notes.push("Only Fedora hosts are supported".to_owned());
    }
    if !hardware.cpu.virtualization {
        notes.push("CPU virtualization support was not detected".to_owned());
    }
    if !hardware.kvm.present {
        notes.push("/dev/kvm is missing".to_owned());
    } else if !hardware.kvm.accessible {
        notes.push("/dev/kvm is not accessible to the current user".to_owned());
    }
    for (name, component) in [
        ("libvirt", host.components.libvirt),
        ("SELinux", host.components.selinux),
        ("firewalld", host.components.firewalld),
        ("virt-manager", host.components.virt_manager),
    ] {
        if component != ComponentState::Ready {
            notes.push(format!("{name}: {component}"));
        }
    }
    notes
}

#[cfg(test)]
mod tests {
    use super::*;
    use forge_core::{CpuInfo, DistributionInfo, GpuInfo, HostComponents, KvmInfo};

    fn fixtures() -> (HardwareInfo, HostInfo) {
        (
            HardwareInfo {
                cpu: CpuInfo {
                    model: "Test CPU".to_owned(),
                    logical_cores: 8,
                    virtualization: true,
                },
                memory_bytes: 16 * 1024 * 1024 * 1024,
                gpus: Vec::<GpuInfo>::new(),
                storage: vec![],
                kvm: KvmInfo {
                    present: true,
                    accessible: true,
                },
            },
            HostInfo {
                distribution: DistributionInfo {
                    id: Some("fedora".to_owned()),
                    name: Some("Fedora Linux".to_owned()),
                    version: Some("42".to_owned()),
                    is_fedora: true,
                },
                components: HostComponents {
                    kvm: ComponentState::Ready,
                    libvirt: ComponentState::Ready,
                    selinux: ComponentState::Ready,
                    firewalld: ComponentState::Ready,
                    virt_manager: ComponentState::Ready,
                },
            },
        )
    }

    #[test]
    fn complete_fedora_is_ready() {
        let (hardware, host) = fixtures();
        assert_eq!(evaluate(hardware, host).state, HostState::Ready);
    }

    #[test]
    fn non_fedora_is_unsupported() {
        let (hardware, mut host) = fixtures();
        host.distribution.is_fedora = false;
        assert_eq!(evaluate(hardware, host).state, HostState::Unsupported);
    }

    #[test]
    fn missing_kvm_is_incomplete() {
        let (mut hardware, host) = fixtures();
        hardware.kvm.present = false;
        assert_eq!(evaluate(hardware, host).state, HostState::Incomplete);
    }

    #[test]
    fn inactive_optional_component_is_degraded() {
        let (hardware, mut host) = fixtures();
        host.components.firewalld = ComponentState::Inactive;
        assert_eq!(evaluate(hardware, host).state, HostState::Degraded);
    }
}
