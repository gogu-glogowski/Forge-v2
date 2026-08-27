//! Read-only Fedora host checks.

use forge_core::{ComponentState, DistributionInfo, HostComponents, HostInfo};
use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

#[must_use]
pub fn inspect() -> HostInfo {
    let os_release = fs::read_to_string("/etc/os-release").unwrap_or_default();
    HostInfo {
        distribution: parse_os_release(&os_release),
        components: HostComponents {
            kvm: device_state(Path::new("/dev/kvm")),
            libvirt: service_state(&["libvirtd.service", "virtqemud.service"]),
            selinux: selinux_state(Path::new("/sys/fs/selinux/enforce")),
            firewalld: service_state(&["firewalld.service"]),
            virt_manager: binary_state("virt-manager"),
        },
    }
}

#[must_use]
pub fn parse_os_release(input: &str) -> DistributionInfo {
    let value = |key: &str| {
        input.lines().find_map(|line| {
            let (candidate, raw) = line.split_once('=')?;
            (candidate == key).then(|| raw.trim_matches('"').to_owned())
        })
    };
    let id = value("ID");
    DistributionInfo {
        is_fedora: id.as_deref() == Some("fedora"),
        id,
        name: value("NAME"),
        version: value("VERSION_ID"),
    }
}

fn device_state(path: &Path) -> ComponentState {
    if path.exists() {
        ComponentState::Ready
    } else {
        ComponentState::Missing
    }
}

fn selinux_state(enforce_path: &Path) -> ComponentState {
    match fs::read_to_string(enforce_path).as_deref().map(str::trim) {
        Ok("1") => ComponentState::Ready,
        Ok("0") => ComponentState::Inactive,
        Ok(_) | Err(_) if enforce_path.exists() => ComponentState::Unknown,
        Err(_) | Ok(_) => ComponentState::Missing,
    }
}

fn binary_state(name: &str) -> ComponentState {
    let found = env::var_os("PATH").is_some_and(|paths| {
        env::split_paths(&paths).any(|directory| directory.join(name).is_file())
    });
    if found {
        ComponentState::Ready
    } else {
        ComponentState::Missing
    }
}

fn service_state(units: &[&str]) -> ComponentState {
    let mut installed = false;
    for unit in units {
        let Ok(output) = Command::new("systemctl")
            .args(["show", unit, "--property=LoadState,ActiveState", "--value"])
            .output()
        else {
            return ComponentState::Unknown;
        };
        let text = String::from_utf8_lossy(&output.stdout);
        installed |= !text.contains("not-found");
        if text.lines().any(|line| line == "active") {
            return ComponentState::Ready;
        }
    }
    if installed {
        ComponentState::Inactive
    } else {
        ComponentState::Missing
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_fedora() {
        let distribution = parse_os_release("NAME=\"Fedora Linux\"\nID=fedora\nVERSION_ID=42\n");
        assert!(distribution.is_fedora);
        assert_eq!(distribution.version.as_deref(), Some("42"));
    }

    #[test]
    fn rejects_other_distributions() {
        let distribution = parse_os_release("NAME=Debian\nID=debian\n");
        assert!(!distribution.is_fedora);
    }
}
