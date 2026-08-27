//! Read-only Linux hardware discovery.

use forge_core::{CpuInfo, GpuInfo, HardwareInfo, KvmInfo, StorageDevice};
use std::fs;
use std::io;
use std::path::Path;

/// Collects a snapshot of hardware visible through Linux pseudo-filesystems.
///
/// # Errors
///
/// Returns an I/O error when the required CPU or memory information cannot be
/// read from `/proc`.
pub fn collect() -> io::Result<HardwareInfo> {
    let cpu_text = fs::read_to_string("/proc/cpuinfo")?;
    let memory_text = fs::read_to_string("/proc/meminfo")?;

    Ok(HardwareInfo {
        cpu: parse_cpuinfo(&cpu_text),
        memory_bytes: parse_memory_bytes(&memory_text).unwrap_or_default(),
        gpus: collect_gpus(Path::new("/sys/class/drm")),
        storage: collect_storage(Path::new("/sys/block")),
        kvm: inspect_kvm(Path::new("/dev/kvm")),
    })
}

#[must_use]
pub fn parse_cpuinfo(input: &str) -> CpuInfo {
    let logical_cores = input
        .lines()
        .filter(|line| field(line, "processor").is_some())
        .count();
    let model = input
        .lines()
        .find_map(|line| field(line, "model name"))
        .unwrap_or("Unknown CPU")
        .to_owned();
    let virtualization = input.lines().any(|line| {
        field(line, "flags")
            .or_else(|| field(line, "Features"))
            .is_some_and(|flags| {
                flags
                    .split_whitespace()
                    .any(|flag| matches!(flag, "vmx" | "svm"))
            })
    });

    CpuInfo {
        model,
        logical_cores,
        virtualization,
    }
}

#[must_use]
pub fn parse_memory_bytes(input: &str) -> Option<u64> {
    let kib = input
        .lines()
        .find_map(|line| field(line, "MemTotal"))?
        .split_whitespace()
        .next()?
        .parse::<u64>()
        .ok()?;
    kib.checked_mul(1024)
}

fn field<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let (key, value) = line.split_once(':')?;
    (key.trim() == name).then(|| value.trim())
}

fn collect_gpus(root: &Path) -> Vec<GpuInfo> {
    sorted_entry_names(root)
        .into_iter()
        .filter(|name| name.starts_with("card") && !name.contains('-'))
        .map(|name| GpuInfo { name })
        .collect()
}

fn collect_storage(root: &Path) -> Vec<StorageDevice> {
    sorted_entry_names(root)
        .into_iter()
        .map(|name| {
            let sectors = fs::read_to_string(root.join(&name).join("size"))
                .ok()
                .and_then(|value| value.trim().parse::<u64>().ok());
            StorageDevice {
                name,
                size_bytes: sectors.and_then(|value| value.checked_mul(512)),
            }
        })
        .collect()
}

fn sorted_entry_names(root: &Path) -> Vec<String> {
    let mut names = fs::read_dir(root)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect::<Vec<_>>();
    names.sort();
    names
}

fn inspect_kvm(path: &Path) -> KvmInfo {
    KvmInfo {
        present: path.exists(),
        accessible: fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .is_ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_x86_cpu_and_virtualization() {
        let input = "processor: 0\nmodel name: Example CPU\nflags: fpu vmx sse\n\
                     processor: 1\nmodel name: Example CPU\n";
        let cpu = parse_cpuinfo(input);
        assert_eq!(cpu.model, "Example CPU");
        assert_eq!(cpu.logical_cores, 2);
        assert!(cpu.virtualization);
    }

    #[test]
    fn parses_memory_in_kib() {
        assert_eq!(parse_memory_bytes("MemTotal: 16384 kB\n"), Some(16_777_216));
    }

    #[test]
    fn malformed_memory_is_unknown() {
        assert_eq!(parse_memory_bytes("MemTotal: many kB\n"), None);
    }
}
