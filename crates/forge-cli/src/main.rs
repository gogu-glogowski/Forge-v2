use forge_core::{DoctorReport, HostState};
use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    if let Some("doctor") = env::args().nth(1).as_deref() {
        match forge_doctor::run() {
            Ok(report) => {
                print_report(&report);
                if matches!(report.state, HostState::Ready | HostState::Degraded) {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::from(1)
                }
            }
            Err(error) => {
                eprintln!("forge doctor failed: {error}");
                ExitCode::from(2)
            }
        }
    } else {
        eprintln!("Usage: forge doctor");
        ExitCode::from(2)
    }
}

fn print_report(report: &DoctorReport) {
    let distro = &report.host.distribution;
    println!("Host status: {}", report.state);
    println!(
        "Fedora: {} ({})",
        distro.name.as_deref().unwrap_or("unknown"),
        distro.version.as_deref().unwrap_or("unknown version")
    );
    println!(
        "CPU: {} ({} logical cores, virtualization: {})",
        report.hardware.cpu.model,
        report.hardware.cpu.logical_cores,
        yes_no(report.hardware.cpu.virtualization)
    );
    println!("RAM: {} MiB", report.hardware.memory_bytes / 1024 / 1024);
    println!("GPUs: {}", report.hardware.gpus.len());
    println!("Storage devices: {}", report.hardware.storage.len());
    println!("KVM: {}", report.host.components.kvm);
    println!("libvirt: {}", report.host.components.libvirt);
    println!("SELinux: {}", report.host.components.selinux);
    println!("firewalld: {}", report.host.components.firewalld);
    println!("virt-manager: {}", report.host.components.virt_manager);
    for note in &report.notes {
        println!("- {note}");
    }
}

const fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}
