use forge_core::{DoctorReport, HostState, VmResourcePlan};
use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    match arguments
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["doctor"] => match forge_doctor::run() {
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
        },
        ["profile", "list"] => {
            for profile in forge_profiles::built_in_profiles() {
                println!("{}", profile.name);
            }
            ExitCode::SUCCESS
        }
        ["profile", "plan", profile_name] => plan_profile(profile_name),
        _ => {
            print_usage();
            ExitCode::from(2)
        }
    }
}

fn plan_profile(profile_name: &str) -> ExitCode {
    let Some(profile) = forge_profiles::find(profile_name) else {
        eprintln!("unknown VM profile: {profile_name}");
        return ExitCode::from(2);
    };
    let hardware = match forge_hardware::collect() {
        Ok(hardware) => hardware,
        Err(error) => {
            eprintln!("hardware detection failed: {error}");
            return ExitCode::from(2);
        }
    };
    match forge_profiles::plan(&hardware, &profile) {
        Ok(plan) => {
            print_plan(profile_name, plan);
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("cannot plan profile {profile_name}: {error}");
            ExitCode::from(1)
        }
    }
}

fn print_plan(profile_name: &str, plan: VmResourcePlan) {
    const GIB: u64 = 1024 * 1024 * 1024;
    println!("Profile: {profile_name}");
    println!("vCPU: {}", plan.vcpus);
    println!("RAM start: {} GiB", plan.memory_start_bytes / GIB);
    println!("RAM max: {} GiB", plan.memory_max_bytes / GIB);
    println!("Disk: {} GiB", plan.disk_bytes / GIB);
    println!("Network: {}", plan.network);
    println!("GPU: {}", plan.gpu);
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  forge doctor");
    eprintln!("  forge profile list");
    eprintln!("  forge profile plan <profile>");
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
