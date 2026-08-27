use forge_core::{DoctorReport, DomainSummary, HostState, LibvirtInfo, VmResourcePlan};
use std::env;
use std::io;
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
        ["hypervisor", "info"] => hypervisor_info(),
        ["vm", "list"] => vm_list(),
        ["vm", "define", "fedora-lab"] => define_vm(false),
        ["vm", "define", "fedora-lab", "--dry-run"] => define_vm(true),
        ["domain", "render", profile_name] => render_domain(profile_name),
        _ => {
            print_usage();
            ExitCode::from(2)
        }
    }
}

fn define_vm(dry_run: bool) -> ExitCode {
    let Some(profile) = forge_profiles::find("fedora-lab") else {
        eprintln!("fedora-lab profile is unavailable");
        return ExitCode::from(2);
    };
    let hardware = match forge_hardware::collect() {
        Ok(hardware) => hardware,
        Err(error) => {
            eprintln!("hardware detection failed: {error}");
            return ExitCode::from(2);
        }
    };
    let resource_plan = match forge_profiles::plan(&hardware, &profile) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("cannot plan fedora-lab: {error}");
            return ExitCode::from(1);
        }
    };
    let mut backend = match forge_libvirt::LibvirtDefineBackend::connect_local() {
        Ok(backend) => backend,
        Err(error) => {
            eprintln!("libvirt connection failed: {error}");
            return ExitCode::from(1);
        }
    };
    let plan = match forge_storage::prepare(&mut backend, &profile, &resource_plan) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("cannot prepare Fedora-Lab definition: {error}");
            return ExitCode::from(1);
        }
    };
    print_define_plan(&plan);
    if dry_run {
        println!("\n{}", plan.xml);
        return ExitCode::SUCCESS;
    }
    eprint!("Define Fedora-Lab domain? [y/N] ");
    let mut answer = String::new();
    if io::stdin().read_line(&mut answer).is_err()
        || !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
    {
        eprintln!("Definition cancelled.");
        return ExitCode::SUCCESS;
    }
    match forge_storage::execute(&mut backend, &plan) {
        Ok(result) => {
            println!("Domain UUID: {}", result.domain.uuid);
            println!("Domain state: {}", result.domain.state);
            println!("Volume path: {}", result.volume.path);
            println!(
                "Capacity: {} GiB",
                result.volume.capacity_bytes / 1024 / 1024 / 1024
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Fedora-Lab definition failed: {error}");
            ExitCode::from(1)
        }
    }
}

fn print_define_plan(plan: &forge_storage::DefinePlan) {
    println!("Domain: {}", plan.domain_name);
    println!("vCPU: {}", plan.spec.vcpus);
    println!(
        "RAM: {} MiB start / {} MiB max",
        plan.spec.memory_start_bytes / 1024 / 1024,
        plan.spec.memory_max_bytes / 1024 / 1024
    );
    println!("Disk: {} GiB", plan.capacity_bytes / 1024 / 1024 / 1024);
    println!("Storage pool: {}", plan.pool.name);
    println!("Network: {}", plan.spec.network_interfaces[0].mode);
    println!("GPU: virtual");
}

fn render_domain(profile_name: &str) -> ExitCode {
    if profile_name != "fedora-lab" {
        eprintln!("domain rendering is currently supported only for fedora-lab");
        return ExitCode::from(2);
    }
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
    let plan = match forge_profiles::plan(&hardware, &profile) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("cannot plan profile {profile_name}: {error}");
            return ExitCode::from(1);
        }
    };
    let metadata = forge_domain::DomainMetadata {
        name: profile_name.to_owned(),
        disk_path: format!("/var/lib/libvirt/images/{profile_name}.qcow2"),
    };
    let spec = match forge_domain::fedora_lab_spec(&profile, &plan, metadata) {
        Ok(spec) => spec,
        Err(error) => {
            eprintln!("invalid domain specification: {error}");
            return ExitCode::from(1);
        }
    };
    match forge_domain::render_xml(&spec) {
        Ok(xml) => {
            print!("{xml}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("domain XML validation failed: {error}");
            ExitCode::from(1)
        }
    }
}

fn hypervisor_info() -> ExitCode {
    match forge_libvirt::discover_local() {
        Ok(info) => {
            print_hypervisor_info(&info);
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("hypervisor discovery failed: {error}");
            ExitCode::from(1)
        }
    }
}

fn vm_list() -> ExitCode {
    match forge_libvirt::discover_local() {
        Ok(info) => {
            print!("{}", format_domain_list(&info.domains));
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("VM discovery failed: {error}");
            ExitCode::from(1)
        }
    }
}

fn print_hypervisor_info(info: &LibvirtInfo) {
    println!(
        "Connection: {}",
        if info.alive { "alive" } else { "not alive" }
    );
    println!("URI: {}", info.uri);
    println!(
        "Hypervisor: {} {}",
        info.hypervisor_type, info.hypervisor_version
    );
    println!("libvirt: {}", info.libvirt_version);
    println!("Domains: {}", info.domains.len());
    println!(
        "Host: {} ({} CPUs, {} MiB RAM)",
        info.capabilities.cpu_model,
        info.capabilities.logical_cpus,
        info.capabilities.memory_bytes / 1024 / 1024
    );
}

fn format_domain_list(domains: &[DomainSummary]) -> String {
    if domains.is_empty() {
        return "No virtual machines defined.\n".to_owned();
    }
    let mut output = "NAME\tSTATE\tUUID\tTYPE\n".to_owned();
    for domain in domains {
        output.push_str(&domain.to_string());
        output.push('\n');
    }
    output
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
    eprintln!("  forge hypervisor info");
    eprintln!("  forge vm list");
    eprintln!("  forge vm define fedora-lab [--dry-run]");
    eprintln!("  forge domain render fedora-lab");
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

#[cfg(test)]
mod tests {
    use super::*;
    use forge_core::VmState;

    #[test]
    fn empty_domain_list_is_not_an_error() {
        assert_eq!(format_domain_list(&[]), "No virtual machines defined.\n");
    }

    #[test]
    fn domain_list_has_readable_columns() {
        let domains = [DomainSummary {
            name: "fedora-lab".to_owned(),
            uuid: "example-uuid".to_owned(),
            state: VmState::Shutoff,
            persistent: true,
        }];
        assert_eq!(
            format_domain_list(&domains),
            "NAME\tSTATE\tUUID\tTYPE\nfedora-lab\tshutoff\texample-uuid\tpersistent\n"
        );
    }
}
