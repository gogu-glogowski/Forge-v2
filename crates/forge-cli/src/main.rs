use forge_core::{DoctorReport, DomainSummary, HostState, LibvirtInfo, VmResourcePlan};
use forge_provisioning::{BootBackend, RebuildBackend};
use std::env;
use std::io;
use std::process::ExitCode;
use std::time::Duration;

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
        ["vm", "status", "fedora-lab"] => lifecycle_status(),
        ["vm", "cleanup", "fedora-lab", "--dry-run"] => cleanup_vm_dry_run(),
        ["vm", "start", "fedora-lab", "--dry-run"] => lifecycle_action(true, true),
        ["vm", "start", "fedora-lab"] => lifecycle_action(true, false),
        ["vm", "shutdown", "fedora-lab", "--dry-run"] => lifecycle_action(false, true),
        ["vm", "shutdown", "fedora-lab"] => lifecycle_action(false, false),
        ["state", "show", "fedora-lab"] => state_show(),
        ["state", "reconcile", "fedora-lab"] => state_reconcile(),
        ["state", "adopt", "fedora-lab", "--dry-run"] => state_adopt(true),
        ["state", "adopt", "fedora-lab"] => state_adopt(false),
        ["vm", "define", "fedora-lab"] => define_vm(false),
        ["vm", "define", "fedora-lab", "--dry-run"] => define_vm(true),
        ["vm", "prepare", "fedora-lab"] => prepare_vm(false),
        ["vm", "prepare", "fedora-lab", "--dry-run"] => prepare_vm(true),
        ["vm", "boot", "fedora-lab"] => boot_vm(false),
        ["vm", "boot", "fedora-lab", "--dry-run"] => boot_vm(true),
        ["vm", "rebuild", "fedora-lab", "--dry-run"] => rebuild_vm_dry_run(),
        ["vm", "rebuild", "fedora-lab"] => rebuild_vm(),
        ["domain", "render", profile_name] => render_domain(profile_name),
        ["image", "list"] => image_list(),
        ["image", "inspect", "fedora"] => image_inspect(),
        ["image", "fetch", "fedora"] => image_fetch(),
        _ => {
            print_usage();
            ExitCode::from(2)
        }
    }
}

fn state_manifest_path() -> Result<std::path::PathBuf, String> {
    let home = env::var_os("HOME").ok_or_else(|| "HOME is unavailable".to_owned())?;
    Ok(forge_state::manifest_path(
        &forge_state::state_directory(std::path::Path::new(&home)),
        "fedora-lab",
    ))
}

fn state_show() -> ExitCode {
    let path = match state_manifest_path() {
        Ok(path) => path,
        Err(error) => {
            eprintln!("Forge state path failed: {error}");
            return ExitCode::from(1);
        }
    };
    match forge_state::read_manifest(&path) {
        Ok(Some(manifest)) => match forge_state::serialize(&manifest) {
            Ok(json) => {
                print!("{}", String::from_utf8_lossy(&json));
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("Forge state serialization failed: {error}");
                ExitCode::from(1)
            }
        },
        Ok(None) => {
            println!("State: Missing");
            println!("Manifest path: {}", path.display());
            ExitCode::SUCCESS
        }
        Err(error) => {
            println!("State: CorruptState");
            eprintln!("Forge state cannot be read: {error}");
            ExitCode::from(1)
        }
    }
}

fn discover_state() -> Result<forge_state::ObservedGeneration, String> {
    let backend = forge_libvirt::LibvirtBootBackend::connect_local()
        .map_err(|error| format!("libvirt connection failed: {error}"))?;
    backend
        .inspect_state()
        .map_err(|error| format!("Forge state discovery failed: {error}"))
}

fn state_reconcile() -> ExitCode {
    let path = match state_manifest_path() {
        Ok(path) => path,
        Err(error) => {
            eprintln!("Forge state path failed: {error}");
            return ExitCode::from(1);
        }
    };
    let manifest = match forge_state::read_manifest(&path) {
        Ok(Some(manifest)) => manifest,
        Ok(None) => {
            println!("ReconciliationStatus: Missing");
            println!("Manifest path: {}", path.display());
            return ExitCode::SUCCESS;
        }
        Err(error) => {
            println!("ReconciliationStatus: CorruptState");
            eprintln!("{error}");
            return ExitCode::from(1);
        }
    };
    let observed = match discover_state() {
        Ok(observed) => observed,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(1);
        }
    };
    let report = forge_state::reconcile(&manifest, &observed);
    println!("ReconciliationStatus: {:?}", report.status);
    for issue in report.issues {
        println!(
            "- {:?} {}: expected {}, actual {}",
            issue.status, issue.field, issue.expected, issue.actual
        );
    }
    if report.status == forge_state::ReconciliationStatus::Consistent {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn state_adopt(dry_run: bool) -> ExitCode {
    let path = match state_manifest_path() {
        Ok(path) => path,
        Err(error) => {
            eprintln!("Forge state path failed: {error}");
            return ExitCode::from(1);
        }
    };
    match forge_state::read_manifest(&path) {
        Ok(Some(_)) => {
            eprintln!("Forge state adoption refused: manifest already exists");
            return ExitCode::from(1);
        }
        Ok(None) => {}
        Err(error) => {
            eprintln!("Forge state adoption refused: {error}");
            return ExitCode::from(1);
        }
    }
    let observed = match discover_state() {
        Ok(observed) => observed,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(1);
        }
    };
    let plan =
        match forge_state::plan_adoption(&observed, path.clone(), std::time::SystemTime::now()) {
            Ok(plan) => plan,
            Err(error) => {
                eprintln!("Forge state adoption denied: {error}");
                return ExitCode::from(1);
            }
        };
    print_adoption_plan(&plan, &observed, dry_run);
    if dry_run {
        return ExitCode::SUCCESS;
    }
    eprint!("Adopt current Fedora-Lab generation into Forge state? [y/N] ");
    let mut answer = String::new();
    if io::stdin().read_line(&mut answer).is_err()
        || !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
    {
        eprintln!("State adoption cancelled.");
        return ExitCode::SUCCESS;
    }
    let fresh = match discover_state() {
        Ok(fresh) => fresh,
        Err(error) => {
            eprintln!("pre-write discovery failed: {error}");
            return ExitCode::from(1);
        }
    };
    if forge_state::reconcile(&plan.manifest, &fresh).status
        != forge_state::ReconciliationStatus::Consistent
        || !matches!(forge_state::read_manifest(&path), Ok(None))
    {
        eprintln!("state changed before adoption; manifest write denied");
        return ExitCode::from(1);
    }
    match forge_state::write_manifest_atomic(&path, &plan.manifest) {
        Ok(()) => {
            println!(
                "Forge state manifest written atomically: {}",
                path.display()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Forge state adoption failed: {error}");
            ExitCode::from(1)
        }
    }
}

fn print_adoption_plan(
    plan: &forge_state::AdoptionPlan,
    observed: &forge_state::ObservedGeneration,
    dry_run: bool,
) {
    println!(
        "Adoption mode: {}",
        if dry_run {
            "dry-run (zero mutation)"
        } else {
            "real"
        }
    );
    println!("Domain: {}", observed.domain_name);
    println!("Domain UUID: {}", observed.domain_uuid);
    println!("Libvirt URI: {}", observed.libvirt_uri);
    println!(
        "Storage pool: {} ({})",
        observed.storage_pool_name, observed.storage_pool_uuid
    );
    println!("Planned generation ID: {}", plan.manifest.generation_id);
    println!(
        "State exists: false{}",
        if dry_run {
            " (dry-run does not write the manifest)"
        } else {
            " (manifest is written only after confirmation and revalidation)"
        }
    );
    println!("Manifest path: {}", plan.manifest_path.display());
    println!("Adoptable active resources:");
    for resource in &plan.adoptable_resources {
        println!(
            "- {:?}: {} | key={} | format={} | capacity={} | backing={}",
            resource.role,
            resource.path,
            resource.volume_key,
            resource.format,
            resource.capacity_bytes,
            resource.backing_path.as_deref().unwrap_or("none")
        );
    }
    println!("Unmanaged legacy resources:");
    for resource in &plan.unmanaged_resources {
        println!("- {resource}");
    }
    println!("Mutation: {}", plan.mutation);
}

fn discover_lifecycle_status() -> Result<forge_provisioning::FedoraLabLifecycleStatus, String> {
    let backend = forge_libvirt::LibvirtBootBackend::connect_local()
        .map_err(|error| format!("libvirt connection failed: {error}"))?;
    backend
        .inspect_lifecycle()
        .map_err(|error| format!("Fedora-Lab lifecycle discovery failed: {error}"))
}

fn lifecycle_status() -> ExitCode {
    match discover_lifecycle_status() {
        Ok(status) => {
            print_lifecycle_status(&status);
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(1)
        }
    }
}

fn cleanup_vm_dry_run() -> ExitCode {
    let status = match discover_lifecycle_status() {
        Ok(status) => status,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(1);
        }
    };
    let plan = match forge_provisioning::plan_generation_cleanup(&status) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("Fedora-Lab cleanup cannot be planned safely: {error}");
            return ExitCode::from(1);
        }
    };
    println!("Cleanup mode: dry-run (zero mutation)");
    print_lifecycle_status(&status);
    println!("Cleanup safe: {}", plan.safe);
    println!(
        "Controlled shutdown required for real cleanup: {}",
        plan.requires_shutdown
    );
    println!("Preserve:");
    for resource in &plan.preserve {
        println!("- {resource}");
    }
    println!("Cleanup candidates:");
    if plan.candidates.is_empty() {
        println!("- none");
    }
    for candidate in &plan.candidates {
        println!(
            "- {:?}: {} ({}, {} bytes) — {}",
            candidate.kind,
            candidate.name,
            candidate.path,
            candidate.capacity_bytes,
            candidate.reason
        );
    }
    println!("Retained because ownership is unproven:");
    if plan.retained_unproven.is_empty() {
        println!("- none");
    }
    for resource in &plan.retained_unproven {
        println!("- {resource}");
    }
    println!("Preconditions for a future real cleanup:");
    for condition in &plan.preconditions {
        println!("- {condition}");
    }
    println!("Future cleanup steps:");
    for step in &plan.future_steps {
        println!("- {step}");
    }
    ExitCode::SUCCESS
}

fn lifecycle_action(start: bool, dry_run: bool) -> ExitCode {
    let status = match discover_lifecycle_status() {
        Ok(status) => status,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(1);
        }
    };
    let action = if start {
        forge_provisioning::LifecycleAction::Start
    } else {
        forge_provisioning::LifecycleAction::Shutdown
    };
    let plan = match forge_provisioning::plan_lifecycle_action(&status, action) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("Fedora-Lab lifecycle action denied: {error}");
            return ExitCode::from(1);
        }
    };
    println!(
        "Mode: {}",
        if dry_run {
            "dry-run (zero mutation)"
        } else {
            "real"
        }
    );
    println!("Action: {:?}", plan.action);
    println!("Current state: {}", plan.current_state);
    println!("Timeout: {} seconds", plan.timeout_seconds);
    println!(
        "Idempotent result: {}",
        plan.idempotent_result
            .map_or_else(|| "none".to_owned(), |result| format!("{result:?}"))
    );
    println!("Preflight checks:");
    for check in &plan.checks {
        println!("- {check}");
    }
    println!("Execution steps:");
    for step in &plan.steps {
        println!("- {step}");
    }
    if dry_run || plan.idempotent_result.is_some() {
        return ExitCode::SUCCESS;
    }
    eprint!(
        "{} Fedora-Lab now? [y/N] ",
        if start { "Start" } else { "Shutdown" }
    );
    let mut answer = String::new();
    if io::stdin().read_line(&mut answer).is_err()
        || !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
    {
        eprintln!("Lifecycle action cancelled.");
        return ExitCode::SUCCESS;
    }
    let mut backend = match forge_libvirt::LibvirtBootBackend::connect_local() {
        Ok(backend) => backend,
        Err(error) => {
            eprintln!("libvirt connection failed: {error}");
            return ExitCode::from(1);
        }
    };
    let fresh = match backend.inspect_lifecycle() {
        Ok(fresh) => fresh,
        Err(error) => {
            eprintln!("pre-mutation lifecycle revalidation failed: {error}");
            return ExitCode::from(1);
        }
    };
    if fresh.domain_uuid != status.domain_uuid
        || fresh.domain_state != status.domain_state
        || fresh.active_overlay_path != status.active_overlay_path
        || fresh.active_backing_path != status.active_backing_path
        || fresh.active_seed_path != status.active_seed_path
        || forge_provisioning::plan_lifecycle_action(&fresh, action).is_err()
    {
        eprintln!("pre-mutation lifecycle state changed; action denied");
        return ExitCode::from(1);
    }
    let result = if start {
        execute_lifecycle_start(&mut backend)
    } else {
        backend.shutdown_and_wait(Duration::from_secs(plan.timeout_seconds))
    };
    match result {
        Ok(()) => {
            println!("Lifecycle action completed.");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Lifecycle action failed: {error}");
            ExitCode::from(1)
        }
    }
}

fn execute_lifecycle_start(
    backend: &mut forge_libvirt::LibvirtBootBackend,
) -> Result<(), forge_provisioning::ProvisioningError> {
    let timeouts = forge_provisioning::BootTimeouts::default();
    backend.start()?;
    backend.wait_running(Duration::from_secs(timeouts.domain_running_seconds))?;
    let ip = backend.discover_ip(Duration::from_secs(timeouts.dhcp_lease_seconds))?;
    let guest_agent =
        backend.wait_guest_agent(Duration::from_secs(timeouts.guest_agent_seconds))?;
    println!("DomainBootStatus: Running");
    println!("GuestAgentStatus: {guest_agent:?}");
    if let Some(ip) = ip {
        println!("DhcpLeaseStatus: Available({ip})");
        let key = env::var_os("HOME")
            .map(std::path::PathBuf::from)
            .unwrap_or_default()
            .join(".ssh/forge_ed25519");
        let ssh = backend.observe_ssh(
            &ip,
            key.to_string_lossy().as_ref(),
            Duration::from_secs(timeouts.ssh_seconds),
        )?;
        println!("SshStatus: {:?}", ssh.status);
        println!("CloudInitStatus: {:?}", ssh.cloud_init);
    } else {
        println!("DhcpLeaseStatus: TimedOut");
    }
    Ok(())
}

fn print_lifecycle_status(status: &forge_provisioning::FedoraLabLifecycleStatus) {
    println!("Domain: fedora-lab");
    println!("State: {}", status.domain_state);
    println!("UUID: {}", status.domain_uuid);
    println!("Persistent: {}", status.persistent);
    println!("Autostart: {}", status.autostart);
    println!("Default network: {:?}", status.default_network);
    println!("Active vda: {}", status.active_overlay_path);
    println!(
        "Active backing: {}",
        status.active_backing_path.as_deref().unwrap_or("none")
    );
    println!(
        "Active seed: {}",
        status.active_seed_path.as_deref().unwrap_or("none")
    );
    println!("Guest-agent channel: {}", status.guest_agent_channel);
    println!("Guest-agent status: {:?}", status.guest_agent_status);
    println!(
        "IP addresses: {}",
        if status.ip_addresses.is_empty() {
            "none".to_owned()
        } else {
            status.ip_addresses.join(", ")
        }
    );
    for (label, volume) in [
        ("Base", &status.base),
        ("Current overlay", &status.current_overlay),
        ("Current seed", &status.current_seed),
        ("Legacy overlay", &status.legacy_overlay),
        ("Legacy seed", &status.legacy_seed),
    ] {
        println!(
            "{label}: {} (exists: {}, capacity: {} bytes)",
            volume.path,
            volume.exists,
            volume.capacity_bytes.unwrap_or(0)
        );
    }
}

fn rebuild_vm_dry_run() -> ExitCode {
    match build_rebuild_plan() {
        Ok((plan, _)) => {
            print_rebuild_plan(&plan);
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Fedora-Lab rebuild dry-run failed: {error}");
            ExitCode::from(1)
        }
    }
}

fn rebuild_vm() -> ExitCode {
    let (plan, seed) = match build_rebuild_plan() {
        Ok(value) => value,
        Err(error) => {
            eprintln!("Fedora-Lab rebuild planning failed: {error}");
            return ExitCode::from(1);
        }
    };
    print_rebuild_plan(&plan);
    eprint!("Rebuild Fedora-Lab from clean verified base? [y/N] ");
    let mut answer = String::new();
    if io::stdin().read_line(&mut answer).is_err()
        || !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
    {
        eprintln!("Rebuild cancelled.");
        return ExitCode::SUCCESS;
    }
    let mut backend = match forge_libvirt::LibvirtBootBackend::connect_local() {
        Ok(backend) => backend,
        Err(error) => {
            eprintln!("libvirt connection failed: {error}");
            return ExitCode::from(1);
        }
    };
    match forge_provisioning::execute_rebuild(&mut backend, &plan, &seed) {
        Ok(result) => {
            println!("Domain status: {:?}", result.first_boot.domain);
            println!("DHCP lease status: {:?}", result.first_boot.dhcp_lease);
            println!("Guest agent status: {:?}", result.first_boot.guest_agent);
            println!("SSH status: {:?}", result.first_boot.ssh);
            println!("Cloud-init status: {:?}", result.first_boot.cloud_init);
            println!(
                "Forge user confirmed: {}",
                result.first_boot.forge_user_confirmed
            );
            println!(
                "Hostname: {}",
                result
                    .first_boot
                    .hostname
                    .as_deref()
                    .unwrap_or("not confirmed")
            );
            println!("Old overlay and seed retained: true");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Fedora-Lab rebuild failed: {error}");
            ExitCode::from(1)
        }
    }
}

fn build_rebuild_plan() -> Result<
    (
        forge_provisioning::RebuildPlan,
        forge_provisioning::SeedPlan,
    ),
    String,
> {
    let Some(home) = env::var_os("HOME") else {
        return Err("cannot locate Forge resources: HOME is unavailable".to_owned());
    };
    let home = std::path::PathBuf::from(home);
    let key_path = home.join(forge_provisioning::FORGE_PUBLIC_KEY_PATH);
    let public_key = std::fs::read_to_string(&key_path).map_err(|error| {
        format!(
            "cannot read Forge public key {}: {error}",
            key_path.display()
        )
    })?;
    let cloud_data = forge_provisioning::cloud_init(&public_key)
        .map_err(|error| format!("cannot build Fedora-Lab seed plan: {error}"))?;
    let directories = forge_images::default_directories()
        .ok_or_else(|| "cannot determine Forge image directories".to_owned())?;
    let source = forge_images::verified_fedora(&directories)
        .map_err(|error| format!("verified Fedora source is unavailable: {error}"))?;
    let profile = forge_profiles::find("fedora-lab")
        .ok_or_else(|| "fedora-lab profile is unavailable".to_owned())?;
    let hardware =
        forge_hardware::collect().map_err(|error| format!("hardware detection failed: {error}"))?;
    let resources = forge_profiles::plan(&hardware, &profile)
        .map_err(|error| format!("cannot plan fedora-lab: {error}"))?;
    let backend = forge_libvirt::LibvirtBootBackend::connect_local()
        .map_err(|error| format!("libvirt connection failed: {error}"))?;
    let environment = backend
        .inspect_rebuild()
        .map_err(|error| format!("Fedora-Lab rebuild discovery failed: {error}"))?;
    let new_overlay_path = format!(
        "{}/{}",
        environment.pool_path,
        forge_provisioning::REBUILD_OVERLAY_VOLUME
    );
    let mut spec = forge_domain::fedora_lab_spec(
        &profile,
        &resources,
        forge_domain::DomainMetadata {
            name: "fedora-lab".to_owned(),
            disk_path: new_overlay_path,
        },
    )
    .map_err(|error| format!("cannot build replacement DomainSpec: {error}"))?;
    spec.uuid = Some(environment.domain_uuid.clone());
    let xml = forge_domain::render_xml(&spec)
        .map_err(|error| format!("cannot render replacement domain XML: {error}"))?;
    let xml = forge_provisioning::attach_seed(
        &xml,
        &format!(
            "{}/{}",
            environment.pool_path,
            forge_provisioning::REBUILD_SEED_VOLUME
        ),
    )
    .map_err(|error| format!("cannot attach replacement seed to domain XML: {error}"))?;
    let seed_data = cloud_data.clone();
    let plan = forge_provisioning::plan_rebuild(
        &environment,
        &source.local_path.display().to_string(),
        &key_path.display().to_string(),
        resources.disk_bytes,
        cloud_data.content_sha256,
        xml,
    )
    .map_err(|error| format!("Fedora-Lab cannot be rebuilt safely: {error}"))?;
    let seed = forge_provisioning::SeedPlan {
        volume_name: forge_provisioning::REBUILD_SEED_VOLUME.to_owned(),
        volume_path: plan.new_seed_path.clone(),
        create: true,
        data: seed_data,
    };
    Ok((plan, seed))
}

fn print_rebuild_plan(plan: &forge_provisioning::RebuildPlan) {
    println!("Rebuild mode: dry-run (zero mutation)");
    println!("Domain state: {}", plan.environment.domain_state);
    println!("Domain persistent: {}", plan.environment.domain_persistent);
    println!("Current overlay: {}", plan.environment.current_overlay_path);
    println!(
        "Current backing: {}",
        plan.environment
            .current_backing_path
            .as_deref()
            .unwrap_or("missing")
    );
    println!(
        "Base: {} (exists: {})",
        plan.environment.base_path, plan.environment.base_exists
    );
    println!(
        "Seed: {} (exists: {})",
        plan.environment.seed_path, plan.environment.seed_exists
    );
    println!("New overlay: {}", plan.new_overlay_path);
    println!("New seed: {}", plan.new_seed_path);
    println!("New seed SHA-256: {}", plan.new_seed_sha256);
    println!("Preserve:");
    for resource in &plan.preserved_resources {
        println!("- {resource}");
    }
    println!("Replace only after validation:");
    for resource in &plan.replaced_resources {
        println!("- {resource}");
    }
    println!("Rebuild steps:");
    for (index, step) in plan.steps.iter().enumerate() {
        println!("{}. {step}", index + 1);
    }
    println!("Rollback boundaries:");
    for boundary in &plan.rollback_boundaries {
        println!("- {boundary}");
    }
    let timeouts = plan.first_boot_timeouts;
    println!(
        "First-boot typed observations: DomainBootStatus, DhcpLeaseStatus, GuestAgentStatus, SshStatus, CloudInitStatus"
    );
    println!(
        "Timeouts: domain={}s dhcp={}s guest-agent={}s ssh={}s cloud-init={}s",
        timeouts.domain_running_seconds,
        timeouts.dhcp_lease_seconds,
        timeouts.guest_agent_seconds,
        timeouts.ssh_seconds,
        timeouts.cloud_init_seconds
    );
    println!("Planned domain XML:");
    print!("{}", plan.domain_xml);
}

fn boot_vm(dry_run: bool) -> ExitCode {
    let Some(home) = env::var_os("HOME") else {
        eprintln!("cannot locate dedicated Forge public key: HOME is unavailable");
        return ExitCode::from(2);
    };
    let key_path = std::path::PathBuf::from(home).join(forge_provisioning::FORGE_PUBLIC_KEY_PATH);
    let public_key = match std::fs::read_to_string(&key_path) {
        Ok(key) => key,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            eprintln!(
                "{}",
                forge_provisioning::ProvisioningError::MissingPublicKey(
                    key_path.display().to_string()
                )
            );
            return ExitCode::from(1);
        }
        Err(error) => {
            eprintln!(
                "cannot read Forge public key {}: {error}",
                key_path.display()
            );
            return ExitCode::from(1);
        }
    };
    let mut backend = match forge_libvirt::LibvirtBootBackend::connect_local() {
        Ok(backend) => backend,
        Err(error) => {
            eprintln!("libvirt connection failed: {error}");
            return ExitCode::from(1);
        }
    };
    let environment = match backend.inspect() {
        Ok(environment) => environment,
        Err(error) => {
            eprintln!("Fedora-Lab boot discovery failed: {error}");
            return ExitCode::from(1);
        }
    };
    let pool_path = std::path::Path::new(&environment.seed_path)
        .parent()
        .and_then(std::path::Path::to_str)
        .unwrap_or("");
    let private_key_path = key_path.with_extension("");
    let plan = match forge_provisioning::plan(
        &public_key,
        private_key_path.to_string_lossy().as_ref(),
        &environment,
        pool_path,
    ) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("Fedora-Lab cannot boot safely: {error}");
            return ExitCode::from(1);
        }
    };
    print_boot_plan(&plan, &key_path);
    if dry_run {
        return ExitCode::SUCCESS;
    }
    eprint!("Boot Fedora-Lab now? [y/N] ");
    let mut answer = String::new();
    if io::stdin().read_line(&mut answer).is_err()
        || !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
    {
        eprintln!("Boot cancelled.");
        return ExitCode::SUCCESS;
    }
    match forge_provisioning::execute(&mut backend, &plan) {
        Ok(result) => {
            println!("Domain status: {:?}", result.domain);
            println!("DHCP lease status: {:?}", result.dhcp_lease);
            println!("Guest agent status: {:?}", result.guest_agent);
            println!("SSH status: {:?}", result.ssh);
            println!("Cloud-init status: {:?}", result.cloud_init);
            println!("Forge user confirmed: {}", result.forge_user_confirmed);
            println!(
                "Hostname: {}",
                result.hostname.as_deref().unwrap_or("not confirmed")
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Fedora-Lab boot failed: {error}");
            ExitCode::from(1)
        }
    }
}

fn print_boot_plan(plan: &forge_provisioning::BootPlan, key_path: &std::path::Path) {
    println!("Domain: {}", plan.domain_name);
    println!("State: {}", plan.state);
    println!("Overlay: {}", plan.overlay_path);
    println!("Base: {}", plan.base_path);
    println!(
        "SSH public key: {} (public material only)",
        key_path.display()
    );
    println!("Cloud-init hostname: fedora-lab");
    println!("Cloud-init user: forge (locked password, SSH key only, no sudo privileges)");
    println!("Cloud-init packages: qemu-guest-agent");
    println!(
        "Seed method: NoCloud ISO (cidata), volume {}",
        plan.seed.volume_path
    );
    println!(
        "Seed action: {}",
        if plan.seed.create {
            "create"
        } else {
            "reuse matching seed"
        }
    );
    println!("Seed SHA-256: {}", plan.seed.data.content_sha256);
    println!("Device: read-only SATA CD-ROM; vda overlay unchanged");
    println!("IP discovery: {}", plan.ip_discovery.join(" -> "));
    println!("First boot steps:");
    for step in &plan.first_boot_steps {
        println!("- {step}");
    }
}

fn prepare_vm(dry_run: bool) -> ExitCode {
    let Some(profile) = forge_profiles::find("fedora-lab") else {
        eprintln!("fedora-lab profile is unavailable");
        return ExitCode::from(2);
    };
    let directories = match image_directories() {
        Ok(directories) => directories,
        Err(code) => return code,
    };
    let source = match forge_images::verified_fedora(&directories) {
        Ok(source) => source,
        Err(error) => {
            eprintln!("verified Fedora source is unavailable: {error}");
            return ExitCode::from(1);
        }
    };
    let source_size = match std::fs::metadata(&source.local_path) {
        Ok(metadata) => metadata.len(),
        Err(error) => {
            eprintln!("cannot inspect verified Fedora source: {error}");
            return ExitCode::from(1);
        }
    };
    let source_capacity = match forge_images::qcow2_virtual_size(&source.local_path) {
        Ok(capacity) => capacity,
        Err(error) => {
            eprintln!("cannot inspect verified Fedora qcow2 capacity: {error}");
            return ExitCode::from(1);
        }
    };
    let hardware = match forge_hardware::collect() {
        Ok(hardware) => hardware,
        Err(error) => {
            eprintln!("hardware detection failed: {error}");
            return ExitCode::from(2);
        }
    };
    let resources = match forge_profiles::plan(&hardware, &profile) {
        Ok(resources) => resources,
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
    let plan = match forge_storage::plan_image_prepare(
        &mut backend,
        &profile,
        &resources,
        &source,
        source_size,
        source_capacity,
    ) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("cannot safely prepare Fedora-Lab: {error}");
            return ExitCode::from(1);
        }
    };
    print_image_prepare_plan(&plan);
    if dry_run {
        println!("\nPlanned domain XML:\n{}", plan.xml);
        return ExitCode::SUCCESS;
    }
    eprint!("Prepare Fedora-Lab disk from verified Fedora image? [y/N] ");
    let mut answer = String::new();
    if io::stdin().read_line(&mut answer).is_err()
        || !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
    {
        eprintln!("Preparation cancelled.");
        return ExitCode::SUCCESS;
    }
    match forge_storage::execute_image_prepare(&mut backend, &plan) {
        Ok(result) => {
            println!("Base volume: {}", result.base.path);
            println!("Overlay volume: {}", result.overlay.path);
            println!("Domain UUID: {}", result.domain.uuid);
            println!("Domain state: {}", result.domain.state);
            for (path, diagnostic) in result.context.qemu_img_diagnostics {
                println!("qemu-img {path}: {diagnostic}");
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Fedora-Lab preparation failed: {error}");
            ExitCode::from(1)
        }
    }
}

fn print_image_prepare_plan(plan: &forge_storage::ImagePreparePlan) {
    println!("Verified source: {}", plan.source.local_path.display());
    println!("Source status: {}", plan.source.status);
    println!(
        "Source SHA-256: {}",
        plan.source.actual_checksum.as_deref().unwrap_or("unknown")
    );
    println!("Source size: {} bytes", plan.source_size_bytes);
    println!(
        "Source virtual capacity: {} bytes",
        plan.source_capacity_bytes
    );
    println!(
        "Storage pool: {} ({})",
        plan.pool.name, plan.pool.target_path
    );
    println!("Base volume: {}", plan.base.name);
    println!("Base path: {}", plan.base.path);
    println!("Base policy: imported immutable qcow2; never a guest disk");
    println!("Overlay volume: {}", plan.overlay.name);
    println!("Overlay path: {}", plan.overlay.path);
    println!(
        "Backing store: {} -> {}",
        plan.overlay.path,
        plan.overlay.backing_path.as_deref().unwrap_or("none")
    );
    println!("Domain state: {}", plan.existing_domain.state);
    println!("Domain persistent: {}", plan.existing_domain.persistent);
    println!("Domain autostart: {}", plan.existing_domain.autostart);
    println!("Existing volume: {}", plan.existing_volume.path);
    println!("Existing format: {}", plan.existing_volume.format);
    println!(
        "Existing capacity: {} bytes",
        plan.existing_volume.capacity_bytes
    );
    println!(
        "Existing allocation: {} bytes",
        plan.existing_volume.allocation_bytes
    );
    println!(
        "Existing backing store: {}",
        plan.existing_volume
            .backing_path
            .as_deref()
            .unwrap_or("none")
    );
    println!("Migration safe: {}", plan.migration_safe);
}

fn image_directories() -> Result<forge_images::ImageDirectories, ExitCode> {
    forge_images::default_directories().ok_or_else(|| {
        eprintln!("cannot determine Forge image directories: HOME is unavailable");
        ExitCode::from(2)
    })
}

fn image_list() -> ExitCode {
    let Ok(directories) = image_directories() else {
        return ExitCode::from(2);
    };
    match forge_images::list(&directories) {
        Ok(images) => {
            println!("DISTRO\tRELEASE\tARCH\tSTATUS");
            for image in images {
                println!(
                    "{}\t{}\t{}\t{}",
                    image.distro, image.release, image.architecture, image.status
                );
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("image listing failed: {error}");
            ExitCode::from(1)
        }
    }
}

fn image_inspect() -> ExitCode {
    let Ok(directories) = image_directories() else {
        return ExitCode::from(2);
    };
    match forge_images::inspect(&directories) {
        Ok(metadata) => {
            print_image_metadata(&metadata);
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("image inspection failed: {error}");
            ExitCode::from(1)
        }
    }
}

fn image_fetch() -> ExitCode {
    let Ok(directories) = image_directories() else {
        return ExitCode::from(2);
    };
    println!("Fetching official Fedora Cloud Base 44 x86_64 image...");
    let mut fetcher = forge_images::SystemArtifactFetcher;
    match forge_images::fetch_fedora(&directories, &mut fetcher) {
        Ok(metadata) => {
            print_image_metadata(&metadata);
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Fedora image fetch failed: {error}");
            ExitCode::from(1)
        }
    }
}

fn print_image_metadata(metadata: &forge_images::ImageMetadata) {
    println!("Distro: {}", metadata.distro);
    println!("Release: {}", metadata.release);
    println!("Architecture: {}", metadata.architecture);
    println!("Source: {}", metadata.source_url);
    println!("Local path: {}", metadata.local_path.display());
    println!(
        "Expected SHA-256: {}",
        metadata.expected_checksum.as_deref().unwrap_or("unknown")
    );
    println!(
        "Actual SHA-256: {}",
        metadata.actual_checksum.as_deref().unwrap_or("unknown")
    );
    println!(
        "Verified at: {}",
        metadata
            .verified_at_unix_seconds
            .map_or_else(|| "never".to_owned(), |value| value.to_string())
    );
    println!("Status: {}", metadata.status);
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
    eprintln!("  forge vm status fedora-lab");
    eprintln!("  forge vm cleanup fedora-lab --dry-run");
    eprintln!("  forge vm start fedora-lab [--dry-run]");
    eprintln!("  forge vm shutdown fedora-lab [--dry-run]");
    eprintln!("  forge state show fedora-lab");
    eprintln!("  forge state reconcile fedora-lab");
    eprintln!("  forge state adopt fedora-lab [--dry-run]");
    eprintln!("  forge vm define fedora-lab [--dry-run]");
    eprintln!("  forge vm prepare fedora-lab [--dry-run]");
    eprintln!("  forge vm boot fedora-lab [--dry-run]");
    eprintln!("  forge vm rebuild fedora-lab [--dry-run]");
    eprintln!("  forge domain render fedora-lab");
    eprintln!("  forge image list");
    eprintln!("  forge image inspect fedora");
    eprintln!("  forge image fetch fedora");
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
