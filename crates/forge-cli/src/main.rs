use forge_core::{
    DoctorReport, DomainSummary, HostState, InstanceName, LibvirtInfo, ProfileId, VmResourcePlan,
};
use forge_provisioning::{BootBackend, RebuildBackend};
use std::env;
use std::io;
use std::os::fd::AsRawFd;
use std::process::ExitCode;
use std::time::{Duration, Instant};

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
                println!("{}\t{}", profile.id, profile.display_name);
            }
            ExitCode::SUCCESS
        }
        ["profile", "show", profile_name] => show_profile(profile_name),
        ["profile", "plan", profile_name] => plan_profile(profile_name),
        ["vm", "plan", profile_name, instance_name] => plan_instance(profile_name, instance_name),
        ["vm", "create", profile_name, instance_name, "--dry-run"] => {
            create_vm_dry_run(profile_name, instance_name)
        }
        ["vm", "create", profile_name, instance_name] => create_vm(profile_name, instance_name),
        ["hypervisor", "info"] => hypervisor_info(),
        ["vm", "list"] => vm_list(),
        ["vm", "status", instance] => lifecycle_status(instance),
        ["vm", "cleanup", "fedora-lab", "--dry-run"] => cleanup_vm_dry_run(),
        ["vm", "cleanup", "fedora-lab"] => managed_cleanup(false),
        ["vm", "start", instance, "--dry-run"] => {
            lifecycle_action(instance, forge_provisioning::LifecycleAction::Start, true)
        }
        ["vm", "start", instance] => {
            lifecycle_action(instance, forge_provisioning::LifecycleAction::Start, false)
        }
        ["vm", "shutdown", instance, "--dry-run"] => lifecycle_action(
            instance,
            forge_provisioning::LifecycleAction::Shutdown,
            true,
        ),
        ["vm", "shutdown", instance] => lifecycle_action(
            instance,
            forge_provisioning::LifecycleAction::Shutdown,
            false,
        ),
        ["vm", "stop", instance, "--force", "--dry-run"] => lifecycle_action(
            instance,
            forge_provisioning::LifecycleAction::ForceStop,
            true,
        ),
        ["vm", "stop", instance, "--force"] => lifecycle_action(
            instance,
            forge_provisioning::LifecycleAction::ForceStop,
            false,
        ),
        ["state", "show", "fedora-lab"] => state_show(),
        ["state", "reconcile", instance] => state_reconcile(instance),
        ["state", "recover", "fedora-lab", "--dry-run"] => state_recover(true),
        ["state", "recover", "fedora-lab"] => state_recover(false),
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
        ["vm", "rebuild", "fedora-lab", "--managed", "--dry-run"] => managed_rebuild(true),
        ["vm", "rebuild", "fedora-lab", "--managed"] => managed_rebuild(false),
        ["domain", "render", profile_name] => render_domain(profile_name),
        ["image", "list"] => image_list(),
        ["image", "inspect", "fedora"] => image_inspect(),
        ["image", "fetch", "fedora"] => image_fetch(),
        ["image", "recover", "whonix-workstation", "--dry-run"] => recover_whonix_workstation(true),
        ["image", "recover", "whonix-workstation"] => recover_whonix_workstation(false),
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

#[allow(clippy::too_many_lines)]
fn state_reconcile(instance_name: &str) -> ExitCode {
    let instance = match InstanceName::new(instance_name) {
        Ok(instance) => instance,
        Err(error) => {
            eprintln!("invalid instance name: {error}");
            return ExitCode::from(2);
        }
    };
    let layout = match managed_state_layout_for(&instance) {
        Ok(layout) => layout,
        Err(error) => {
            eprintln!("Forge state path failed: {error}");
            return ExitCode::from(1);
        }
    };
    let state = match forge_state::inspect_layout(&layout) {
        Ok(state) => state,
        Err(error) => {
            println!("ReconciliationStatus: CorruptState");
            eprintln!("{error}");
            return ExitCode::from(1);
        }
    };
    let manifest = match state {
        forge_state::ManagedState::Missing => {
            println!("ReconciliationStatus: Missing");
            println!("Manifest path: {}", layout.legacy_manifest.display());
            return ExitCode::SUCCESS;
        }
        forge_state::ManagedState::Legacy(manifest) => manifest,
        forge_state::ManagedState::Current(index) => {
            let manifests = match load_index_manifests(&layout, &index) {
                Ok(manifests) => manifests,
                Err(error) => {
                    println!("ManagedReconciliationStatus: Conflict");
                    eprintln!("{error}");
                    return ExitCode::from(1);
                }
            };
            let active = match active_manifest(&index, &manifests) {
                Ok(active) => active,
                Err(error) => {
                    println!("ManagedReconciliationStatus: Conflict");
                    eprintln!("{error}");
                    return ExitCode::from(1);
                }
            };
            if let Err(error) = validate_profile_binding(instance_name, &index, active) {
                println!("ManagedReconciliationStatus: Conflict");
                eprintln!("{error}");
                return ExitCode::from(1);
            }
            let backend =
                match forge_libvirt::LibvirtBootBackend::connect_instance(instance.clone()) {
                    Ok(backend) => backend,
                    Err(error) => {
                        eprintln!("libvirt connection failed: {error}");
                        return ExitCode::from(1);
                    }
                };
            let observed = match backend.inspect_managed_state(active) {
                Ok(observed) => observed,
                Err(error) => {
                    eprintln!("instance state discovery failed: {error}");
                    return ExitCode::from(1);
                }
            };
            let report = forge_state::reconcile_managed(&index, &manifests, &observed);
            println!("ManagedReconciliationStatus: {:?}", report.status);
            println!("Detail: {}", report.detail);
            println!(
                "Observed generation: {}",
                report
                    .observed_generation_id
                    .as_deref()
                    .unwrap_or("unknown")
            );
            if let Some(reason) = report.recovery_reason {
                println!("Recovery: {reason:?}");
            }
            if let Some(reason) = report.conflict_reason {
                println!("Conflict: {reason:?}");
            }
            return if report.status == forge_state::ManagedReconciliationStatus::Consistent {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            };
        }
        forge_state::ManagedState::Conflict(reason) => {
            println!("ManagedReconciliationStatus: Conflict");
            eprintln!("{reason}");
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

fn recovery_inputs(
    backend: &forge_libvirt::LibvirtBootBackend,
) -> Result<
    (
        forge_state::ObservedGeneration,
        forge_state::RecoveryObservability,
        forge_provisioning::SshObservation,
    ),
    String,
> {
    let lifecycle = backend
        .inspect_lifecycle()
        .map_err(|error| format!("recovery lifecycle discovery failed: {error}"))?;
    let observed = backend
        .inspect_state()
        .map_err(|error| format!("recovery state discovery failed: {error}"))?;
    let ip_address = lifecycle
        .ip_addresses
        .iter()
        .find(|address| !address.contains(':'))
        .cloned();
    let home = env::var_os("HOME").ok_or_else(|| "HOME is unavailable".to_owned())?;
    let ssh_directory = std::path::PathBuf::from(home).join(".ssh");
    let private_key = ssh_directory.join("forge_ed25519");
    let known_hosts = ssh_directory.join("forge-recovery-known_hosts");
    let host_identity = std::fs::read_to_string(&known_hosts)
        .map_err(|error| format!("dedicated recovery known_hosts cannot be read: {error}"))?;
    if host_identity.lines().count() != 1 || host_identity.trim().is_empty() {
        return Err(
            "dedicated recovery known_hosts must contain exactly one host identity".to_owned(),
        );
    }
    let ssh = if let Some(ip) = ip_address.as_deref() {
        backend
            .observe_recovery_ssh(
                ip,
                private_key.to_string_lossy().as_ref(),
                known_hosts.to_string_lossy().as_ref(),
                Duration::from_secs(30),
            )
            .map_err(|error| format!("recovery SSH observability failed: {error}"))?
    } else {
        forge_provisioning::SshObservation {
            status: forge_provisioning::SshStatus::NotChecked,
            cloud_init: forge_provisioning::CloudInitStatus::Unknown,
            forge_user_confirmed: false,
            hostname: None,
        }
    };
    let health = forge_state::RecoveryObservability {
        domain_running: lifecycle.domain_state == forge_core::VmState::Running,
        ip_address,
        qga_channel: lifecycle.guest_agent_channel,
        qga_available: lifecycle.guest_agent_status
            == forge_provisioning::GuestAgentStatus::Available,
        ssh_host_identity_verified: ssh.status == forge_provisioning::SshStatus::Authenticated,
        ssh_host_identity: Some(host_identity),
        ssh_authenticated: ssh.status == forge_provisioning::SshStatus::Authenticated,
        cloud_init_done: ssh.cloud_init == forge_provisioning::CloudInitStatus::Done,
        forge_user_confirmed: ssh.forge_user_confirmed,
        hostname: ssh.hostname.clone(),
    };
    Ok((observed, health, ssh))
}

#[allow(clippy::too_many_lines)]
fn state_recover(dry_run: bool) -> ExitCode {
    let layout = match managed_state_layout() {
        Ok(value) => value,
        Err(error) => {
            eprintln!("recovery refused: {error}");
            return ExitCode::from(1);
        }
    };
    let index = match forge_state::inspect_layout(&layout) {
        Ok(forge_state::ManagedState::Current(index)) => index,
        Ok(_) => {
            eprintln!("recovery refused: current managed generation index is required");
            return ExitCode::from(1);
        }
        Err(error) => {
            eprintln!("recovery refused: {error}");
            return ExitCode::from(1);
        }
    };
    let manifests = match load_index_manifests(&layout, &index) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("recovery refused: {error}");
            return ExitCode::from(1);
        }
    };
    let backend = match forge_libvirt::LibvirtBootBackend::connect_local() {
        Ok(value) => value,
        Err(error) => {
            eprintln!("recovery refused: libvirt connection failed: {error}");
            return ExitCode::from(1);
        }
    };
    let (observed, health, ssh) = match recovery_inputs(&backend) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("recovery refused: {error}");
            return ExitCode::from(1);
        }
    };
    let plan = match forge_state::plan_managed_recovery(&index, &manifests, &observed, &health) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("RecoverySafetyDecision: Refused");
            eprintln!("{error}");
            return ExitCode::from(1);
        }
    };
    print_recovery_plan(&index, &plan, &ssh, dry_run);
    if dry_run {
        return ExitCode::SUCCESS;
    }
    eprint!("Finalize the exact observed Preparing generation? [y/N] ");
    let mut confirmation = String::new();
    if io::stdin().read_line(&mut confirmation).is_err()
        || !matches!(confirmation.trim(), "y" | "Y" | "yes" | "YES")
    {
        println!("Recovery cancelled; state unchanged.");
        return ExitCode::SUCCESS;
    }
    let fresh_index = match forge_state::read_index(&layout.index) {
        Ok(Some(value)) => value,
        Ok(None) => {
            eprintln!("recovery refused: index disappeared before execute");
            return ExitCode::from(1);
        }
        Err(error) => {
            eprintln!("recovery refused: index revalidation failed: {error}");
            return ExitCode::from(1);
        }
    };
    let fresh_manifests = match load_index_manifests(&layout, &fresh_index) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("recovery refused: {error}");
            return ExitCode::from(1);
        }
    };
    let (fresh_observed, fresh_health, _) = match recovery_inputs(&backend) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("recovery refused during fresh validation: {error}");
            return ExitCode::from(1);
        }
    };
    let next = match forge_state::execute_managed_recovery(
        &plan,
        &fresh_index,
        &fresh_manifests,
        &fresh_observed,
        &fresh_health,
    ) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("recovery refused during pre-execute revalidation: {error}");
            return ExitCode::from(1);
        }
    };
    match forge_state::write_index_atomic(&layout.index, &next) {
        Ok(()) => {
            println!("Recovery finalized atomically; immutable manifests were not changed.");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("atomic recovery state transition failed: {error}");
            ExitCode::from(1)
        }
    }
}

fn print_recovery_plan(
    index: &forge_state::GenerationIndex,
    plan: &forge_state::ManagedRecoveryPlan,
    ssh: &forge_provisioning::SshObservation,
    dry_run: bool,
) {
    println!("Durable generations:");
    for entry in &index.generations {
        println!("- {}: {:?}", entry.generation_id, entry.status);
    }
    println!("Observed generation: {}", plan.preparing_generation_id);
    println!("Fresh observability:");
    println!("- DomainRunning: {}", plan.observability.domain_running);
    println!(
        "- IPv4: {}",
        plan.observability
            .ip_address
            .as_deref()
            .unwrap_or("unknown")
    );
    println!("- QgaAvailable: {}", plan.observability.qga_available);
    println!("- SshStatus: {:?}", ssh.status);
    println!("- CloudInitStatus: {:?}", ssh.cloud_init);
    println!("- forge_user_confirmed: {}", ssh.forge_user_confirmed);
    println!(
        "- hostname: {}",
        ssh.hostname.as_deref().unwrap_or("unknown")
    );
    println!("Planned transition:");
    println!("- {}: Active -> Retained", plan.active_generation_id);
    println!("- {}: Preparing -> Active", plan.preparing_generation_id);
    println!("RecoverySafetyDecision: Allowed");
    println!("Mutation: {}", !dry_run);
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

fn confirmation_accepted(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
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

fn discover_lifecycle_status(
    operational: &OperationalInstance,
) -> Result<forge_provisioning::InstanceLifecycleStatus, String> {
    let backend = forge_libvirt::LibvirtBootBackend::connect_instance(operational.instance.clone())
        .map_err(|error| format!("libvirt connection failed: {error}"))?;
    let status = backend
        .inspect_managed_lifecycle(&operational.active)
        .map_err(|error| format!("instance lifecycle discovery failed: {error}"))?;
    let observed = backend
        .inspect_managed_state(&operational.active)
        .map_err(|error| format!("instance reconciliation discovery failed: {error}"))?;
    let reconciliation =
        forge_state::reconcile_managed(&operational.index, &operational.manifests, &observed);
    if reconciliation.status != forge_state::ManagedReconciliationStatus::Consistent {
        return Err(format!(
            "instance lifecycle denied by {:?}: {}",
            reconciliation.status, reconciliation.detail
        ));
    }
    Ok(status)
}

fn lifecycle_status(instance_name: &str) -> ExitCode {
    let operational = match operational_instance(instance_name) {
        Ok(operational) => operational,
        Err(error) => {
            eprintln!("instance resolution failed: {error}");
            return ExitCode::from(1);
        }
    };
    match discover_lifecycle_status(&operational) {
        Ok(status) => {
            print_lifecycle_status(instance_name, &status);
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(1)
        }
    }
}

fn cleanup_vm_dry_run() -> ExitCode {
    managed_cleanup(true)
}

fn managed_state_layout() -> Result<forge_state::StateLayout, String> {
    let instance = InstanceName::new("fedora-lab").expect("compatibility instance name is valid");
    managed_state_layout_for(&instance)
}

fn managed_state_layout_for(instance: &InstanceName) -> Result<forge_state::StateLayout, String> {
    let home = env::var_os("HOME").ok_or_else(|| "HOME is unavailable".to_owned())?;
    Ok(forge_state::StateLayout::for_instance(
        &forge_state::state_directory(std::path::Path::new(&home)),
        instance,
    ))
}

fn active_manifest<'a>(
    index: &forge_state::GenerationIndex,
    manifests: &'a [forge_state::GenerationManifest],
) -> Result<&'a forge_state::GenerationManifest, String> {
    let active_entries = index
        .generations
        .iter()
        .filter(|entry| entry.status == forge_state::GenerationStatus::Active)
        .collect::<Vec<_>>();
    if active_entries.len() != 1 || active_entries[0].generation_id != index.active_generation_id {
        return Err("durable state does not contain exactly one selected Active generation".into());
    }
    manifests
        .iter()
        .find(|manifest| manifest.generation_id == index.active_generation_id)
        .ok_or_else(|| "active generation manifest is missing".to_owned())
}

fn validate_profile_binding(
    instance_name: &str,
    index: &forge_state::GenerationIndex,
    active: &forge_state::GenerationManifest,
) -> Result<forge_core::VmProfile, String> {
    let durable_base = active
        .resources
        .iter()
        .find(|resource| resource.role == forge_state::ResourceRole::SharedBase)
        .ok_or_else(|| "active generation lacks SharedBase".to_owned())?;
    let profile = if let Some(profile) = forge_profiles::find(instance_name) {
        profile
    } else {
        let mut matching = forge_profiles::built_in_profiles()
            .into_iter()
            .filter(|profile| {
                profile.persistence == forge_core::PersistencePolicy::Persistent
                    && forge_profiles::base_volume_name(profile) == durable_base.volume_name
            })
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            return Err(format!(
                "durable shared-base identity does not select exactly one profile for instance {instance_name}"
            ));
        }
        matching.remove(0)
    };
    if profile.persistence != forge_core::PersistencePolicy::Persistent {
        return Err("operational lifecycle requires Persistent profile policy".to_owned());
    }
    if index.domain_name != instance_name || active.domain_name != instance_name {
        return Err("profile, instance, and durable domain identity differ".to_owned());
    }
    let resource = |role| {
        active
            .resources
            .iter()
            .find(|resource| resource.role == role)
            .ok_or_else(|| format!("active generation lacks {role:?}"))
    };
    let base = resource(forge_state::ResourceRole::SharedBase)?;
    let overlay = resource(forge_state::ResourceRole::WritableOverlay)?;
    if base.volume_name != forge_profiles::base_volume_name(&profile)
        || overlay.capacity_bytes != profile.resources.disk_bytes
    {
        return Err("active generation topology differs from profile policy".to_owned());
    }
    validate_provisioning_topology(&profile.provisioning, &active.resources)?;
    Ok(profile)
}

fn validate_provisioning_topology(
    policy: &forge_core::ProvisioningPolicy,
    resources: &[forge_state::ManagedResource],
) -> Result<(), String> {
    let seeds = resources
        .iter()
        .filter(|resource| resource.role == forge_state::ResourceRole::NoCloudSeed)
        .collect::<Vec<_>>();
    match policy {
        forge_core::ProvisioningPolicy::NoCloud { .. }
            if seeds.len() == 1 && seeds[0].capacity_bytes > 0 =>
        {
            Ok(())
        }
        forge_core::ProvisioningPolicy::NoCloud { .. } => {
            Err("NoCloud profile requires exactly one non-empty seed".to_owned())
        }
        forge_core::ProvisioningPolicy::None if seeds.is_empty() => Ok(()),
        forge_core::ProvisioningPolicy::None => {
            Err("manual provisioning profile forbids a seed".to_owned())
        }
    }
}

struct OperationalInstance {
    instance: InstanceName,
    profile: forge_core::VmProfile,
    index: forge_state::GenerationIndex,
    manifests: Vec<forge_state::GenerationManifest>,
    active: forge_state::GenerationManifest,
}

fn operational_instance(instance_name: &str) -> Result<OperationalInstance, String> {
    let instance = InstanceName::new(instance_name)
        .map_err(|error| format!("invalid instance name: {error}"))?;
    let layout = managed_state_layout_for(&instance)?;
    let index = match forge_state::inspect_layout(&layout).map_err(|error| error.to_string())? {
        forge_state::ManagedState::Current(index) => index,
        forge_state::ManagedState::Missing => {
            return Err("managed instance state is missing".into());
        }
        forge_state::ManagedState::Legacy(_) => {
            return Err("legacy state requires explicit migration before managed lifecycle".into());
        }
        forge_state::ManagedState::Conflict(reason) => return Err(reason),
    };
    let manifests = load_index_manifests(&layout, &index)?;
    let active = active_manifest(&index, &manifests)?.clone();
    let profile = validate_profile_binding(instance_name, &index, &active)?;
    Ok(OperationalInstance {
        instance,
        profile,
        index,
        manifests,
        active,
    })
}

fn load_generation(path: &std::path::Path) -> Result<forge_state::GenerationManifest, String> {
    forge_state::read_manifest(path)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("generation manifest is missing: {}", path.display()))
}

fn load_index_manifests(
    layout: &forge_state::StateLayout,
    index: &forge_state::GenerationIndex,
) -> Result<Vec<forge_state::GenerationManifest>, String> {
    index
        .generations
        .iter()
        .map(|entry| load_generation(&layout.generation_path(&entry.generation_id)))
        .collect()
}

fn discover_cleanup_evidence(
    backend: &forge_libvirt::LibvirtBootBackend,
    index: &forge_state::GenerationIndex,
    manifests: &[forge_state::GenerationManifest],
    observed_active: &forge_state::ObservedGeneration,
) -> Vec<forge_state::RetainedEvidence> {
    manifests
        .iter()
        .map(|manifest| {
            let overlay = manifest
                .resources
                .iter()
                .find(|resource| resource.role == forge_state::ResourceRole::WritableOverlay)
                .map_or("", |resource| resource.path.as_str());
            let seed = manifest
                .resources
                .iter()
                .find(|resource| resource.role == forge_state::ResourceRole::NoCloudSeed)
                .map_or("", |resource| resource.path.as_str());
            let actual = if manifest.generation_id == index.active_generation_id {
                Ok(observed_active.clone())
            } else {
                backend.inspect_generation_paths(overlay, seed)
            };
            let observed_pool_uuid = actual
                .as_ref()
                .map(|value| value.storage_pool_uuid.clone())
                .unwrap_or_default();
            let resources = match actual {
                Ok(actual) => manifest
                    .resources
                    .iter()
                    .map(|expected| {
                        let found = actual
                            .resources
                            .iter()
                            .find(|resource| resource.role == expected.role);
                        forge_state::ResourceEvidence {
                            resource: expected.clone(),
                            exists: found.is_some(),
                            observed_resource: found.map(|item| forge_state::ManagedResource {
                                role: item.role,
                                volume_name: item.volume_name.clone(),
                                volume_key: item.volume_key.clone(),
                                path: item.path.clone(),
                                format: item.format.clone(),
                                capacity_bytes: item.capacity_bytes,
                                backing_path: item.backing_path.clone(),
                            }),
                            referenced_by_domains: found
                                .map(|item| item.referenced_by_domains.clone())
                                .unwrap_or_default(),
                            backing_for_volumes: found
                                .map(|item| item.backing_for_volumes.clone())
                                .unwrap_or_default(),
                        }
                    })
                    .collect(),
                Err(_) => manifest
                    .resources
                    .iter()
                    .cloned()
                    .map(|resource| forge_state::ResourceEvidence {
                        resource,
                        exists: false,
                        observed_resource: None,
                        referenced_by_domains: Vec::new(),
                        backing_for_volumes: Vec::new(),
                    })
                    .collect(),
            };
            let mut authoritative = manifest.clone();
            if let Some(entry) = index
                .generations
                .iter()
                .find(|entry| entry.generation_id == manifest.generation_id)
            {
                authoritative.status = entry.status;
            }
            forge_state::RetainedEvidence {
                manifest: authoritative,
                observed_pool_uuid,
                resources,
            }
        })
        .collect()
}

struct CleanupExecutor<'a> {
    backend: &'a forge_libvirt::LibvirtBootBackend,
    layout: &'a forge_state::StateLayout,
}

impl forge_state::CleanupBackend for CleanupExecutor<'_> {
    fn revalidate(
        &mut self,
        plan: &forge_state::ManagedCleanupPlan,
        candidate: &forge_state::ManagedCleanupCandidate,
    ) -> Result<(), String> {
        let fresh_index = forge_state::read_index(&self.layout.index)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "generation index disappeared".to_owned())?;
        if fresh_index != plan.source_index {
            return Err("generation index changed since planning".to_owned());
        }
        let manifests = load_index_manifests(self.layout, &fresh_index)?;
        let observed = self
            .backend
            .inspect_state()
            .map_err(|error| error.to_string())?;
        let reconciliation = forge_state::reconcile_managed(&fresh_index, &manifests, &observed);
        let evidence = discover_cleanup_evidence(self.backend, &fresh_index, &manifests, &observed);
        let fresh_plan = forge_state::plan_managed_cleanup(
            &fresh_index,
            &evidence,
            observed.unmanaged_resources.clone(),
            reconciliation.status,
        )
        .map_err(|error| error.to_string())?;
        if fresh_plan.source_evidence != plan.source_evidence
            || fresh_plan.source_reconciliation != plan.source_reconciliation
            || fresh_plan.unmanaged_legacy != plan.unmanaged_legacy
            || fresh_plan.shared_protected != plan.shared_protected
            || fresh_plan.candidates != plan.candidates
            || !fresh_plan.candidates.contains(candidate)
        {
            return Err("libvirt/storage cleanup snapshot changed since planning".to_owned());
        }
        Ok(())
    }

    fn persist_index(
        &mut self,
        expected: &forge_state::GenerationIndex,
        next: &forge_state::GenerationIndex,
    ) -> Result<(), String> {
        let current = forge_state::read_index(&self.layout.index)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "generation index disappeared".to_owned())?;
        if &current != expected {
            return Err("generation index changed before durable cleanup transition".to_owned());
        }
        forge_state::write_index_atomic(&self.layout.index, next).map_err(|error| error.to_string())
    }

    fn delete_exact(&mut self, resource: &forge_state::ManagedResource) -> Result<(), String> {
        self.backend
            .delete_managed_volume_exact(resource)
            .map_err(|error| error.to_string())
    }

    fn verify_absent(&mut self, resource: &forge_state::ManagedResource) -> Result<(), String> {
        self.backend
            .verify_managed_volume_absent(resource)
            .map_err(|error| error.to_string())
    }
}

#[allow(clippy::too_many_lines)]
fn managed_cleanup(dry_run: bool) -> ExitCode {
    let layout = match managed_state_layout() {
        Ok(value) => value,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(1);
        }
    };
    let state = match forge_state::inspect_layout(&layout) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("cleanup state failed closed: {error}");
            return ExitCode::from(1);
        }
    };
    let observed_active = match discover_state() {
        Ok(value) => value,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(1);
        }
    };
    let (index, manifests) = match state {
        forge_state::ManagedState::Legacy(manifest) => {
            let migration = match forge_state::plan_migration(&layout, &manifest) {
                Ok(value) => value,
                Err(error) => {
                    eprintln!("migration planning failed: {error}");
                    return ExitCode::from(1);
                }
            };
            (migration.index, vec![manifest])
        }
        forge_state::ManagedState::Current(index) => {
            let mut manifests = Vec::new();
            for entry in &index.generations {
                match load_generation(&layout.generation_path(&entry.generation_id)) {
                    Ok(value) => manifests.push(value),
                    Err(error) => {
                        eprintln!("cleanup refused: {error}");
                        return ExitCode::from(1);
                    }
                }
            }
            (index, manifests)
        }
        forge_state::ManagedState::Missing => {
            eprintln!("cleanup refused: Forge ownership state is missing");
            return ExitCode::from(1);
        }
        forge_state::ManagedState::Conflict(reason) => {
            eprintln!("cleanup refused: {reason}");
            return ExitCode::from(1);
        }
    };
    let managed_reconciliation =
        forge_state::reconcile_managed(&index, &manifests, &observed_active);
    if managed_reconciliation.status != forge_state::ManagedReconciliationStatus::Consistent {
        eprintln!(
            "cleanup refused: {:?}: {}",
            managed_reconciliation.status, managed_reconciliation.detail
        );
        return ExitCode::from(1);
    }
    let backend = match forge_libvirt::LibvirtBootBackend::connect_local() {
        Ok(value) => value,
        Err(error) => {
            eprintln!("libvirt connection failed: {error}");
            return ExitCode::from(1);
        }
    };
    let evidence = discover_cleanup_evidence(&backend, &index, &manifests, &observed_active);
    let plan = match forge_state::plan_managed_cleanup(
        &index,
        &evidence,
        observed_active.unmanaged_resources.clone(),
        managed_reconciliation.status,
    ) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("cleanup refused: {error}");
            return ExitCode::from(1);
        }
    };
    println!(
        "Cleanup mode: {}",
        if dry_run {
            "dry-run (zero mutation)"
        } else {
            "real"
        }
    );
    println!("ACTIVE OWNED\n- {}", plan.active_generation_id);
    println!("RETAINED OWNED");
    if plan.retained_generation_ids.is_empty() {
        println!("- none");
    } else {
        for id in &plan.retained_generation_ids {
            println!("- {id}");
        }
    }
    println!("FAILED");
    let failed = index
        .generations
        .iter()
        .filter(|entry| entry.status == forge_state::GenerationStatus::Failed)
        .collect::<Vec<_>>();
    if failed.is_empty() {
        println!("- none");
    } else {
        for entry in failed {
            println!("- {}", entry.generation_id);
        }
    }
    println!("UNMANAGED LEGACY");
    if plan.unmanaged_legacy.is_empty() {
        println!("- none");
    } else {
        for item in &plan.unmanaged_legacy {
            println!("- {item}");
        }
    }
    println!("SHARED / PROTECTED");
    for item in &plan.shared_protected {
        println!("- {item}");
    }
    println!("DELETE CANDIDATES");
    if plan.candidates.is_empty() {
        println!("- none");
    } else {
        for candidate in &plan.candidates {
            println!("- generation {}", candidate.generation_id);
            for proof in &candidate.proof {
                println!("  proof: {proof}");
            }
            for resource in &candidate.resources {
                println!(
                    "  {:?}: {} key={}",
                    resource.role, resource.path, resource.volume_key
                );
            }
        }
    }
    println!("CONFLICT / REFUSED");
    if plan.refused.is_empty() {
        println!("- none");
    } else {
        for item in &plan.refused {
            println!("- {item}");
        }
    }
    println!("EXECUTE ORDER");
    println!("- revalidate complete durable/libvirt snapshot");
    println!("- atomically persist cleanup intent");
    println!("- exact delete seed through libvirt storage API");
    println!("- verify exact seed absence and persist progress");
    println!("- exact delete overlay through libvirt storage API");
    println!("- verify exact overlay absence");
    println!("- atomically mark generation Cleaned");
    println!("- final managed reconciliation");
    if dry_run {
        return ExitCode::SUCCESS;
    }
    if plan.candidates.is_empty() {
        println!("Nothing to clean.");
        return ExitCode::SUCCESS;
    }
    eprint!("Delete exact retained-owned Fedora-Lab generation resources? [y/N] ");
    let mut answer = String::new();
    if io::stdin().read_line(&mut answer).is_err()
        || !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
    {
        eprintln!("Cleanup cancelled.");
        return ExitCode::SUCCESS;
    }
    if plan.candidates.len() != 1 {
        eprintln!("cleanup refused: execute requires exactly one proven Retained candidate");
        return ExitCode::from(1);
    }
    let mut executor = CleanupExecutor {
        backend: &backend,
        layout: &layout,
    };
    let execution =
        match forge_state::execute_cleanup_candidate(&mut executor, &plan, &plan.candidates[0]) {
            Ok(value) => value,
            Err(error) => {
                eprintln!("cleanup stopped fail-closed: {error}");
                return ExitCode::from(1);
            }
        };
    let final_manifests = match load_index_manifests(&layout, &execution.next_index) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("cleanup completed but final reconciliation failed: {error}");
            return ExitCode::from(1);
        }
    };
    let final_observed = match discover_state() {
        Ok(value) => value,
        Err(error) => {
            eprintln!("cleanup completed but final reconciliation failed: {error}");
            return ExitCode::from(1);
        }
    };
    let final_reconciliation =
        forge_state::reconcile_managed(&execution.next_index, &final_manifests, &final_observed);
    if final_reconciliation.status != forge_state::ManagedReconciliationStatus::Consistent {
        eprintln!(
            "cleanup completed but final reconciliation is {:?}: {}",
            final_reconciliation.status, final_reconciliation.detail
        );
        return ExitCode::from(1);
    }
    println!(
        "Exact retained-owned cleanup completed; shared base and unmanaged legacy were untouched."
    );
    ExitCode::SUCCESS
}

#[allow(clippy::too_many_lines)]
fn lifecycle_action(
    instance_name: &str,
    action: forge_provisioning::LifecycleAction,
    dry_run: bool,
) -> ExitCode {
    let operational = match operational_instance(instance_name) {
        Ok(operational) => operational,
        Err(error) => {
            eprintln!("instance resolution failed: {error}");
            return ExitCode::from(1);
        }
    };
    let status = match discover_lifecycle_status(&operational) {
        Ok(status) => status,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(1);
        }
    };
    let plan = match forge_provisioning::plan_instance_lifecycle(
        &status,
        &operational.profile,
        true,
        action,
    ) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("instance lifecycle action denied: {error}");
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
    println!("Instance: {instance_name}");
    println!(
        "Active generation: {}",
        operational.index.active_generation_id
    );
    println!("Domain UUID: {}", status.domain_uuid);
    println!("Current state: {}", plan.current_state);
    println!("Timeout: {} seconds", plan.timeout_seconds);
    println!(
        "Confirmation required: {}",
        plan.idempotent_result.is_none()
    );
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
    println!("Mutation: {}", !dry_run && plan.idempotent_result.is_none());
    if dry_run || plan.idempotent_result.is_some() {
        return ExitCode::SUCCESS;
    }
    eprint!(
        "{} instance {} now? [y/N] ",
        match action {
            forge_provisioning::LifecycleAction::Start => "Start",
            forge_provisioning::LifecycleAction::Shutdown => "Gracefully shut down",
            forge_provisioning::LifecycleAction::ForceStop => {
                "FORCE-STOP (equivalent to cutting VM power)"
            }
        },
        instance_name,
    );
    let mut answer = String::new();
    if io::stdin().read_line(&mut answer).is_err() || !confirmation_accepted(&answer) {
        eprintln!("Lifecycle action cancelled.");
        return ExitCode::SUCCESS;
    }
    let fresh_operational = match operational_instance(instance_name) {
        Ok(fresh) => fresh,
        Err(error) => {
            eprintln!("pre-mutation instance revalidation failed: {error}");
            return ExitCode::from(1);
        }
    };
    if fresh_operational.profile != operational.profile
        || fresh_operational.index != operational.index
        || fresh_operational.manifests != operational.manifests
        || fresh_operational.active != operational.active
    {
        eprintln!("profile or durable state changed before lifecycle action; action denied");
        return ExitCode::from(1);
    }
    let mut backend = match forge_libvirt::LibvirtBootBackend::connect_instance(
        fresh_operational.instance.clone(),
    ) {
        Ok(backend) => backend,
        Err(error) => {
            eprintln!("libvirt connection failed: {error}");
            return ExitCode::from(1);
        }
    };
    let fresh = match backend.inspect_managed_lifecycle(&fresh_operational.active) {
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
        || forge_provisioning::plan_instance_lifecycle(
            &fresh,
            &fresh_operational.profile,
            true,
            action,
        )
        .is_err()
    {
        eprintln!("pre-mutation lifecycle state changed; action denied");
        return ExitCode::from(1);
    }
    let result = match action {
        forge_provisioning::LifecycleAction::Start => {
            execute_lifecycle_start(&mut backend, &fresh_operational.profile.first_boot_success)
        }
        forge_provisioning::LifecycleAction::Shutdown => {
            forge_provisioning::execute_graceful_shutdown(
                &mut backend,
                Duration::from_secs(plan.timeout_seconds),
            )
            .map(|_| ())
        }
        forge_provisioning::LifecycleAction::ForceStop => forge_provisioning::execute_force_stop(
            &mut backend,
            &fresh.domain_uuid,
            Duration::from_secs(plan.timeout_seconds),
        ),
    };
    match result {
        Ok(()) => {
            if action == forge_provisioning::LifecycleAction::ForceStop {
                let post = match operational_instance(instance_name) {
                    Ok(post) => post,
                    Err(error) => {
                        eprintln!(
                            "force-stop completed but durable state revalidation failed: {error}"
                        );
                        return ExitCode::from(1);
                    }
                };
                if post.profile != fresh_operational.profile
                    || post.index != fresh_operational.index
                    || post.manifests != fresh_operational.manifests
                    || post.active != fresh_operational.active
                {
                    eprintln!(
                        "force-stop completed but durable state or generation ownership changed"
                    );
                    return ExitCode::from(1);
                }
                let post_status = match discover_lifecycle_status(&post) {
                    Ok(status) => status,
                    Err(error) => {
                        eprintln!("force-stop completed but final reconciliation failed: {error}");
                        return ExitCode::from(1);
                    }
                };
                if post_status.domain_state != forge_core::VmState::Shutoff
                    || post_status.domain_uuid != fresh.domain_uuid
                    || post_status.active_overlay_path != fresh.active_overlay_path
                    || post_status.active_backing_path != fresh.active_backing_path
                    || post_status.active_seed_path != fresh.active_seed_path
                {
                    eprintln!("force-stop completed but final exact state verification failed");
                    return ExitCode::from(1);
                }
                println!("Post-force reconciliation: Consistent");
                println!(
                    "WARNING: force-stop was equivalent to cutting VM power; the guest filesystem may be unclean."
                );
            }
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
    policy: &forge_core::FirstBootSuccessPolicy,
) -> Result<(), forge_provisioning::ProvisioningError> {
    let timeouts = forge_provisioning::BootTimeouts::default();
    let key = env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_default()
        .join(".ssh/forge_ed25519");
    match forge_provisioning::execute_runtime_start(
        backend,
        policy,
        key.to_string_lossy().as_ref(),
        timeouts,
    )? {
        forge_provisioning::RuntimeStartResult::ManualGuest { domain } => {
            println!("DomainBootStatus: {domain:?}");
            println!("Guest observability: skipped by ManualGuest policy");
        }
        forge_provisioning::RuntimeStartResult::CloudInitManaged(result) => {
            println!("DomainBootStatus: {:?}", result.domain);
            println!("GuestAgentStatus: {:?}", result.guest_agent);
            println!("DhcpLeaseStatus: {:?}", result.dhcp_lease);
            println!("SshStatus: {:?}", result.ssh);
            println!("CloudInitStatus: {:?}", result.cloud_init);
        }
    }
    Ok(())
}

fn print_lifecycle_status(
    instance_name: &str,
    status: &forge_provisioning::InstanceLifecycleStatus,
) {
    println!("Domain: {instance_name}");
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

#[allow(clippy::too_many_lines)]
fn managed_rebuild(dry_run: bool) -> ExitCode {
    let layout = match managed_state_layout() {
        Ok(value) => value,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(1);
        }
    };
    let state = match forge_state::inspect_layout(&layout) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("managed state failed closed: {error}");
            return ExitCode::from(1);
        }
    };
    let (index, legacy, migration) = match state {
        forge_state::ManagedState::Legacy(manifest) => {
            let migration = match forge_state::plan_migration(&layout, &manifest) {
                Ok(value) => value,
                Err(error) => {
                    eprintln!("migration planning failed: {error}");
                    return ExitCode::from(1);
                }
            };
            (migration.index.clone(), Some(manifest), Some(migration))
        }
        forge_state::ManagedState::Current(index) => (index, None, None),
        forge_state::ManagedState::Missing => {
            eprintln!("managed rebuild refused: active ownership manifest is missing");
            return ExitCode::from(1);
        }
        forge_state::ManagedState::Conflict(reason) => {
            eprintln!("managed rebuild refused: {reason}");
            return ExitCode::from(1);
        }
    };
    let current = match discover_state() {
        Ok(value) => value,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(1);
        }
    };
    let manifests = if let Some(manifest) = legacy.clone() {
        vec![manifest]
    } else {
        match load_index_manifests(&layout, &index) {
            Ok(manifests) => manifests,
            Err(error) => {
                eprintln!("managed rebuild refused: {error}");
                return ExitCode::from(1);
            }
        }
    };
    let managed_reconciliation = forge_state::reconcile_managed(&index, &manifests, &current);
    if managed_reconciliation.status != forge_state::ManagedReconciliationStatus::Consistent {
        eprintln!(
            "managed rebuild refused: {:?}: {}",
            managed_reconciliation.status, managed_reconciliation.detail
        );
        return ExitCode::from(1);
    }
    let generation_id = forge_state::new_generation_id();
    let (plan, seed, managed_plan) = match build_managed_rebuild_plan(&index, generation_id) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("managed rebuild planning failed: {error}");
            return ExitCode::from(1);
        }
    };
    println!(
        "Managed rebuild mode: {}",
        if dry_run {
            "dry-run (zero mutation)"
        } else {
            "real"
        }
    );
    println!(
        "State layout: {}/{{index.json,generations/<generation-id>.json}}",
        layout.domain_directory.display()
    );
    if let Some(migration) = &migration {
        println!(
            "Legacy state migration planned: {} -> {} + {} (legacy source preserved)",
            migration.source.display(),
            migration.generation_manifest.display(),
            migration.index_path.display()
        );
    }
    println!(
        "Current Active generation: {}",
        managed_plan.current_generation_id
    );
    println!("Planned generation ID: {}", managed_plan.generation_id);
    println!("Initial durable status: {:?}", managed_plan.initial_status);
    println!("New overlay: {}", managed_plan.overlay_path);
    println!("New seed: {}", managed_plan.seed_path);
    println!("Shared base: {}", plan.environment.base_path);
    println!("Managed lifecycle:");
    for (i, step) in managed_plan.steps.iter().enumerate() {
        println!("{}. {step}", i + 1);
    }
    println!("Recovery boundaries:");
    for item in &managed_plan.recovery_boundaries {
        println!("- {item}");
    }
    println!("Planned domain XML:");
    print!("{}", plan.domain_xml);
    if dry_run {
        return ExitCode::SUCCESS;
    }
    eprint!("Rebuild Fedora-Lab as a new managed generation? [y/N] ");
    let mut answer = String::new();
    if io::stdin().read_line(&mut answer).is_err()
        || !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
    {
        eprintln!("Managed rebuild cancelled.");
        return ExitCode::SUCCESS;
    }
    let mut index = if let Some(manifest) = legacy.as_ref() {
        match forge_state::execute_migration(&layout, manifest) {
            Ok(value) => value,
            Err(error) => {
                eprintln!("state migration failed before resource creation: {error}");
                return ExitCode::from(1);
            }
        }
    } else {
        index
    };
    let mut backend = match forge_libvirt::LibvirtBootBackend::connect_local() {
        Ok(value) => value,
        Err(error) => {
            eprintln!("libvirt connection failed: {error}");
            return ExitCode::from(1);
        }
    };
    let mut context = forge_provisioning::RebuildContext {
        overlay_name: Some(managed_plan.overlay_name.clone()),
        seed_name: Some(managed_plan.seed_name.clone()),
        ..Default::default()
    };
    let before_switch = (|| -> Result<forge_state::GenerationManifest, String> {
        backend
            .create_rebuild_overlay(&plan)
            .map_err(|e| e.to_string())?;
        context.overlay_created = true;
        backend.create_seed(&seed).map_err(|e| e.to_string())?;
        context.seed_created = true;
        backend
            .validate_rebuild_seed(&plan)
            .map_err(|e| e.to_string())?;
        let observed = backend
            .inspect_generation_paths(&plan.new_overlay_path, &plan.new_seed_path)
            .map_err(|e| e.to_string())?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs();
        let manifest = forge_state::manifest_from_observed(
            &observed,
            managed_plan.generation_id.clone(),
            forge_state::GenerationStatus::Preparing,
            now,
        );
        if forge_state::reconcile_preparing(&manifest, &observed).status
            != forge_state::ReconciliationStatus::Consistent
        {
            return Err("Preparing generation reconciliation failed".into());
        }
        forge_state::write_manifest_atomic(
            &layout.generation_path(&manifest.generation_id),
            &manifest,
        )
        .map_err(|e| e.to_string())?;
        index = forge_state::add_preparing(&index, &manifest).map_err(|e| e.to_string())?;
        forge_state::write_index_atomic(&layout.index, &index).map_err(|e| e.to_string())?;
        Ok(manifest)
    })();
    let _preparing = match before_switch {
        Ok(value) => value,
        Err(primary) => {
            let rollback = backend.rollback_new_resources(&context);
            eprintln!("managed rebuild failed before switch: {primary}; rollback: {rollback:?}");
            return ExitCode::from(1);
        }
    };
    if let Err(error) = backend
        .shutdown_and_wait(Duration::from_secs(120))
        .and_then(|_| backend.verify_pre_switch(&plan.environment))
    {
        let rollback = backend.rollback_new_resources(&context);
        if rollback.is_empty()
            && let Ok(failed) = forge_state::mark_failed(&index, &managed_plan.generation_id)
            && forge_state::write_index_atomic(&layout.index, &failed).is_ok()
        {
            eprintln!(
                "managed rebuild failed before switch: {error}; new resources rolled back and generation marked Failed"
            );
        } else {
            eprintln!(
                "managed rebuild failed before switch: {error}; recovery required, rollback={rollback:?}"
            );
        }
        return ExitCode::from(1);
    }
    if let Err(error) = backend.switch_and_verify(&plan) {
        eprintln!(
            "domain switch did not verify unambiguously; both generations remain owned for recovery: {error}"
        );
        return ExitCode::from(1);
    }
    context.domain_switched = true;
    let boot = (|| {
        backend.start()?;
        backend.wait_running(Duration::from_secs(
            plan.first_boot_timeouts.domain_running_seconds,
        ))?;
        let ip = backend.discover_ip(Duration::from_secs(
            plan.first_boot_timeouts.dhcp_lease_seconds,
        ))?;
        let qga = backend.wait_guest_agent(Duration::from_secs(
            plan.first_boot_timeouts.guest_agent_seconds,
        ))?;
        let ssh = if let Some(ip) = ip.as_deref() {
            backend.observe_ssh(
                ip,
                plan.public_key_path.trim_end_matches(".pub"),
                Duration::from_secs(plan.first_boot_timeouts.ssh_seconds),
            )?
        } else {
            forge_provisioning::SshObservation {
                status: forge_provisioning::SshStatus::TimedOut {
                    after_seconds: plan.first_boot_timeouts.dhcp_lease_seconds,
                },
                cloud_init: forge_provisioning::CloudInitStatus::Unknown,
                forge_user_confirmed: false,
                hostname: None,
            }
        };
        Ok::<_, forge_provisioning::ProvisioningError>((ip, qga, ssh))
    })();
    let (ip, qga, ssh) = match boot {
        Ok(value) => value,
        Err(error) => {
            eprintln!(
                "new generation is switched but first boot failed; recovery required and old generation remains owned: {error}"
            );
            return ExitCode::from(1);
        }
    };
    if !matches!(qga, forge_provisioning::GuestAgentStatus::Available)
        || !matches!(ssh.status, forge_provisioning::SshStatus::Authenticated)
        || !matches!(ssh.cloud_init, forge_provisioning::CloudInitStatus::Done)
        || !ssh.forge_user_confirmed
        || ssh.hostname.as_deref() != Some("fedora-lab")
    {
        eprintln!(
            "first boot was not fully confirmed; state remains recovery-safe with previous Active and new Preparing"
        );
        return ExitCode::from(1);
    }
    index = match forge_state::finalize_switch(&index, &managed_plan.generation_id) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("boot succeeded but final state transition requires recovery: {error}");
            return ExitCode::from(1);
        }
    };
    if let Err(error) = forge_state::write_index_atomic(&layout.index, &index) {
        eprintln!("boot succeeded but atomic final state write requires recovery: {error}");
        return ExitCode::from(1);
    }
    println!(
        "Managed generation {} is Active; previous generation is Retained; IP={}",
        managed_plan.generation_id,
        ip.as_deref().unwrap_or("none")
    );
    ExitCode::SUCCESS
}

fn build_managed_rebuild_plan(
    index: &forge_state::GenerationIndex,
    generation_id: String,
) -> Result<
    (
        forge_provisioning::RebuildPlan,
        forge_provisioning::SeedPlan,
        forge_state::ManagedRebuildPlan,
    ),
    String,
> {
    let Some(home) = env::var_os("HOME") else {
        return Err("HOME is unavailable".into());
    };
    let home = std::path::PathBuf::from(home);
    let key_path = home.join(forge_provisioning::FORGE_PUBLIC_KEY_PATH);
    let public_key = std::fs::read_to_string(&key_path).map_err(|e| e.to_string())?;
    let cloud = forge_provisioning::cloud_init(&public_key).map_err(|e| e.to_string())?;
    let dirs = forge_images::default_directories()
        .ok_or_else(|| "cannot determine image directories".to_owned())?;
    let source = forge_images::verified_fedora(&dirs).map_err(|e| e.to_string())?;
    let profile = forge_profiles::find("fedora-lab").ok_or_else(|| "profile missing".to_owned())?;
    let hardware = forge_hardware::collect().map_err(|e| e.to_string())?;
    let resources = forge_profiles::plan(&hardware, &profile).map_err(|e| e.to_string())?;
    let backend = forge_libvirt::LibvirtBootBackend::connect_local().map_err(|e| e.to_string())?;
    let env = backend.inspect_rebuild().map_err(|e| e.to_string())?;
    let managed = forge_state::plan_managed_rebuild(index, &env.pool_path, generation_id)
        .map_err(|e| e.to_string())?;
    let mut spec = forge_domain::fedora_lab_spec(
        &profile,
        &resources,
        forge_domain::DomainMetadata {
            name: "fedora-lab".into(),
            disk_path: managed.overlay_path.clone(),
        },
    )
    .map_err(|e| e.to_string())?;
    spec.uuid = Some(env.domain_uuid.clone());
    let xml = forge_domain::render_xml(&spec).map_err(|e| e.to_string())?;
    let xml =
        forge_provisioning::attach_seed(&xml, &managed.seed_path).map_err(|e| e.to_string())?;
    let plan = forge_provisioning::plan_rebuild_named(
        &env,
        &source.local_path.display().to_string(),
        &key_path.display().to_string(),
        resources.disk_bytes,
        cloud.content_sha256.clone(),
        xml,
        &managed.overlay_name,
        &managed.seed_name,
    )
    .map_err(|e| e.to_string())?;
    let seed = forge_provisioning::SeedPlan {
        volume_name: managed.seed_name.clone(),
        volume_path: managed.seed_path.clone(),
        create: true,
        data: cloud,
    };
    Ok((plan, seed, managed))
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

fn recover_whonix_workstation(dry_run: bool) -> ExitCode {
    let Ok(directories) = image_directories() else {
        return ExitCode::from(2);
    };
    let plan = match forge_images::plan_whonix_workstation_recovery(&directories) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("Workstation preparation recovery refused: {error}");
            return ExitCode::from(1);
        }
    };
    println!("State: Preparing (pre-publication)");
    println!("Intent: {}", plan.intent_path.display());
    println!(
        "Controlled extraction root: {}",
        plan.extraction_root.display()
    );
    println!(
        "Extracted Workstation artifact: {}",
        plan.extracted_workstation_path.display()
    );
    println!("Prepared destination: absent");
    println!("Published metadata: absent");
    println!(
        "Recovery mutation: remove exact controlled root, sync downloads, remove intent, sync images"
    );
    if dry_run {
        println!("Mode: recovery dry-run (zero mutation)");
        return ExitCode::SUCCESS;
    }
    eprint!("Execute exact Workstation preparation cleanup? [y/N] ");
    let mut answer = String::new();
    if io::stdin().read_line(&mut answer).is_err()
        || !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
    {
        eprintln!("Recovery cancelled.");
        return ExitCode::SUCCESS;
    }
    match forge_images::execute_whonix_workstation_recovery(&directories, &plan) {
        Ok(()) => {
            println!("Workstation preparation state: Missing");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Workstation preparation recovery failed: {error}");
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
    println!("Network: {}", plan.spec.network_interfaces[0]);
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

fn show_profile(profile_name: &str) -> ExitCode {
    let Some(profile) = forge_profiles::find(profile_name) else {
        eprintln!("unknown VM profile: {profile_name}");
        return ExitCode::from(2);
    };
    println!("Profile ID: {}", profile.id);
    println!("Display name: {}", profile.display_name);
    println!("Guest family: {}", profile.guest_family);
    println!("Instance kind: {:?}", profile.instance_kind);
    println!("Architecture: {:?}", profile.architecture);
    println!("Firmware/machine: {:?}", profile.firmware_machine);
    println!(
        "Disk capacity: {} GiB",
        profile.resources.disk_bytes / 1024 / 1024 / 1024
    );
    println!("Image source: {:?}", profile.image_source);
    println!("Image verification: {:?}", profile.image_verification);
    println!("Provisioning: {:?}", profile.provisioning);
    println!("First-boot success: {:?}", profile.first_boot_success);
    println!("Network: {:?}", profile.network_policy);
    println!("Graphics: {:?}", profile.graphics_policy);
    println!("Persistence: {:?}", profile.persistence);
    ExitCode::SUCCESS
}

fn plan_instance(profile_name: &str, instance_name: &str) -> ExitCode {
    let Some(profile) = forge_profiles::find(profile_name) else {
        eprintln!("unknown VM profile: {profile_name}");
        return ExitCode::from(2);
    };
    let instance = match InstanceName::new(instance_name) {
        Ok(instance) => instance,
        Err(error) => {
            eprintln!("invalid instance name: {error}");
            return ExitCode::from(2);
        }
    };
    let hardware = match forge_hardware::collect() {
        Ok(hardware) => hardware,
        Err(error) => {
            eprintln!("hardware detection failed: {error}");
            return ExitCode::from(2);
        }
    };
    let identity = forge_profiles::InstanceIdentity {
        name: instance,
        profile_id: ProfileId::new(profile_name).expect("registry profile ID is valid"),
    };
    let plan = match forge_profiles::plan_instance(&hardware, &profile, identity) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("cannot plan instance: {error}");
            return ExitCode::from(1);
        }
    };
    let disk_path = format!(
        "/var/lib/libvirt/images/{}",
        plan.storage.overlay_volume_name
    );
    let domain = match forge_domain::profile_spec(
        &profile,
        &plan.resources,
        forge_domain::DomainMetadata {
            name: plan.identity.name.to_string(),
            disk_path,
        },
    ) {
        Ok(domain) => domain,
        Err(error) => {
            eprintln!("cannot build domain plan: {error}");
            return ExitCode::from(1);
        }
    };
    println!("Mode: plan (zero mutation)");
    println!("Profile: {}", plan.identity.profile_id);
    println!("Instance: {}", plan.identity.name);
    println!(
        "Resource plan: {} vCPU, {} MiB start / {} MiB max, {} GiB disk",
        plan.resources.vcpus,
        plan.resources.memory_start_bytes / 1024 / 1024,
        plan.resources.memory_max_bytes / 1024 / 1024,
        plan.resources.disk_bytes / 1024 / 1024 / 1024,
    );
    println!(
        "Image plan: {:?}, verification {:?}, base {}",
        plan.image.source, plan.image.verification, plan.image.base_volume_name
    );
    println!(
        "Domain plan: {} ({:?}, {:?})",
        domain.name, domain.firmware, domain.machine
    );
    println!(
        "Storage plan: overlay {}, seed {}",
        plan.storage.overlay_volume_name,
        plan.storage.seed_volume_name.as_deref().unwrap_or("none")
    );
    println!("Provisioning plan: {:?}", plan.provisioning);
    println!("Network plan: {:?}", plan.network);
    println!("Lifecycle/state plan: {:?}", plan.lifecycle);
    ExitCode::SUCCESS
}

#[allow(clippy::too_many_lines)]
fn create_vm_dry_run(profile_name: &str, instance_name: &str) -> ExitCode {
    let Some(profile) = forge_profiles::find(profile_name) else {
        eprintln!("unknown VM profile: {profile_name}");
        return ExitCode::from(2);
    };
    let instance = match InstanceName::new(instance_name) {
        Ok(instance) => instance,
        Err(error) => {
            eprintln!("invalid instance name: {error}");
            return ExitCode::from(2);
        }
    };
    let hardware = match forge_hardware::collect() {
        Ok(hardware) => hardware,
        Err(error) => {
            eprintln!("hardware detection failed: {error}");
            return ExitCode::from(2);
        }
    };
    let identity = forge_profiles::InstanceIdentity {
        name: instance.clone(),
        profile_id: profile.id.clone(),
    };
    let instance_plan = match forge_profiles::plan_instance(&hardware, &profile, identity) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("cannot plan instance creation: {error}");
            return ExitCode::from(1);
        }
    };
    if matches!(
        instance_plan.lifecycle,
        forge_profiles::LifecyclePlan::DisposableUnimplemented
    ) {
        eprintln!("refusing create: disposable lifecycle is explicitly unimplemented");
        return ExitCode::from(1);
    }
    let generation_id = forge_state::new_generation_id();
    let needs_seed = matches!(
        profile.provisioning,
        forge_core::ProvisioningPolicy::NoCloud { .. }
    );
    let generation =
        match forge_state::plan_generation_resources(&instance, generation_id, needs_seed) {
            Ok(plan) => plan,
            Err(error) => {
                eprintln!("cannot plan generation resources: {error}");
                return ExitCode::from(1);
            }
        };
    let plan = match forge_profiles::plan_create(instance_plan, generation) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("cannot assemble creation plan: {error}");
            return ExitCode::from(1);
        }
    };
    let disk_path = format!("/var/lib/libvirt/images/{}", plan.generation.overlay);
    let domain = match forge_domain::profile_spec(
        &profile,
        &plan.instance.resources,
        forge_domain::DomainMetadata {
            name: instance.to_string(),
            disk_path,
        },
    ) {
        Ok(domain) => domain,
        Err(error) => {
            eprintln!("cannot build domain creation plan: {error}");
            return ExitCode::from(1);
        }
    };
    if profile.kind == forge_core::GuestProfileKind::WhonixWorkstation {
        let evidence = match workstation_pair_evidence() {
            Ok(evidence) => evidence,
            Err(error) => {
                eprintln!("Whonix pair planning refused: {error}");
                return ExitCode::from(1);
            }
        };
        let forge_core::NetworkPolicy::WhonixWorkstation(workstation_link) =
            &profile.network_policy
        else {
            unreachable!()
        };
        if let Err(error) = forge_profiles::validate_whonix_pair(
            &evidence,
            workstation_link,
            &evidence.bundle_identity,
        ) {
            eprintln!("Whonix pair planning refused: {error}");
            return ExitCode::from(1);
        }
        println!(
            "Pair: Gateway {} generation {}, domain UUID {}, pair ID {}, endpoint 127.0.0.1:{} -> 127.0.0.1:{}",
            evidence.gateway_instance,
            evidence.gateway_generation,
            evidence.gateway_domain_uuid,
            evidence.gateway_link.pair_id,
            evidence.gateway_link.local_port,
            evidence.gateway_link.remote_port
        );
        println!("Shared bundle identity: {}", evidence.bundle_identity);
        println!("Prepared base role: WorkstationDisk (same verified bundle provenance)");
        println!("Workstation endpoint: 127.0.0.1:5577 -> 127.0.0.1:6688");
        println!("Pair validation: exact complementary endpoints");
        println!("Workstation uplink: none (no passt, NAT, bridge, or libvirt network)");
    }
    let shared_base = match resolve_shared_base_dry_run(&plan) {
        Ok(resolution) => resolution,
        Err(error) => {
            eprintln!("shared-base dry-run classification refused: {error}");
            return ExitCode::from(1);
        }
    };
    print_create_plan(&plan, &domain, &shared_base);
    ExitCode::SUCCESS
}

fn workstation_pair_evidence() -> Result<forge_profiles::WhonixPairEvidence, String> {
    let gateway = forge_profiles::whonix_gateway();
    let layout = managed_state_layout_for(&InstanceName::new("whonix-gateway").unwrap())?;
    let forge_state::ManagedState::Current(index) =
        forge_state::inspect_layout(&layout).map_err(|error| error.to_string())?
    else {
        return Err("matching Gateway durable state is absent".to_owned());
    };
    let manifests = load_index_manifests(&layout, &index)?;
    let active = active_manifest(&index, &manifests)?;
    let backend = forge_libvirt::LibvirtBootBackend::connect_instance(
        InstanceName::new("whonix-gateway").unwrap(),
    )
    .map_err(|error| error.to_string())?;
    let observed = backend
        .inspect_managed_state(active)
        .map_err(|error| error.to_string())?;
    let reconciliation = forge_state::reconcile_managed(&index, &manifests, &observed);
    if reconciliation.status != forge_state::ManagedReconciliationStatus::Consistent {
        return Err(format!(
            "Gateway reconciliation is {:?}",
            reconciliation.status
        ));
    }
    let xml = backend
        .inspect_domain_xml()
        .map_err(|error| error.to_string())?;
    let gateway_domain_uuid = xml
        .split_once("<uuid>")
        .and_then(|(_, rest)| rest.split_once("</uuid>"))
        .map(|(uuid, _)| uuid.trim().to_owned())
        .filter(|uuid| !uuid.is_empty())
        .ok_or_else(|| "Gateway domain XML has no UUID".to_owned())?;
    if xml.matches("<interface ").count() != 2
        || !xml.contains("<interface type='user'>")
        || !xml.contains("<backend type='passt'/>")
        || !xml.contains("<interface type='udp'>")
        || !xml.contains("<source address='127.0.0.1' port='5577'>")
        || !xml.contains("<local address='127.0.0.1' port='6688'/>")
        || xml.contains("source network='default'")
        || xml.contains("<interface type='bridge'>")
    {
        return Err("Gateway domain topology is not the exact expected pair endpoint".to_owned());
    }
    let forge_core::NetworkPolicy::WhonixGateway(gateway_link) = gateway.network_policy else {
        unreachable!()
    };
    let directories = forge_images::default_directories()
        .ok_or_else(|| "Forge image directories are unavailable".to_owned())?;
    let metadata = forge_images::read_whonix_verified_metadata(&directories)
        .map_err(|error| error.to_string())?;
    Ok(forge_profiles::WhonixPairEvidence {
        gateway_instance: InstanceName::new("whonix-gateway").unwrap(),
        gateway_generation: index.active_generation_id,
        gateway_domain_uuid,
        gateway_link,
        bundle_identity: metadata.provenance.bundle_identity_sha256,
    })
}

fn workstation_pair_snapshot(
    factory: &forge_profiles::GenericCreatePlan,
) -> Result<forge_profiles::WhonixPairSnapshot, String> {
    let evidence = workstation_pair_evidence()?;
    let forge_core::NetworkPolicy::WhonixWorkstation(workstation_link) = &factory.instance.network
    else {
        return Err("Workstation plan lost its typed UDP-only network policy".to_owned());
    };
    forge_profiles::validate_whonix_pair(&evidence, workstation_link, &evidence.bundle_identity)
        .map_err(|error| error.to_string())?;
    let directories = forge_images::default_directories()
        .ok_or_else(|| "Forge image directories are unavailable".to_owned())?;
    let metadata = forge_images::read_whonix_verified_metadata(&directories)
        .map_err(|error| error.to_string())?;
    let workstation_base_digest = forge_images::whonix_artifact_digest(
        &metadata.provenance,
        forge_images::BundleArtifactRole::WorkstationDisk,
    )
    .map_err(|error| error.to_string())?;
    Ok(forge_profiles::WhonixPairSnapshot {
        gateway: evidence,
        workstation_overlay: factory.generation.overlay.clone(),
        workstation_base_digest,
    })
}

fn require_workstation_targets_absent(
    factory: &forge_profiles::GenericCreatePlan,
) -> Result<(), String> {
    use forge_storage::{DefineBackend, ImagePrepareBackend};
    let instance = &factory.instance.identity.name;
    let layout = managed_state_layout_for(instance)?;
    if !matches!(
        forge_state::inspect_layout(&layout).map_err(|error| error.to_string())?,
        forge_state::ManagedState::Missing
    ) {
        return Err("Workstation durable target identity already exists".to_owned());
    }
    let mut backend =
        forge_libvirt::LibvirtDefineBackend::connect_local().map_err(|error| error.to_string())?;
    if DefineBackend::domain_exists(&mut backend, instance.as_str())
        .map_err(|error| error.to_string())?
    {
        return Err("Workstation domain target identity already exists".to_owned());
    }
    for volume in [factory.generation.overlay.as_str()] {
        if ImagePrepareBackend::inspect_volume(&mut backend, forge_storage::DEFAULT_POOL, volume)
            .map_err(|error| error.to_string())?
            .is_some()
        {
            return Err(format!(
                "Workstation volume target identity already exists: {volume}"
            ));
        }
    }
    Ok(())
}

fn print_create_plan(
    plan: &forge_profiles::GenericCreatePlan,
    domain: &forge_domain::DomainSpec,
    shared_base: &SharedBaseDryRunResolution,
) {
    println!("Mode: create dry-run (zero mutation)");
    println!("Profile: {}", plan.instance.identity.profile_id);
    println!("Instance identity: {}", plan.instance.identity.name);
    println!(
        "Generation identity plan: {}",
        plan.generation.generation_id
    );
    println!(
        "Image plan: source {:?}, verification {:?}, format {:?}, prepared base {}",
        plan.prepared_base.source,
        plan.prepared_base.verification,
        plan.prepared_base.source_format,
        plan.prepared_base.base_volume_name
    );
    println!(
        "Prepared base semantics: prove and reuse an exact existing trusted base; otherwise prepare it when absent"
    );
    println!("Prepared base ownership: shared, protected, reusable");
    print!("{}", format_shared_base_resolution(shared_base));
    if matches!(
        plan.prepared_base.source,
        forge_core::ImageSourcePolicy::WhonixLibvirtBundle { .. }
    ) {
        println!("Bundle: {}", forge_images::WHONIX_ARCHIVE_FILENAME);
        println!("Bundle source: {}", forge_images::WHONIX_SOURCE_URL);
        println!(
            "Verification chain: detached OpenPGP, pinned signer {}, exact file@name notation, monotonic signature time",
            forge_images::WHONIX_SIGNING_KEY_FINGERPRINT
        );
        println!("Expected bundle roles:");
        for entry in forge_images::whonix_bundle_layout() {
            println!("  - {:?}: {}", entry.role, entry.path);
        }
    }
    println!(
        "Storage plan: new generation-owned overlay {}, capacity {} GiB",
        plan.generation.overlay,
        plan.instance.resources.disk_bytes / 1024 / 1024 / 1024
    );
    println!(
        "Seed plan: {}",
        plan.generation.seed.as_deref().unwrap_or("none")
    );
    println!(
        "Domain plan: persistent {} ({:?}, {:?})",
        domain.name, domain.firmware, domain.machine
    );
    println!("Provisioning plan: {:?}", plan.instance.provisioning);
    println!("Network plan: {:?}", plan.instance.network);
    for interface in &domain.network_interfaces {
        println!("Network attachment: {interface}");
    }
    println!("Graphics plan: {:?}", plan.instance.graphics);
    println!("Persistence plan: {:?}", plan.instance.lifecycle);
    println!(
        "First-boot success policy: {:?}",
        plan.instance.first_boot_success
    );
    println!("Automatic first boot: {}", plan.auto_boot);
    println!("Required observations: {:?}", plan.observations);
    println!("Initial generation state: {}", plan.initial_state);
    println!("Creation transaction:");
    for step in &plan.steps {
        println!("  - {step}");
    }
    println!(
        "State path: ~/.local/share/forge/state/{}/",
        plan.instance.identity.name
    );
    println!("Mutation: {}", plan.mutation);
}

struct PreparedBaseArtifact {
    path: std::path::PathBuf,
    file_bytes: u64,
    capacity_bytes: u64,
    kali_proof: Option<forge_images::KaliPreparedBaseExecuteProof>,
    whonix_workstation_proof: Option<forge_images::WhonixWorkstationExecuteProof>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SharedBaseConsumerProof {
    consumer: String,
    resource: forge_state::ManagedResource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SharedBaseDryRunResolution {
    disposition: forge_storage::SharedBaseDisposition,
    path: String,
    proof_source: String,
}

fn format_shared_base_resolution(resolution: &SharedBaseDryRunResolution) -> String {
    format!(
        "Shared base disposition: {:?}\nExisting shared base: {}\nReuse proof source: {}\n",
        resolution.disposition, resolution.path, resolution.proof_source
    )
}

fn validate_preparation_strategy(
    plan: &forge_profiles::PreparedBaseImagePlan,
) -> Result<forge_profiles::PrepareBaseStrategy, String> {
    use forge_core::{ImageSourcePolicy, ImageVerificationPolicy};
    use forge_profiles::{PrepareBaseStrategy, SourceImageFormat};
    match (
        &plan.source,
        plan.verification,
        plan.source_format,
        plan.preparation,
    ) {
        (
            ImageSourcePolicy::KaliQemuArchive { .. },
            ImageVerificationPolicy::KaliDetachedSignedSha256Sums,
            SourceImageFormat::SevenZipQcow2Archive,
            PrepareBaseStrategy::SevenZipSingleQcow2,
        ) => Ok(plan.preparation),
        (
            ImageSourcePolicy::WhonixLibvirtBundle { release },
            ImageVerificationPolicy::WhonixDetachedOpenPgp,
            SourceImageFormat::TarXzMultiArtifactBundle,
            PrepareBaseStrategy::WhonixBundleGateway,
        ) if release == forge_images::WHONIX_RELEASE
            && plan.base_volume_name == format!("forge-base-whonix-gateway-{release}.qcow2") =>
        {
            Ok(plan.preparation)
        }
        (
            ImageSourcePolicy::WhonixLibvirtBundle { release },
            ImageVerificationPolicy::WhonixDetachedOpenPgp,
            SourceImageFormat::TarXzMultiArtifactBundle,
            PrepareBaseStrategy::WhonixBundleWorkstation,
        ) if release == forge_images::WHONIX_RELEASE
            && plan.base_volume_name
                == format!("forge-base-whonix-workstation-{release}.qcow2") =>
        {
            Ok(plan.preparation)
        }
        _ => Err("unsupported or incoherent image preparation strategy".to_owned()),
    }
}

fn acquire_prepared_base(
    plan: &forge_profiles::PreparedBaseImagePlan,
) -> Result<PreparedBaseArtifact, String> {
    let started = Instant::now();
    eprintln!("[forge] phase start: prepared-base cryptographic validation");
    let directories = forge_images::default_directories()
        .ok_or_else(|| "Forge image directories are unavailable".to_owned())?;
    let (path, kali_proof, whonix_workstation_proof) = match validate_preparation_strategy(plan)? {
        forge_profiles::PrepareBaseStrategy::SevenZipSingleQcow2 => {
            let (metadata, proof) = forge_images::prepare_kali_for_execute(
                &directories,
                &mut forge_images::SystemArtifactFetcher,
            )
            .map_err(|error| error.to_string())?;
            (metadata.prepared_qcow2_path, Some(proof), None)
        }
        forge_profiles::PrepareBaseStrategy::WhonixBundleGateway => {
            let path = forge_images::fetch_whonix_gateway(
                &directories,
                &mut forge_images::SystemArtifactFetcher,
            )
            .map_err(|error| error.to_string())?
            .prepared_qcow2_path;
            (path, None, None)
        }
        forge_profiles::PrepareBaseStrategy::WhonixBundleWorkstation => {
            let (metadata, proof) = forge_images::prepare_whonix_workstation_for_execute(
                &directories,
                &mut forge_images::SystemArtifactFetcher,
            )
            .map_err(|error| error.to_string())?;
            (metadata.prepared_qcow2_path, None, Some(proof))
        }
        forge_profiles::PrepareBaseStrategy::VerifiedQcow2 => {
            return Err("verified direct-qcow2 real create is not implemented".to_owned());
        }
    };
    let file_bytes = std::fs::metadata(&path)
        .map_err(|error| error.to_string())?
        .len();
    let capacity_bytes =
        forge_images::qcow2_virtual_size(&path).map_err(|error| error.to_string())?;
    let artifact = PreparedBaseArtifact {
        path,
        file_bytes,
        capacity_bytes,
        kali_proof,
        whonix_workstation_proof,
    };
    eprintln!(
        "[forge] phase done: prepared-base cryptographic validation elapsed={:.1}s",
        started.elapsed().as_secs_f64()
    );
    Ok(artifact)
}

fn verified_prepared_base_read_only(
    plan: &forge_profiles::PreparedBaseImagePlan,
) -> Result<PreparedBaseArtifact, String> {
    let directories = forge_images::default_directories()
        .ok_or_else(|| "Forge image directories are unavailable".to_owned())?;
    let path = match validate_preparation_strategy(plan)? {
        forge_profiles::PrepareBaseStrategy::SevenZipSingleQcow2 => {
            forge_images::verified_kali(&directories)
                .map_err(|error| error.to_string())?
                .prepared_qcow2_path
        }
        forge_profiles::PrepareBaseStrategy::WhonixBundleGateway => {
            forge_images::verified_whonix_gateway(&directories)
                .map_err(|error| error.to_string())?
                .prepared_qcow2_path
        }
        forge_profiles::PrepareBaseStrategy::WhonixBundleWorkstation => {
            forge_images::verified_whonix_workstation(&directories)
                .map_err(|error| error.to_string())?
                .prepared_qcow2_path
        }
        forge_profiles::PrepareBaseStrategy::VerifiedQcow2 => {
            return Err("verified direct-qcow2 real create is not implemented".to_owned());
        }
    };
    let file_bytes = std::fs::metadata(&path)
        .map_err(|error| error.to_string())?
        .len();
    let capacity_bytes =
        forge_images::qcow2_virtual_size(&path).map_err(|error| error.to_string())?;
    Ok(PreparedBaseArtifact {
        path,
        file_bytes,
        capacity_bytes,
        kali_proof: None,
        whonix_workstation_proof: None,
    })
}

fn prove_prepared_base(
    plan: &forge_profiles::PreparedBaseImagePlan,
    source: &PreparedBaseArtifact,
) -> Result<(), String> {
    let directories = forge_images::default_directories()
        .ok_or_else(|| "Forge image directories are unavailable".to_owned())?;
    match validate_preparation_strategy(plan)? {
        forge_profiles::PrepareBaseStrategy::SevenZipSingleQcow2 => {
            let proof = source
                .kali_proof
                .as_ref()
                .ok_or_else(|| "Kali execute proof is absent after full validation".to_owned())?;
            forge_images::revalidate_kali_prepared_base_execute_proof(&directories, proof)
                .map(|_| ())
        }
        forge_profiles::PrepareBaseStrategy::WhonixBundleGateway => {
            forge_images::verified_whonix_gateway(&directories).map(|_| ())
        }
        forge_profiles::PrepareBaseStrategy::WhonixBundleWorkstation => {
            let proof = source.whonix_workstation_proof.as_ref().ok_or_else(|| {
                "Workstation execute proof is absent after full validation".to_owned()
            })?;
            forge_images::revalidate_whonix_workstation_execute_proof(&directories, proof)
                .map(|_| ())
        }
        forge_profiles::PrepareBaseStrategy::VerifiedQcow2 => {
            return Err("verified direct-qcow2 real create is not implemented".to_owned());
        }
    }
    .map_err(|error| error.to_string())
}

struct ManualGuestCreateBackend {
    storage: forge_libvirt::LibvirtDefineBackend,
    instance: InstanceName,
    domain_uuid: String,
    source: PreparedBaseArtifact,
    layout: forge_state::StateLayout,
    workstation_pair_snapshot: Option<forge_profiles::WhonixPairSnapshot>,
    base_created: bool,
    overlay_created: bool,
}

fn existing_shared_base_proof(
    target_layout: &forge_state::StateLayout,
    expected_name: &str,
    expected: &forge_storage::OverlayVolume,
) -> Result<SharedBaseConsumerProof, String> {
    let state_root = target_layout
        .domain_directory
        .parent()
        .ok_or_else(|| "managed state root is unavailable".to_owned())?;
    let entries = std::fs::read_dir(state_root).map_err(|error| error.to_string())?;
    let mut proof: Option<SharedBaseConsumerProof> = None;
    for entry in entries {
        let entry = entry.map_err(|error| error.to_string())?;
        if !entry
            .file_type()
            .map_err(|error| error.to_string())?
            .is_dir()
        {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(instance) = InstanceName::new(&name) else {
            continue;
        };
        let layout = forge_state::StateLayout::for_instance(state_root, &instance);
        let forge_state::ManagedState::Current(index) =
            forge_state::inspect_layout(&layout).map_err(|error| error.to_string())?
        else {
            continue;
        };
        let manifests = load_index_manifests(&layout, &index)?;
        let active = active_manifest(&index, &manifests)?;
        let Some(base) = active.resources.iter().find(|resource| {
            resource.role == forge_state::ResourceRole::SharedBase
                && resource.volume_name == expected_name
        }) else {
            continue;
        };
        let backend = forge_libvirt::LibvirtBootBackend::connect_instance(instance)
            .map_err(|error| error.to_string())?;
        let observed = backend
            .inspect_managed_state(active)
            .map_err(|error| error.to_string())?;
        let reconciliation = forge_state::reconcile_managed(&index, &manifests, &observed);
        if reconciliation.status != forge_state::ManagedReconciliationStatus::Consistent {
            return Err(format!(
                "shared base consumer {name} is not consistently reconciled: {}",
                reconciliation.detail
            ));
        }
        if base.path != expected.path
            || base.format != expected.format
            || base.capacity_bytes != expected.capacity_bytes
            || base.backing_path != expected.backing_path
        {
            return Err(format!(
                "existing shared base identity differs from durable consumer {name}"
            ));
        }
        if let Some(previous) = &proof
            && previous.resource != *base
        {
            return Err("managed consumers disagree about shared base identity".to_owned());
        }
        proof = Some(SharedBaseConsumerProof {
            consumer: name,
            resource: base.clone(),
        });
    }
    proof.ok_or_else(|| {
        "existing shared base has no exact Consistent durable managed-consumer proof".to_owned()
    })
}

fn resolve_shared_base_dry_run(
    plan: &forge_profiles::GenericCreatePlan,
) -> Result<SharedBaseDryRunResolution, String> {
    use forge_storage::ImagePrepareBackend;
    let mut storage =
        forge_libvirt::LibvirtDefineBackend::connect_local().map_err(|error| error.to_string())?;
    let pool = ImagePrepareBackend::inspect_pool(&mut storage, forge_storage::DEFAULT_POOL)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "default pool is absent".to_owned())?;
    if !pool.active {
        return Err("default pool is inactive".to_owned());
    }
    let path = format!(
        "{}/{}",
        pool.target_path.trim_end_matches('/'),
        plan.prepared_base.base_volume_name
    );
    let existing = ImagePrepareBackend::inspect_volume(
        &mut storage,
        forge_storage::DEFAULT_POOL,
        &plan.prepared_base.base_volume_name,
    )
    .map_err(|error| error.to_string())?;
    let Some(existing) = existing else {
        let expected = forge_storage::BaseImageVolume {
            name: plan.prepared_base.base_volume_name.clone(),
            path: path.clone(),
            imported_bytes: 0,
            capacity_bytes: 0,
            format: "qcow2".to_owned(),
        };
        let disposition = forge_storage::classify_shared_base(&expected, None, None)?;
        return Ok(SharedBaseDryRunResolution {
            disposition,
            path: format!("{path} (absent)"),
            proof_source: "not required; shared base is absent".to_owned(),
        });
    };
    let source = verified_prepared_base_read_only(&plan.prepared_base)?;
    let expected = forge_storage::BaseImageVolume {
        name: plan.prepared_base.base_volume_name.clone(),
        path: path.clone(),
        imported_bytes: source.file_bytes,
        capacity_bytes: source.capacity_bytes,
        format: "qcow2".to_owned(),
    };
    let layout = managed_state_layout_for(&plan.instance.identity.name)?;
    let proof =
        existing_shared_base_proof(&layout, &plan.prepared_base.base_volume_name, &existing)?;
    let disposition =
        forge_storage::classify_shared_base(&expected, Some(&existing), Some(&proof.resource))?;
    Ok(SharedBaseDryRunResolution {
        disposition,
        path,
        proof_source: format!("durable Consistent Active generation of {}", proof.consumer),
    })
}

impl forge_storage::GenericCreateBackend for ManualGuestCreateBackend {
    fn revalidate_targets(
        &mut self,
        plan: &forge_storage::GenericCreateExecutionPlan,
    ) -> Result<forge_storage::SharedBaseDisposition, String> {
        use forge_storage::{DefineBackend, ImagePrepareBackend};
        let started = Instant::now();
        eprintln!("[forge] phase start: execute boundary revalidation");
        if let Some(planned) = &self.workstation_pair_snapshot {
            let current = workstation_pair_snapshot(&plan.factory)?;
            forge_profiles::revalidate_whonix_snapshot(planned, &current)
                .map_err(|error| error.to_string())?;
        }
        if !matches!(
            forge_state::inspect_layout(&self.layout).map_err(|error| error.to_string())?,
            forge_state::ManagedState::Missing
        ) || DefineBackend::domain_exists(&mut self.storage, self.instance.as_str())
            .map_err(|error| error.to_string())?
            || (matches!(
                plan.factory.instance.network,
                forge_core::NetworkPolicy::DefaultNat
            ) && !self
                .storage
                .default_network_active()
                .map_err(|error| error.to_string())?)
        {
            return Err("domain, state, or default network precondition changed".to_owned());
        }
        let pool =
            ImagePrepareBackend::inspect_pool(&mut self.storage, forge_storage::DEFAULT_POOL)
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "default pool is absent".to_owned())?;
        if !pool.active || pool.available_bytes < plan.factory.instance.resources.disk_bytes {
            return Err("default pool is inactive or lacks required capacity".to_owned());
        }
        if ImagePrepareBackend::inspect_volume(
            &mut self.storage,
            forge_storage::DEFAULT_POOL,
            &plan.factory.generation.overlay,
        )
        .map_err(|error| error.to_string())?
        .is_some()
        {
            return Err(format!(
                "generation-owned overlay already exists: {}",
                plan.factory.generation.overlay
            ));
        }
        prove_prepared_base(&plan.factory.prepared_base, &self.source)?;
        let base = ImagePrepareBackend::inspect_volume(
            &mut self.storage,
            forge_storage::DEFAULT_POOL,
            &plan.factory.prepared_base.base_volume_name,
        )
        .map_err(|error| error.to_string())?;
        let expected = forge_storage::BaseImageVolume {
            name: plan.factory.prepared_base.base_volume_name.clone(),
            path: format!(
                "{}/{}",
                pool.target_path.trim_end_matches('/'),
                plan.factory.prepared_base.base_volume_name
            ),
            imported_bytes: self.source.file_bytes,
            capacity_bytes: self.source.capacity_bytes,
            format: "qcow2".to_owned(),
        };
        let durable = base
            .as_ref()
            .map(|existing| {
                existing_shared_base_proof(
                    &self.layout,
                    &plan.factory.prepared_base.base_volume_name,
                    existing,
                )
            })
            .transpose()?;
        let disposition = forge_storage::classify_shared_base(
            &expected,
            base.as_ref(),
            durable.as_ref().map(|proof| &proof.resource),
        )?;
        eprintln!(
            "[forge] phase done: execute boundary revalidation shared-base={disposition:?} elapsed={:.1}s",
            started.elapsed().as_secs_f64()
        );
        Ok(disposition)
    }

    fn prepare_storage(
        &mut self,
        plan: &forge_storage::GenericCreateExecutionPlan,
        disposition: forge_storage::SharedBaseDisposition,
    ) -> Result<(), String> {
        use forge_storage::ImagePrepareBackend;
        let started = Instant::now();
        eprintln!("[forge] phase start: storage import and overlay creation");
        let pool =
            ImagePrepareBackend::inspect_pool(&mut self.storage, forge_storage::DEFAULT_POOL)
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "default pool is absent".to_owned())?;
        let base_path = format!(
            "{}/{}",
            pool.target_path.trim_end_matches('/'),
            plan.factory.prepared_base.base_volume_name
        );
        let base = forge_storage::BaseImageVolume {
            name: plan.factory.prepared_base.base_volume_name.clone(),
            path: base_path.clone(),
            imported_bytes: self.source.file_bytes,
            capacity_bytes: self.source.capacity_bytes,
            format: "qcow2".to_owned(),
        };
        match disposition {
            forge_storage::SharedBaseDisposition::Prepare => {
                let directories = forge_images::default_directories()
                    .ok_or_else(|| "Forge image directories are unavailable".to_owned())?;
                let pinned_source = if let Some(proof) = self.source.kali_proof.as_ref() {
                    Some(
                        forge_images::open_kali_prepared_base_execute_source(&directories, proof)
                            .map_err(|error| error.to_string())?,
                    )
                } else {
                    self.source
                        .whonix_workstation_proof
                        .as_ref()
                        .map(|proof| {
                            forge_images::open_whonix_workstation_execute_source(
                                &directories,
                                proof,
                            )
                            .map_err(|error| error.to_string())
                        })
                        .transpose()?
                };
                let source_path = pinned_source.as_ref().map_or_else(
                    || self.source.path.to_string_lossy().into_owned(),
                    |file| format!("/proc/self/fd/{}", file.as_raw_fd()),
                );
                ImagePrepareBackend::import_base(
                    &mut self.storage,
                    forge_storage::DEFAULT_POOL,
                    &base,
                    &source_path,
                )
                .map_err(|error| error.to_string())?;
                self.base_created = true;
            }
            forge_storage::SharedBaseDisposition::ReuseProven => {
                let existing = ImagePrepareBackend::inspect_volume(
                    &mut self.storage,
                    forge_storage::DEFAULT_POOL,
                    &base.name,
                )
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "proven shared base disappeared before reuse".to_owned())?;
                let durable = existing_shared_base_proof(&self.layout, &base.name, &existing)?;
                forge_storage::classify_shared_base(
                    &base,
                    Some(&existing),
                    Some(&durable.resource),
                )?;
            }
        }
        let overlay = forge_storage::OverlayVolume {
            name: plan.factory.generation.overlay.clone(),
            path: format!(
                "{}/{}",
                pool.target_path.trim_end_matches('/'),
                plan.factory.generation.overlay
            ),
            capacity_bytes: plan.factory.instance.resources.disk_bytes,
            allocation_bytes: 0,
            format: "qcow2".to_owned(),
            backing_path: Some(base_path),
        };
        ImagePrepareBackend::create_overlay(
            &mut self.storage,
            forge_storage::DEFAULT_POOL,
            &overlay,
        )
        .map_err(|error| error.to_string())?;
        self.overlay_created = true;
        eprintln!(
            "[forge] phase done: storage import and overlay creation elapsed={:.1}s",
            started.elapsed().as_secs_f64()
        );
        Ok(())
    }

    fn inspect_preparing(
        &mut self,
        plan: &forge_storage::GenericCreateExecutionPlan,
    ) -> Result<forge_state::ObservedGeneration, String> {
        self.storage
            .inspect_preparing_generation(
                &self.instance,
                &self.domain_uuid,
                &plan.factory.generation.overlay,
            )
            .map_err(|error| error.to_string())
    }

    fn persist_preparing(
        &mut self,
        manifest: &forge_state::GenerationManifest,
    ) -> Result<(), String> {
        forge_state::publish_initial_preparing(&self.layout, manifest)
            .map_err(|error| error.to_string())
    }

    fn define_domain(&mut self, domain_xml: &str) -> Result<(), String> {
        let domain = forge_storage::DefineBackend::define_domain(&mut self.storage, domain_xml)
            .map_err(|error| error.error.to_string())?;
        if domain.uuid != self.domain_uuid || domain.state != forge_core::VmState::Shutoff {
            return Err("defined domain identity/state differs from the plan".to_owned());
        }
        Ok(())
    }

    fn inspect_defined(
        &mut self,
        plan: &forge_storage::GenericCreateExecutionPlan,
    ) -> Result<forge_state::ObservedGeneration, String> {
        forge_libvirt::LibvirtBootBackend::connect_instance(self.instance.clone())
            .map_err(|error| error.to_string())?
            .inspect_generation_overlay_only(&format!(
                "/var/lib/libvirt/images/{}",
                plan.factory.generation.overlay
            ))
            .map_err(|error| error.to_string())
    }

    fn activate(
        &mut self,
        manifest: &forge_state::GenerationManifest,
        observed: &forge_state::ObservedGeneration,
    ) -> Result<forge_state::GenerationIndex, String> {
        forge_state::activate_initial_generation(&self.layout, manifest, observed)
            .map_err(|error| error.to_string())
    }

    fn rollback_before_ownership(
        &mut self,
        plan: &forge_storage::GenericCreateExecutionPlan,
    ) -> Result<(), String> {
        let mut failures = Vec::new();
        if self.overlay_created
            && let Err(error) = forge_storage::DefineBackend::delete_volume(
                &mut self.storage,
                forge_storage::DEFAULT_POOL,
                &plan.factory.generation.overlay,
            )
        {
            failures.push(error.to_string());
        }
        if self.base_created
            && let Err(error) = forge_storage::DefineBackend::delete_volume(
                &mut self.storage,
                forge_storage::DEFAULT_POOL,
                &plan.factory.prepared_base.base_volume_name,
            )
        {
            failures.push(error.to_string());
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }
}

fn create_vm(profile_name: &str, instance_name: &str) -> ExitCode {
    if !matches!(
        profile_name,
        "kali-lab" | "whonix-gateway" | "whonix-workstation"
    ) {
        eprintln!("real generic create is unavailable for this profile's image strategy");
        return ExitCode::from(2);
    }
    eprint!("Create persistent ManualGuest {instance_name} from {profile_name}? [y/N] ");
    let mut answer = String::new();
    if io::stdin().read_line(&mut answer).is_err()
        || !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
    {
        eprintln!("Creation cancelled.");
        return ExitCode::SUCCESS;
    }
    match execute_manual_guest_create(profile_name, instance_name) {
        Ok(index) => {
            println!("Active generation: {}", index.active_generation_id);
            println!(
                "Persistent ManualGuest created shut off; use Virt-Manager or forge vm start."
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("ManualGuest create failed: {error}");
            ExitCode::from(1)
        }
    }
}

fn execute_manual_guest_create(
    profile_name: &str,
    instance_name: &str,
) -> Result<forge_state::GenerationIndex, String> {
    let create_started = Instant::now();
    eprintln!("[forge] phase start: total create");
    let profile = forge_profiles::find(profile_name)
        .ok_or_else(|| format!("unknown VM profile: {profile_name}"))?;
    let instance = InstanceName::new(instance_name).map_err(|error| error.to_string())?;
    let hardware = forge_hardware::collect().map_err(|error| error.to_string())?;
    let instance_plan = forge_profiles::plan_instance(
        &hardware,
        &profile,
        forge_profiles::InstanceIdentity {
            name: instance.clone(),
            profile_id: profile.id.clone(),
        },
    )
    .map_err(|error| error.to_string())?;
    let generation_id = forge_state::new_generation_id();
    let generation = forge_state::plan_generation_resources(&instance, generation_id, false)
        .map_err(|error| error.to_string())?;
    let factory = forge_profiles::plan_create(instance_plan, generation)
        .map_err(|error| error.to_string())?;
    let workstation_pair_snapshot =
        if profile.kind == forge_core::GuestProfileKind::WhonixWorkstation {
            let planned = workstation_pair_snapshot(&factory)?;
            require_workstation_targets_absent(&factory)?;
            let current = workstation_pair_snapshot(&factory)?;
            forge_profiles::revalidate_whonix_snapshot(&planned, &current)
                .map_err(|error| error.to_string())?;
            require_workstation_targets_absent(&factory)?;
            Some(planned)
        } else {
            None
        };
    let source = acquire_prepared_base(&factory.prepared_base)?;
    if source.capacity_bytes > factory.instance.resources.disk_bytes {
        return Err("prepared source capacity exceeds the profile disk policy".to_owned());
    }
    let domain_uuid = forge_state::new_generation_id()
        .strip_prefix("gen-")
        .expect("Forge generation IDs have a stable prefix")
        .to_owned();
    let mut domain = forge_domain::profile_spec(
        &profile,
        &factory.instance.resources,
        forge_domain::DomainMetadata {
            name: instance.to_string(),
            disk_path: format!("/var/lib/libvirt/images/{}", factory.generation.overlay),
        },
    )
    .map_err(|error| error.to_string())?;
    domain.uuid = Some(domain_uuid.clone());
    let domain_xml = forge_domain::render_xml(&domain).map_err(|error| error.to_string())?;
    let created_unix_seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_secs();
    let home = env::var_os("HOME").ok_or_else(|| "HOME is unavailable".to_owned())?;
    let layout = forge_state::StateLayout::for_instance(
        &forge_state::state_directory(std::path::Path::new(&home)),
        &instance,
    );
    let mut backend = ManualGuestCreateBackend {
        storage: forge_libvirt::LibvirtDefineBackend::connect_local()
            .map_err(|error| error.to_string())?,
        instance,
        domain_uuid,
        source,
        layout,
        workstation_pair_snapshot,
        base_created: false,
        overlay_created: false,
    };
    let result = forge_storage::execute_generic_create(
        &mut backend,
        &forge_storage::GenericCreateExecutionPlan {
            factory,
            created_unix_seconds,
            domain_xml,
        },
    )
    .map(|result| result.index)
    .map_err(|error| error.to_string());
    eprintln!(
        "[forge] phase done: total create outcome={} elapsed={:.1}s",
        if result.is_ok() { "success" } else { "refused" },
        create_started.elapsed().as_secs_f64()
    );
    result
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
    eprintln!("  forge profile show <profile>");
    eprintln!("  forge profile plan <profile>");
    eprintln!("  forge vm plan <profile> <instance>");
    eprintln!("  forge hypervisor info");
    eprintln!("  forge vm list");
    eprintln!("  forge vm status fedora-lab");
    eprintln!("  forge vm create <profile> <instance> --dry-run");
    eprintln!("  forge vm cleanup fedora-lab --dry-run");
    eprintln!("  forge vm start fedora-lab [--dry-run]");
    eprintln!("  forge vm shutdown fedora-lab [--dry-run]");
    eprintln!("  forge vm stop fedora-lab --force [--dry-run]");
    eprintln!("  forge state show fedora-lab");
    eprintln!("  forge state reconcile fedora-lab");
    eprintln!("  forge state recover fedora-lab [--dry-run]");
    eprintln!("  forge state adopt fedora-lab [--dry-run]");
    eprintln!("  forge vm define fedora-lab [--dry-run]");
    eprintln!("  forge vm prepare fedora-lab [--dry-run]");
    eprintln!("  forge vm boot fedora-lab [--dry-run]");
    eprintln!("  forge vm rebuild fedora-lab [--dry-run]");
    eprintln!("  forge vm rebuild fedora-lab --managed [--dry-run]");
    eprintln!("  forge vm cleanup fedora-lab [--dry-run]");
    eprintln!("  forge domain render fedora-lab");
    eprintln!("  forge image list");
    eprintln!("  forge image inspect fedora");
    eprintln!("  forge image fetch fedora");
    eprintln!("  forge image recover whonix-workstation [--dry-run]");
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
    use forge_core::{ImageSourcePolicy, ImageVerificationPolicy, ProvisioningPolicy, VmState};
    use forge_profiles::{PrepareBaseStrategy, PreparedBaseImagePlan, SourceImageFormat};

    fn prepared_plan(
        source: ImageSourcePolicy,
        verification: ImageVerificationPolicy,
        source_format: SourceImageFormat,
        preparation: PrepareBaseStrategy,
    ) -> PreparedBaseImagePlan {
        PreparedBaseImagePlan {
            source,
            verification,
            source_format,
            preparation,
            base_volume_name: "base.qcow2".to_owned(),
        }
    }

    fn seed() -> forge_state::ManagedResource {
        forge_state::ManagedResource {
            role: forge_state::ResourceRole::NoCloudSeed,
            volume_name: "seed.iso".to_owned(),
            volume_key: "/pool/seed.iso".to_owned(),
            path: "/pool/seed.iso".to_owned(),
            format: "raw".to_owned(),
            capacity_bytes: 4096,
            backing_path: None,
        }
    }

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

    #[test]
    fn provisioning_policy_drives_seed_reconciliation() {
        let no_cloud = ProvisioningPolicy::NoCloud {
            default_user: "forge".to_owned(),
            guest_agent: true,
        };
        assert!(validate_provisioning_topology(&no_cloud, &[]).is_err());
        assert!(validate_provisioning_topology(&no_cloud, &[seed()]).is_ok());
        assert!(validate_provisioning_topology(&ProvisioningPolicy::None, &[]).is_ok());
        assert!(validate_provisioning_topology(&ProvisioningPolicy::None, &[seed()]).is_err());
    }

    #[test]
    fn fedora_profile_still_requires_its_nocloud_seed() {
        let fedora = forge_profiles::find("fedora-lab").unwrap();
        assert!(matches!(
            fedora.provisioning,
            ProvisioningPolicy::NoCloud { .. }
        ));
        assert!(validate_provisioning_topology(&fedora.provisioning, &[seed()]).is_ok());
        assert!(validate_provisioning_topology(&fedora.provisioning, &[]).is_err());
    }

    #[test]
    fn real_create_dispatch_is_policy_driven_for_kali_and_whonix() {
        let kali = prepared_plan(
            ImageSourcePolicy::KaliQemuArchive {
                release: "2026.2".to_owned(),
            },
            ImageVerificationPolicy::KaliDetachedSignedSha256Sums,
            SourceImageFormat::SevenZipQcow2Archive,
            PrepareBaseStrategy::SevenZipSingleQcow2,
        );
        assert_eq!(
            validate_preparation_strategy(&kali).unwrap(),
            PrepareBaseStrategy::SevenZipSingleQcow2
        );
        let mut whonix = prepared_plan(
            ImageSourcePolicy::WhonixLibvirtBundle {
                release: "18.2.1.9".to_owned(),
            },
            ImageVerificationPolicy::WhonixDetachedOpenPgp,
            SourceImageFormat::TarXzMultiArtifactBundle,
            PrepareBaseStrategy::WhonixBundleGateway,
        );
        whonix.base_volume_name = "forge-base-whonix-gateway-18.2.1.9.qcow2".to_owned();
        assert_eq!(
            validate_preparation_strategy(&whonix).unwrap(),
            PrepareBaseStrategy::WhonixBundleGateway
        );
        let mut workstation = whonix.clone();
        workstation.preparation = PrepareBaseStrategy::WhonixBundleWorkstation;
        workstation.base_volume_name = "forge-base-whonix-workstation-18.2.1.9.qcow2".to_owned();
        assert_eq!(
            validate_preparation_strategy(&workstation).unwrap(),
            PrepareBaseStrategy::WhonixBundleWorkstation
        );
        workstation.preparation = PrepareBaseStrategy::WhonixBundleGateway;
        assert!(validate_preparation_strategy(&workstation).is_err());
    }

    #[test]
    fn incoherent_or_unsupported_real_create_strategy_is_refused() {
        let mismatched = prepared_plan(
            ImageSourcePolicy::WhonixLibvirtBundle {
                release: "18.2.1.9".to_owned(),
            },
            ImageVerificationPolicy::WhonixDetachedOpenPgp,
            SourceImageFormat::TarXzMultiArtifactBundle,
            PrepareBaseStrategy::SevenZipSingleQcow2,
        );
        assert!(validate_preparation_strategy(&mismatched).is_err());
        let unsupported = prepared_plan(
            ImageSourcePolicy::VerifiedQcow2 {
                source_id: "mock".to_owned(),
            },
            ImageVerificationPolicy::Sha256Digest,
            SourceImageFormat::Qcow2,
            PrepareBaseStrategy::VerifiedQcow2,
        );
        assert!(validate_preparation_strategy(&unsupported).is_err());
    }

    #[test]
    fn explicit_force_stop_confirmation_is_fail_closed() {
        assert!(!confirmation_accepted(""));
        assert!(!confirmation_accepted("no"));
        assert!(!confirmation_accepted("force"));
        assert!(confirmation_accepted("yes\n"));
    }

    #[test]
    fn dry_run_shared_base_output_exposes_typed_disposition_and_proof() {
        let resolution = SharedBaseDryRunResolution {
            disposition: forge_storage::SharedBaseDisposition::ReuseProven,
            path: "/pool/base.qcow2".to_owned(),
            proof_source: "durable Consistent Active generation of existing-vm".to_owned(),
        };
        assert_eq!(
            format_shared_base_resolution(&resolution),
            "Shared base disposition: ReuseProven\nExisting shared base: /pool/base.qcow2\nReuse proof source: durable Consistent Active generation of existing-vm\n"
        );
        assert!(format_shared_base_resolution(&resolution).contains("ReuseProven"));
    }

    #[test]
    fn independent_instance_resolves_profile_from_unique_durable_shared_base() {
        let generation_id = "gen-test".to_owned();
        let index = forge_state::GenerationIndex {
            schema_version: forge_state::INDEX_SCHEMA_VERSION,
            domain_name: "kali-2".to_owned(),
            domain_uuid: "domain-uuid".to_owned(),
            active_generation_id: generation_id.clone(),
            generations: vec![forge_state::GenerationEntry {
                generation_id: generation_id.clone(),
                status: forge_state::GenerationStatus::Active,
                manifest_file: "generations/gen-test.json".to_owned(),
            }],
            cleanup_progress: vec![],
        };
        let active = forge_state::GenerationManifest {
            schema_version: forge_state::SCHEMA_VERSION,
            domain_name: "kali-2".to_owned(),
            domain_uuid: "domain-uuid".to_owned(),
            generation_id,
            created_unix_seconds: 1,
            libvirt_uri: "qemu:///system".to_owned(),
            storage_pool_name: "default".to_owned(),
            storage_pool_uuid: "pool-uuid".to_owned(),
            status: forge_state::GenerationStatus::Preparing,
            resources: vec![
                forge_state::ManagedResource {
                    role: forge_state::ResourceRole::SharedBase,
                    volume_name: "forge-base-kali-2026.2.qcow2".to_owned(),
                    volume_key: "/pool/base".to_owned(),
                    path: "/pool/base".to_owned(),
                    format: "qcow2".to_owned(),
                    capacity_bytes: 86_000_000_000,
                    backing_path: None,
                },
                forge_state::ManagedResource {
                    role: forge_state::ResourceRole::WritableOverlay,
                    volume_name: "kali-2-gen-test.qcow2".to_owned(),
                    volume_key: "/pool/overlay".to_owned(),
                    path: "/pool/overlay".to_owned(),
                    format: "qcow2".to_owned(),
                    capacity_bytes: 86 * 1024 * 1024 * 1024,
                    backing_path: Some("/pool/base".to_owned()),
                },
            ],
        };
        let profile = validate_profile_binding("kali-2", &index, &active).unwrap();
        assert_eq!(profile.id.as_str(), "kali-lab");
    }
}
