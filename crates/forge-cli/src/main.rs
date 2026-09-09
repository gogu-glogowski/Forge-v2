use forge_core::{
    DoctorReport, DomainSummary, HostState, InstanceName, LibvirtInfo, ProfileId, VmResourcePlan,
};
use forge_images::FedoraWorkstationPreparationBackend;
use forge_provisioning::{BootBackend, RebuildBackend};
use forge_storage::{DefineBackend, ImagePrepareBackend};
use std::env;
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::process::ExitCode;
use std::time::{Duration, Instant};

#[allow(clippy::too_many_lines)]
fn main() -> ExitCode {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    let argument_views = arguments.iter().map(String::as_str).collect::<Vec<_>>();
    if is_help_request(&argument_views) {
        print_usage();
        return ExitCode::SUCCESS;
    }
    if let Some(command) = parse_delete_command(&argument_views) {
        return delete_vm(&command.instance, command.force);
    }
    match argument_views.as_slice() {
        ["doctor"] => match forge_doctor::run() {
            Ok(report) => {
                let storage_ready = print_storage_readiness();
                print_report(&report, storage_ready);
                if matches!(report.state, HostState::Ready | HostState::Degraded) && storage_ready {
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
                let status = match profile.availability {
                    forge_core::ProductAvailability::Supported => "Supported",
                    forge_core::ProductAvailability::LegacyCompatibility(_) => "Retired/Legacy",
                };
                println!("{}\t{}\t{status}", profile.id, profile.display_name);
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
        ["vm", "clone", source, target, "--dry-run"] => clone_vm(source, target, true),
        ["vm", "clone", source, target] => clone_vm(source, target, false),
        ["vm", "fresh", instance, "--dry-run"] => fresh_vm(instance, true),
        ["vm", "fresh", instance] => fresh_vm(instance, false),
        ["hypervisor", "info"] => hypervisor_info(),
        ["vm", "list"] => vm_list(),
        ["vm", "status", instance] => lifecycle_status(instance),
        ["vm", "cleanup", instance, "--dry-run"] => cleanup_vm_dry_run(instance),
        ["vm", "cleanup", instance] => managed_cleanup(instance, false),
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
        ["state", "recover", instance, "--dry-run"] => state_recover(instance, true),
        ["state", "recover", instance] => state_recover(instance, false),
        ["state", "adopt", "fedora-lab", "--dry-run"] => state_adopt(true),
        ["state", "adopt", "fedora-lab"] => state_adopt(false),
        ["vm", "define", "fedora-lab"] => define_vm(false),
        ["vm", "define", "fedora-lab", "--dry-run"] => define_vm(true),
        ["vm", "prepare", "fedora-lab"] => prepare_vm(false),
        ["vm", "prepare", "fedora-lab", "--dry-run"] => prepare_vm(true),
        ["vm", "boot", "fedora-lab"] => boot_vm(false),
        ["vm", "boot", "fedora-lab", "--dry-run"] => boot_vm(true),
        ["vm", "rebuild", instance, "--dry-run"] => rebuild_instance_dry_run(instance),
        ["vm", "rebuild", "fedora-lab"] => rebuild_vm(),
        ["vm", "rebuild", "fedora-lab", "--managed", "--dry-run"] => managed_rebuild(true),
        ["vm", "rebuild", "fedora-lab", "--managed"] => managed_rebuild(false),
        ["domain", "render", profile_name] => render_domain(profile_name),
        ["image", "list"] => image_list(),
        ["image", "inspect", "fedora"] => image_inspect(),
        ["image", "fetch", "fedora"] => image_fetch(),
        ["image", "inspect", "kali"] => image_inspect_kali(),
        ["image", "fetch", "kali"] => image_fetch_kali(),
        ["image", "inspect", "fedora-workstation"] => image_inspect_workstation(),
        ["image", "fetch", "fedora-workstation"] => image_fetch_workstation(),
        ["image", "prepare", "fedora-workstation", "--dry-run"] => {
            image_prepare_workstation_dry_run()
        }
        ["image", "prepare", "fedora-workstation"] => image_prepare_workstation(),
        ["image", "prepare-status", "fedora-workstation"] => image_prepare_workstation_status(),
        ["image", "prepare-start", "fedora-workstation"] => image_prepare_workstation_start(),
        ["image", "prepare-continue", "fedora-workstation"] => image_prepare_workstation_continue(),
        ["image", "prepare-confirm-installed", "fedora-workstation"] => {
            image_prepare_workstation_confirm_installed()
        }
        ["image", "prepare-confirm-graphical", "fedora-workstation"] => {
            image_prepare_workstation_confirm_graphical()
        }
        ["image", "prepare-promote", "fedora-workstation"] => image_prepare_workstation_promote(),
        ["image", "abort", "fedora-workstation", preparation_id] => {
            image_abort_workstation(preparation_id)
        }
        ["image", "recover", "whonix-workstation", "--dry-run"] => recover_whonix_workstation(true),
        ["image", "recover", "whonix-workstation"] => recover_whonix_workstation(false),
        _ => {
            print_usage();
            ExitCode::from(2)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DeleteCommand {
    instance: String,
    force: bool,
}

fn parse_delete_command(arguments: &[&str]) -> Option<DeleteCommand> {
    match arguments {
        ["delete", instance] => Some(DeleteCommand {
            instance: (*instance).to_owned(),
            force: false,
        }),
        ["delete", instance, "--force"] => Some(DeleteCommand {
            instance: (*instance).to_owned(),
            force: true,
        }),
        _ => None,
    }
}

fn is_help_request(arguments: &[&str]) -> bool {
    matches!(arguments, ["--help"] | ["-h"])
}

const LEGACY_FEDORA_RETIRED: &str = "Legacy Fedora Cloud/NoCloud is retired in Forge V2.5. Fedora Workstation support is being introduced through the new Workstation architecture.";

fn require_new_product(profile: &forge_core::VmProfile) -> Result<(), &'static str> {
    match profile.availability {
        forge_core::ProductAvailability::Supported => Ok(()),
        forge_core::ProductAvailability::LegacyCompatibility(
            forge_core::LegacyProductClassification::LegacyFedoraCloudNoCloud,
        ) => Err(LEGACY_FEDORA_RETIRED),
    }
}

fn print_storage_readiness() -> bool {
    let mut backend = match forge_libvirt::LibvirtDefineBackend::connect_local() {
        Ok(backend) => backend,
        Err(error) => {
            println!("Storage pool (default): Unavailable");
            println!("- libvirt connection failed: {error}");
            return false;
        }
    };
    let pool = match DefineBackend::inspect_pool(&mut backend, forge_storage::DEFAULT_POOL) {
        Ok(pool) => pool,
        Err(error) => {
            println!("Storage pool (default): Unavailable");
            println!("- cannot inspect the standard libvirt storage pool: {error}");
            return false;
        }
    };
    let Some(pool) = pool else {
        println!("Storage pool (default): Missing");
        println!(
            "- Forge needs the standard system libvirt pool named 'default' for images and VM disks."
        );
        println!("- Create and activate it with standard libvirt commands:");
        println!(
            "  sudo virsh -c qemu:///system pool-define-as default dir --target /var/lib/libvirt/images"
        );
        println!("  sudo virsh -c qemu:///system pool-start default");
        println!("  sudo virsh -c qemu:///system pool-autostart default");
        println!("- Recheck with: virsh -c qemu:///system pool-info default");
        return false;
    };
    if !pool.active {
        println!("Storage pool (default): Inactive");
        println!("- Start it with: sudo virsh -c qemu:///system pool-start default");
        println!("- Enable it with: sudo virsh -c qemu:///system pool-autostart default");
        return false;
    }
    if pool.target_path.is_empty() || !pool.target_path.starts_with('/') {
        println!("Storage pool (default): Unusable");
        println!("- The pool has no valid absolute target path.");
        return false;
    }
    println!(
        "Storage pool (default): Ready (target {}, available {} GiB)",
        pool.target_path,
        pool.available_bytes / (1024 * 1024 * 1024)
    );
    true
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

fn discover_state_for(instance: &InstanceName) -> Result<forge_state::ObservedGeneration, String> {
    let backend = forge_libvirt::LibvirtBootBackend::connect_instance(instance.clone())
        .map_err(|error| format!("libvirt connection failed: {error}"))?;
    backend
        .inspect_state()
        .map_err(|error| format!("Forge state discovery failed: {error}"))
}

fn discover_state() -> Result<forge_state::ObservedGeneration, String> {
    discover_state_for(
        &InstanceName::new("fedora-lab").expect("compatibility instance name is valid"),
    )
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
        forge_state::ManagedState::InitialCreateRecoveryRequired(manifest) => {
            println!("ManagedReconciliationStatus: InitialCreateRecoveryRequired");
            println!("Preparing generation: {}", manifest.generation_id);
            println!("Recovery: forge state recover {instance_name} --dry-run");
            return ExitCode::from(1);
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
fn state_recover(instance_name: &str, dry_run: bool) -> ExitCode {
    let instance = match InstanceName::new(instance_name) {
        Ok(instance) => instance,
        Err(error) => {
            eprintln!("recovery refused: invalid instance name: {error}");
            return ExitCode::from(2);
        }
    };
    let layout = match managed_state_layout_for(&instance) {
        Ok(layout) => layout,
        Err(error) => {
            eprintln!("recovery refused: {error}");
            return ExitCode::from(1);
        }
    };
    if matches!(
        forge_state::inspect_layout(&layout),
        Ok(forge_state::ManagedState::InitialCreateRecoveryRequired(_))
    ) {
        return recover_initial_create(instance, layout, dry_run);
    }
    if instance_name != "fedora-lab" {
        return fresh_restore_old(instance_name, dry_run);
    }
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

fn recover_initial_create(
    instance: InstanceName,
    layout: forge_state::StateLayout,
    dry_run: bool,
) -> ExitCode {
    let manifest = match forge_state::inspect_layout(&layout) {
        Ok(forge_state::ManagedState::InitialCreateRecoveryRequired(manifest)) => manifest,
        Ok(_) => {
            eprintln!("recovery refused: initial Preparing recovery boundary changed");
            return ExitCode::from(1);
        }
        Err(error) => {
            eprintln!("recovery refused: {error}");
            return ExitCode::from(1);
        }
    };
    if manifest.domain_name != instance.as_str() {
        eprintln!(
            "recovery refused: durable Preparing domain identity differs from requested instance"
        );
        return ExitCode::from(1);
    }
    let boot = match forge_libvirt::LibvirtBootBackend::connect_instance(instance.clone()) {
        Ok(backend) => backend,
        Err(error) => {
            eprintln!("recovery refused: libvirt connection failed: {error}");
            return ExitCode::from(1);
        }
    };
    let observed = match boot.inspect_managed_state(&manifest) {
        Ok(observed) => observed,
        Err(error) => {
            eprintln!("recovery refused: exact Preparing resource inspection failed: {error}");
            return ExitCode::from(1);
        }
    };
    let index = match forge_state::plan_initial_create_recovery(&layout, &manifest, &observed) {
        Ok(index) => index,
        Err(error) => {
            eprintln!("recovery refused: {error}");
            return ExitCode::from(1);
        }
    };
    let profile = match validate_profile_binding(instance.as_str(), &index, &manifest) {
        Ok(profile) => profile,
        Err(error) => {
            eprintln!("recovery refused: {error}");
            return ExitCode::from(1);
        }
    };
    if let Err(error) = validate_initial_create_domain_topology(&instance, &manifest, &profile) {
        eprintln!("recovery refused: {error}");
        return ExitCode::from(1);
    }
    println!("Recovery boundary: InitialCreatePreparing");
    println!("Instance: {}", instance);
    println!("Preparing generation: {}", manifest.generation_id);
    println!("Planned transition: Preparing -> Active initial index");
    println!("Mutation: {}", !dry_run);
    if dry_run {
        return ExitCode::SUCCESS;
    }
    eprint!("Publish the exact verified initial Active index? [y/N] ");
    let mut confirmation = String::new();
    if io::stdin().read_line(&mut confirmation).is_err()
        || !matches!(confirmation.trim(), "y" | "Y" | "yes" | "YES")
    {
        println!("Recovery cancelled; state unchanged.");
        return ExitCode::SUCCESS;
    }
    let fresh_manifest = match forge_state::inspect_layout(&layout) {
        Ok(forge_state::ManagedState::InitialCreateRecoveryRequired(value))
            if value == manifest =>
        {
            value
        }
        _ => {
            eprintln!("recovery refused: durable Preparing intent changed before publication");
            return ExitCode::from(1);
        }
    };
    let fresh_observed = match boot.inspect_managed_state(&fresh_manifest) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("recovery refused: exact Preparing resource reinspection failed: {error}");
            return ExitCode::from(1);
        }
    };
    let fresh_index = match forge_state::plan_initial_create_recovery(
        &layout,
        &fresh_manifest,
        &fresh_observed,
    ) {
        Ok(value) if value == index => value,
        Ok(_) => {
            eprintln!("recovery refused: planned initial Active index changed before publication");
            return ExitCode::from(1);
        }
        Err(error) => {
            eprintln!("recovery refused: {error}");
            return ExitCode::from(1);
        }
    };
    if let Err(error) =
        validate_initial_create_domain_topology(&instance, &fresh_manifest, &profile)
    {
        eprintln!("recovery refused: {error}");
        return ExitCode::from(1);
    }
    match forge_state::write_index_atomic(&layout.index, &fresh_index) {
        Ok(()) => {
            println!(
                "Initial create recovery finalized atomically; immutable Preparing manifest was not changed."
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("atomic initial recovery publication failed: {error}");
            ExitCode::from(1)
        }
    }
}

fn validate_initial_create_domain_topology(
    instance: &InstanceName,
    manifest: &forge_state::GenerationManifest,
    profile: &forge_core::VmProfile,
) -> Result<(), String> {
    let storage =
        forge_libvirt::LibvirtDefineBackend::connect_local().map_err(|e| e.to_string())?;
    let (domain, xml) = storage.inspect_stable_domain(instance.as_str())?;
    let overlay = manifest
        .resources
        .iter()
        .find(|r| r.role == forge_state::ResourceRole::WritableOverlay)
        .ok_or_else(|| "Preparing manifest lacks writable overlay".to_owned())?;
    if domain.name != manifest.domain_name
        || domain.uuid != manifest.domain_uuid
        || !domain.persistent
        || domain.disk_path != overlay.path
        || domain.topology.disks.len() != 1
        || domain.topology.disks[0].format != "qcow2"
        || domain.topology.disks[0].source != overlay.path
    {
        return Err("defined domain identity or primary-disk topology differs from durable Preparing intent".to_owned());
    }
    match profile.kind {
        forge_core::GuestProfileKind::KaliLab => {
            forge_storage::validate_kali_topology(&domain.topology, &overlay.path)
        }
        forge_core::GuestProfileKind::WhonixGateway => {
            if xml.matches("<interface ").count() != 2
                || !xml.contains("<interface type='user'>")
                || !xml.contains("<backend type='passt'/>")
                || !xml.contains("<interface type='udp'>")
                || !xml.contains("<source address='127.0.0.1' port='5577'>")
                || !xml.contains("<local address='127.0.0.1' port='6688'/>")
            {
                Err("Gateway domain topology differs from exact built-in pair policy".to_owned())
            } else {
                Ok(())
            }
        }
        forge_core::GuestProfileKind::WhonixWorkstation => {
            if xml.matches("<interface ").count() != 1
                || !xml.contains("<interface type='udp'>")
                || !xml.contains("<source address='127.0.0.1' port='6688'>")
                || !xml.contains("<local address='127.0.0.1' port='5577'/>")
            {
                Err(
                    "Workstation domain topology differs from exact built-in pair policy"
                        .to_owned(),
                )
            } else {
                Ok(())
            }
        }
        _ => Ok(()),
    }
}

struct FreshRestoreBackend {
    storage: forge_libvirt::LibvirtDefineBackend,
    boot: forge_libvirt::LibvirtBootBackend,
    layout: forge_state::StateLayout,
    instance: InstanceName,
}

impl forge_storage::FreshRecoveryBackend for FreshRestoreBackend {
    fn revalidate_restore(&mut self, plan: &forge_storage::RestoreOldPlan) -> Result<(), String> {
        let index = forge_state::read_index(&self.layout.index)
            .map_err(|e| e.to_string())?
            .ok_or("recovery index disappeared")?;
        let manifests = load_index_manifests(&self.layout, &index)?;
        if index != plan.source_index
            || manifests
                .iter()
                .find(|m| m.generation_id == plan.old_active.generation_id)
                != Some(&plan.old_active)
            || manifests
                .iter()
                .find(|m| m.generation_id == plan.preparing.generation_id)
                != Some(&plan.preparing)
        {
            return Err("durable Fresh recovery identities changed".to_owned());
        }
        let (domain, _) = self.storage.inspect_stable_domain(self.instance.as_str())?;
        if domain != plan.current_domain {
            return Err("current Preparing domain topology changed".to_owned());
        }
        forge_storage::validate_kali_topology(&domain.topology, &domain.disk_path)?;
        let observed = self
            .boot
            .inspect_generation_overlay_only(&domain.disk_path)
            .map_err(|e| e.to_string())?;
        let report = forge_state::reconcile_managed(&index, &manifests, &observed);
        if !matches!(
            report.recovery_reason,
            Some(forge_state::ManagedRecoveryReason::FreshReplacementPending { .. })
        ) {
            return Err("state is no longer FreshReplacementPending".to_owned());
        }
        Ok(())
    }
    fn define_old(&mut self, xml: &str) -> Result<(), String> {
        let domain = forge_storage::DefineBackend::define_domain(&mut self.storage, xml)
            .map_err(|e| e.error.to_string())?;
        if domain.uuid == self.instance_uuid()? && domain.state == forge_core::VmState::Shutoff {
            Ok(())
        } else {
            Err("restored domain UUID/state mismatch".to_owned())
        }
    }
    fn inspect_old(
        &mut self,
        _: &forge_storage::RestoreOldPlan,
    ) -> Result<forge_storage::StableDomainEvidence, String> {
        self.storage
            .inspect_stable_domain(self.instance.as_str())
            .map(|v| v.0)
    }
    fn publish_failed(
        &mut self,
        expected: &forge_state::GenerationIndex,
        next: &forge_state::GenerationIndex,
    ) -> Result<(), String> {
        let current = forge_state::read_index(&self.layout.index)
            .map_err(|e| e.to_string())?
            .ok_or("recovery index disappeared")?;
        if &current != expected {
            return Err("recovery index changed before atomic publication".to_owned());
        }
        forge_state::write_index_atomic(&self.layout.index, next).map_err(|e| e.to_string())
    }
    fn cleanup_failed_preparing(
        &mut self,
        manifest: &forge_state::GenerationManifest,
    ) -> Result<(), String> {
        let targets = manifest
            .resources
            .iter()
            .filter(|r| r.role != forge_state::ResourceRole::SharedBase)
            .collect::<Vec<_>>();
        if targets.len() != 1 || targets[0].role != forge_state::ResourceRole::WritableOverlay {
            return Err("Fresh recovery cleanup ownership is not one exact overlay".to_owned());
        }
        self.boot
            .delete_managed_volume_exact(targets[0])
            .map_err(|e| e.to_string())?;
        self.boot
            .verify_managed_volume_absent(targets[0])
            .map_err(|e| e.to_string())
    }
    fn reconcile_old(&mut self, expected: &forge_state::GenerationIndex) -> Result<(), String> {
        let manifests = load_index_manifests(&self.layout, expected)?;
        let active = active_manifest(expected, &manifests)?;
        let observed = self
            .boot
            .inspect_managed_state(active)
            .map_err(|e| e.to_string())?;
        let report = forge_state::reconcile_managed(expected, &manifests, &observed);
        if report.status == forge_state::ManagedReconciliationStatus::Consistent {
            Ok(())
        } else {
            Err(format!(
                "restored old Active reconciliation is {:?}",
                report.status
            ))
        }
    }
}

impl FreshRestoreBackend {
    fn instance_uuid(&self) -> Result<String, String> {
        forge_state::read_index(&self.layout.index)
            .map_err(|e| e.to_string())?
            .map(|i| i.domain_uuid)
            .ok_or("recovery index disappeared".to_owned())
    }
}

#[allow(clippy::too_many_lines)]
fn fresh_restore_old(instance_name: &str, dry_run: bool) -> ExitCode {
    let operational = match operational_instance_internal(instance_name, true) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("recovery refused: {e}");
            return ExitCode::from(1);
        }
    };
    if operational.profile.kind != forge_core::GuestProfileKind::KaliLab {
        eprintln!("recovery refused: Fresh restore-old is supported only for Kali");
        return ExitCode::from(1);
    }
    let layout = match managed_state_layout_for(&operational.instance) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("recovery refused: {e}");
            return ExitCode::from(1);
        }
    };
    let storage = match forge_libvirt::LibvirtDefineBackend::connect_local() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("recovery refused: {e}");
            return ExitCode::from(1);
        }
    };
    let boot =
        match forge_libvirt::LibvirtBootBackend::connect_instance(operational.instance.clone()) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("recovery refused: {e}");
                return ExitCode::from(1);
            }
        };
    let (current, _) = match storage.inspect_stable_domain(instance_name) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("recovery refused: {e}");
            return ExitCode::from(1);
        }
    };
    if let Err(e) = forge_storage::validate_kali_topology(&current.topology, &current.disk_path) {
        eprintln!("recovery refused: {e}");
        return ExitCode::from(1);
    }
    let Some(preparing) = operational
        .manifests
        .iter()
        .find(|m| m.status == forge_state::GenerationStatus::Preparing)
    else {
        eprintln!("recovery refused: no Preparing generation");
        return ExitCode::from(1);
    };
    let Some(new_disk) = preparing
        .resources
        .iter()
        .find(|r| r.role == forge_state::ResourceRole::WritableOverlay)
    else {
        eprintln!("recovery refused: Preparing overlay missing");
        return ExitCode::from(1);
    };
    let Some(old_disk) = operational
        .active
        .resources
        .iter()
        .find(|r| r.role == forge_state::ResourceRole::WritableOverlay)
    else {
        eprintln!("recovery refused: Active overlay missing");
        return ExitCode::from(1);
    };
    let preparing_observed = match boot.inspect_generation_overlay_only(&new_disk.path) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("recovery refused: Preparing storage proof failed: {error}");
            return ExitCode::from(1);
        }
    };
    let recovery = forge_state::reconcile_managed(
        &operational.index,
        &operational.manifests,
        &preparing_observed,
    );
    if !matches!(
        recovery.recovery_reason,
        Some(forge_state::ManagedRecoveryReason::FreshReplacementPending { .. })
    ) {
        eprintln!("recovery refused: state is not exact FreshReplacementPending");
        return ExitCode::from(1);
    }
    let Some(domain_evidence) = preparing.fresh_domain_evidence.as_ref() else {
        eprintln!("recovery refused: Preparing has no durable Fresh domain evidence");
        return ExitCode::from(1);
    };
    if format!("{:?}", current.topology) != domain_evidence.replacement_normalized_topology {
        eprintln!("recovery refused: current topology differs from durable Preparing evidence");
        return ExitCode::from(1);
    }
    let old_xml = domain_evidence.old_persistent_xml.clone();
    let plan = match forge_storage::plan_restore_old(
        &operational.index,
        &operational.manifests,
        current,
        old_xml,
    ) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("recovery refused: {e}");
            return ExitCode::from(1);
        }
    };
    println!("RecoveryReason: FreshReplacementPending");
    println!("Durable old Active: {}", plan.old_active.generation_id);
    println!("Preparing generation: {}", plan.preparing.generation_id);
    println!(
        "Observed Preparing binding: {}",
        plan.current_domain.disk_path
    );
    println!("Planned restore-old binding: {}", old_disk.path);
    println!("Recovery cleanup target: {}", new_disk.path);
    println!("Mutation: {}", !dry_run);
    if dry_run {
        return ExitCode::SUCCESS;
    }
    eprint!("Restore exact old Active definition and recover Preparing resources? [y/N] ");
    let mut answer = String::new();
    if io::stdin().read_line(&mut answer).is_err()
        || !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
    {
        println!("Recovery cancelled; state unchanged.");
        return ExitCode::SUCCESS;
    }
    let mut backend = FreshRestoreBackend {
        storage,
        boot,
        layout,
        instance: operational.instance,
    };
    match forge_storage::execute_restore_old(&mut backend, &plan) {
        Ok(_) => {
            println!("Fresh restore-old recovery completed.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Fresh restore-old recovery failed closed: {e}");
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
    let _ = dry_run;
    eprintln!("adoption refused: {LEGACY_FEDORA_RETIRED}");
    return ExitCode::from(1);
    #[allow(unreachable_code)]
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

fn cleanup_vm_dry_run(instance_name: &str) -> ExitCode {
    managed_cleanup(instance_name, true)
}

/// Plans the Kali Fresh transaction. Execution remains deliberately disabled
/// until the stable-name libvirt replacement/recovery boundary is implemented.
#[allow(clippy::too_many_lines)]
fn fresh_vm(instance_name: &str, dry_run: bool) -> ExitCode {
    let operational = match operational_instance(instance_name) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("fresh refused: {error}");
            return ExitCode::from(1);
        }
    };
    if !operational
        .active
        .resources
        .iter()
        .any(|resource| resource.role == forge_state::ResourceRole::SharedBase)
    {
        eprintln!("fresh refused: flat RAW clone is not supported for Kali Fresh");
        return ExitCode::from(1);
    }
    let backend =
        match forge_libvirt::LibvirtBootBackend::connect_instance(operational.instance.clone()) {
            Ok(backend) => backend,
            Err(error) => {
                eprintln!("fresh inspection failed: {error}");
                return ExitCode::from(1);
            }
        };
    let (old_domain, old_domain_xml) = match forge_libvirt::LibvirtDefineBackend::connect_local()
        .map_err(|e| e.to_string())
        .and_then(|b| b.inspect_stable_domain(instance_name))
    {
        Ok(value) => value,
        Err(error) => {
            eprintln!("fresh domain inspection failed: {error}");
            return ExitCode::from(1);
        }
    };
    if let Err(error) =
        forge_storage::validate_kali_topology(&old_domain.topology, &old_domain.disk_path)
    {
        eprintln!("fresh refused before mutation: {error}");
        return ExitCode::from(1);
    }
    let status = match backend.inspect_managed_lifecycle(&operational.active) {
        Ok(status) => status,
        Err(error) => {
            eprintln!("fresh lifecycle inspection failed: {error}");
            return ExitCode::from(1);
        }
    };
    let observed = match backend.inspect_managed_state(&operational.active) {
        Ok(observed) => observed,
        Err(error) => {
            eprintln!("fresh storage inspection failed: {error}");
            return ExitCode::from(1);
        }
    };
    let reconciliation =
        forge_state::reconcile_managed(&operational.index, &operational.manifests, &observed);
    let shared_base = operational
        .active
        .resources
        .iter()
        .find(|resource| resource.role == forge_state::ResourceRole::SharedBase);
    let plan = match forge_storage::plan_fresh(
        forge_storage::FreshPlanInput {
            instance: operational.instance.clone(),
            profile: Some(operational.profile.clone()),
            index: operational.index.clone(),
            active: Some(operational.active.clone()),
            observed,
            domain_state: status.domain_state,
            reconciliation: reconciliation.status,
            shared_base_disposition: if shared_base.is_some() {
                forge_storage::SharedBaseDisposition::ReuseProven
            } else {
                forge_storage::SharedBaseDisposition::Prepare
            },
            old_seed: operational
                .active
                .resources
                .iter()
                .find(|resource| resource.role == forge_state::ResourceRole::NoCloudSeed)
                .cloned(),
            old_network_identity: old_domain.network_identity.clone(),
        },
        forge_state::new_generation_id(),
    ) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("fresh refused: {error}");
            return ExitCode::from(1);
        }
    };
    println!(
        "Mode: {}",
        if dry_run {
            "fresh dry-run (zero mutation)"
        } else {
            "fresh real"
        }
    );
    println!("Instance: {}", plan.stable_instance);
    println!("Profile: {}", plan.profile_id);
    println!(
        "Current Active generation: {}",
        plan.old_active_generation_id
    );
    println!("Current domain UUID: {}", plan.old_domain_uuid);
    println!("Current state: {}", status.domain_state);
    println!("Reconciliation: {:?}", reconciliation.status);
    println!(
        "Shared base disposition: {:?}",
        plan.trusted_base_disposition
    );
    println!(
        "Existing trusted base: {}",
        shared_base.map_or("unknown", |r| r.path.as_str())
    );
    println!("Planned new generation: {}", plan.new_generation_id);
    println!(
        "Planned new overlay: /var/lib/libvirt/images/{}",
        plan.new_overlay
    );
    println!("Seed: {}", plan.new_seed.as_deref().unwrap_or("none"));
    println!("Domain identity: stable instance name / stable UUID");
    println!(
        "Persistent topology proof: exact normalized machine/firmware, CPU/memory, disks, NICs, graphics, QGA, device inventory, and autostart"
    );
    println!(
        "Domain replacement: redefine existing shutoff persistent domain with same stable name/UUID after replacement storage proof"
    );
    println!(
        "Recovery boundary: if domain XML advances before durable Active switch, normal lifecycle refuses until explicit Fresh recovery"
    );
    println!(
        "Guest state: fresh from trusted Kali base; current writable guest changes are not copied"
    );
    println!("Activation: old Active -> Retained; new Preparing -> Active");
    println!("Old generation: retained after success");
    println!("Automatic cleanup: no");
    println!("Automatic boot: no");
    println!("Confirmation required: yes");
    println!("Mutation: false");
    if !dry_run {
        eprint!("Replace {instance_name} with a fresh shutoff Kali generation? [y/N] ");
        let mut answer = String::new();
        if io::stdin().read_line(&mut answer).is_err()
            || !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
        {
            eprintln!("Fresh cancelled.");
            return ExitCode::SUCCESS;
        }
        let old_disk = if let Some(value) = plan
            .old_storage
            .iter()
            .find(|r| r.role == forge_state::ResourceRole::WritableOverlay)
        {
            value.path.clone()
        } else {
            eprintln!("fresh refused: old Active overlay missing");
            return ExitCode::from(1);
        };
        let new_path = format!("/var/lib/libvirt/images/{}", plan.new_overlay);
        let replacement_xml =
            match forge_libvirt::replace_domain_disk(&old_domain_xml, &old_disk, &new_path) {
                Ok(xml) => xml,
                Err(error) => {
                    eprintln!("fresh refused: {error}");
                    return ExitCode::from(1);
                }
            };
        let created_unix_seconds =
            match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                Ok(value) => value.as_secs(),
                Err(error) => {
                    eprintln!("fresh refused: {error}");
                    return ExitCode::from(1);
                }
            };
        let layout = match managed_state_layout_for(&operational.instance) {
            Ok(value) => value,
            Err(error) => {
                eprintln!("fresh refused: {error}");
                return ExitCode::from(1);
            }
        };
        let mut executor = KaliFreshBackend {
            storage: match forge_libvirt::LibvirtDefineBackend::connect_local() {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("fresh refused: {e}");
                    return ExitCode::from(1);
                }
            },
            instance: operational.instance.clone(),
            layout,
            source: operational.clone(),
            old_domain,
            overlay_created: false,
        };
        return match forge_storage::execute_fresh(
            &mut executor,
            &forge_storage::FreshExecutionPlan {
                fresh: plan,
                created_unix_seconds,
                replacement_xml,
            },
        ) {
            Ok(result) => {
                println!("Active generation: {}", result.index.active_generation_id);
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("fresh failed: {error}");
                ExitCode::from(1)
            }
        };
    }
    ExitCode::SUCCESS
}

struct KaliFreshBackend {
    storage: forge_libvirt::LibvirtDefineBackend,
    instance: InstanceName,
    layout: forge_state::StateLayout,
    source: OperationalInstance,
    old_domain: forge_storage::StableDomainEvidence,
    overlay_created: bool,
}

impl forge_storage::FreshExecutionBackend for KaliFreshBackend {
    fn revalidate(
        &mut self,
        plan: &forge_storage::FreshExecutionPlan,
    ) -> Result<forge_storage::StableDomainEvidence, String> {
        let fresh = operational_instance(self.instance.as_str())?;
        if fresh.index != self.source.index
            || fresh.active != self.source.active
            || fresh.manifests != self.source.manifests
        {
            return Err("durable Active/Preparing state changed since planning".to_owned());
        }
        let boot = forge_libvirt::LibvirtBootBackend::connect_instance(self.instance.clone())
            .map_err(|e| e.to_string())?;
        let lifecycle = boot
            .inspect_managed_lifecycle(&fresh.active)
            .map_err(|e| e.to_string())?;
        let observed = boot
            .inspect_managed_state(&fresh.active)
            .map_err(|e| e.to_string())?;
        if lifecycle.domain_state != forge_core::VmState::Shutoff
            || forge_state::reconcile_managed(&fresh.index, &fresh.manifests, &observed).status
                != forge_state::ManagedReconciliationStatus::Consistent
        {
            return Err("source is no longer shutoff and Consistent".to_owned());
        }
        let (domain, _) = self.storage.inspect_stable_domain(self.instance.as_str())?;
        if domain != self.old_domain {
            return Err("old domain identity, disk, or network changed".to_owned());
        }
        forge_storage::validate_kali_topology(&domain.topology, &domain.disk_path)?;
        if forge_storage::DefineBackend::volume_exists(
            &mut self.storage,
            forge_storage::DEFAULT_POOL,
            &plan.fresh.new_overlay,
        )
        .map_err(|e| e.to_string())?
        {
            return Err("candidate overlay collision".to_owned());
        }
        Ok(domain)
    }

    fn create_overlay(&mut self, plan: &forge_storage::FreshExecutionPlan) -> Result<(), String> {
        let base = self
            .source
            .active
            .resources
            .iter()
            .find(|r| r.role == forge_state::ResourceRole::SharedBase)
            .ok_or("trusted shared base missing")?;
        let overlay = forge_storage::OverlayVolume {
            name: plan.fresh.new_overlay.clone(),
            path: format!("/var/lib/libvirt/images/{}", plan.fresh.new_overlay),
            capacity_bytes: self.source.profile.resources.disk_bytes,
            allocation_bytes: 0,
            format: "qcow2".to_owned(),
            backing_path: Some(base.path.clone()),
        };
        forge_storage::ImagePrepareBackend::create_overlay(
            &mut self.storage,
            forge_storage::DEFAULT_POOL,
            &overlay,
        )
        .map_err(|e| e.to_string())?;
        self.overlay_created = true;
        Ok(())
    }

    fn inspect_overlay(
        &mut self,
        plan: &forge_storage::FreshExecutionPlan,
    ) -> Result<forge_state::ObservedGeneration, String> {
        let observed = self
            .storage
            .inspect_preparing_generation(
                &self.instance,
                &plan.fresh.new_domain_uuid,
                &plan.fresh.new_overlay,
                None,
            )
            .map_err(|e| e.to_string())?;
        let overlay = observed
            .resources
            .iter()
            .find(|r| r.role == forge_state::ResourceRole::WritableOverlay)
            .ok_or("new overlay observation missing")?;
        let base = self
            .source
            .active
            .resources
            .iter()
            .find(|r| r.role == forge_state::ResourceRole::SharedBase)
            .ok_or("trusted shared base missing")?;
        if overlay.format != "qcow2"
            || overlay.capacity_bytes != self.source.profile.resources.disk_bytes
            || overlay.backing_path.as_deref() != Some(base.path.as_str())
        {
            return Err("new overlay format/capacity/backing proof failed".to_owned());
        }
        Ok(observed)
    }

    fn publish_preparing(
        &mut self,
        manifest: &forge_state::GenerationManifest,
    ) -> Result<forge_state::GenerationIndex, String> {
        forge_state::write_manifest_atomic(
            &self.layout.generation_path(&manifest.generation_id),
            manifest,
        )
        .map_err(|e| e.to_string())?;
        let next =
            forge_state::add_preparing(&self.source.index, manifest).map_err(|e| e.to_string())?;
        forge_state::write_index_atomic(&self.layout.index, &next).map_err(|e| e.to_string())?;
        Ok(next)
    }
    fn revalidate_old_domain(
        &mut self,
        expected: &forge_storage::StableDomainEvidence,
    ) -> Result<(), String> {
        let (actual, _) = self.storage.inspect_stable_domain(self.instance.as_str())?;
        if &actual == expected {
            Ok(())
        } else {
            Err("old domain changed before redefine".to_owned())
        }
    }
    fn define_replacement(&mut self, xml: &str) -> Result<(), String> {
        let d = forge_storage::DefineBackend::define_domain(&mut self.storage, xml)
            .map_err(|e| e.error.to_string())?;
        if d.uuid == self.old_domain.uuid && d.state == forge_core::VmState::Shutoff {
            Ok(())
        } else {
            Err("defined replacement identity/state mismatch".to_owned())
        }
    }
    fn inspect_replacement(
        &mut self,
        plan: &forge_storage::FreshExecutionPlan,
    ) -> Result<
        (
            forge_storage::StableDomainEvidence,
            forge_state::ObservedGeneration,
        ),
        String,
    > {
        let (domain, _) = self.storage.inspect_stable_domain(self.instance.as_str())?;
        let boot = forge_libvirt::LibvirtBootBackend::connect_instance(self.instance.clone())
            .map_err(|e| e.to_string())?;
        let observed = boot
            .inspect_generation_overlay_only(&format!(
                "/var/lib/libvirt/images/{}",
                plan.fresh.new_overlay
            ))
            .map_err(|e| e.to_string())?;
        Ok((domain, observed))
    }
    fn activate(
        &mut self,
        expected: &forge_state::GenerationIndex,
        next: &forge_state::GenerationIndex,
    ) -> Result<(), String> {
        let current = forge_state::read_index(&self.layout.index)
            .map_err(|e| e.to_string())?
            .ok_or("Fresh index disappeared")?;
        if &current != expected {
            return Err("Fresh index changed before activation".to_owned());
        }
        forge_state::write_index_atomic(&self.layout.index, next).map_err(|e| e.to_string())
    }
    fn reconcile_final(
        &mut self,
        expected: &forge_state::GenerationIndex,
        observed: &forge_state::ObservedGeneration,
    ) -> Result<(), String> {
        let manifests = load_index_manifests(&self.layout, expected)?;
        let report = forge_state::reconcile_managed(expected, &manifests, observed);
        if report.status == forge_state::ManagedReconciliationStatus::Consistent {
            Ok(())
        } else {
            Err(format!(
                "final reconciliation is {:?}: {}",
                report.status, report.detail
            ))
        }
    }
    fn rollback_overlay(&mut self, plan: &forge_storage::FreshExecutionPlan) -> Result<(), String> {
        if self.overlay_created {
            forge_storage::DefineBackend::delete_volume(
                &mut self.storage,
                forge_storage::DEFAULT_POOL,
                &plan.fresh.new_overlay,
            )
            .map_err(|e| e.to_string())?;
            self.overlay_created = false;
        }
        Ok(())
    }
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
        .find(|resource| resource.role == forge_state::ResourceRole::SharedBase);
    let profile = if let Some(profile) = forge_profiles::find(instance_name) {
        profile
    } else {
        let mut matching = forge_profiles::built_in_profiles()
            .into_iter()
            .filter(|profile| {
                profile.persistence == forge_core::PersistencePolicy::Persistent
                    && match durable_base {
                        Some(base) => forge_profiles::base_volume_name(profile) == base.volume_name,
                        None => {
                            profile.kind == forge_core::GuestProfileKind::KaliLab
                                && profile.provisioning == forge_core::ProvisioningPolicy::None
                                && profile.first_boot_success
                                    == forge_core::FirstBootSuccessPolicy::ManualGuest
                        }
                    }
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
    let overlay = resource(forge_state::ResourceRole::WritableOverlay)?;
    if overlay.capacity_bytes != profile.resources.disk_bytes {
        return Err("active generation topology differs from profile policy".to_owned());
    }
    if let Some(base) = durable_base {
        if base.volume_name != forge_profiles::base_volume_name(&profile) {
            return Err("active generation topology differs from profile policy".to_owned());
        }
    } else if overlay.backing_path.is_some() {
        return Err("flat clone generation unexpectedly has a backing path".to_owned());
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

#[derive(Clone)]
struct OperationalInstance {
    instance: InstanceName,
    profile: forge_core::VmProfile,
    index: forge_state::GenerationIndex,
    manifests: Vec<forge_state::GenerationManifest>,
    active: forge_state::GenerationManifest,
}

#[derive(Clone)]
struct CloneSourceProof {
    operational: OperationalInstance,
    status: forge_provisioning::InstanceLifecycleStatus,
}

fn operational_instance(instance_name: &str) -> Result<OperationalInstance, String> {
    operational_instance_internal(instance_name, false)
}

fn operational_instance_internal(
    instance_name: &str,
    allow_recovery: bool,
) -> Result<OperationalInstance, String> {
    let instance = InstanceName::new(instance_name)
        .map_err(|error| format!("invalid instance name: {error}"))?;
    let layout = managed_state_layout_for(&instance)?;
    let index = match forge_state::inspect_layout(&layout).map_err(|error| error.to_string())? {
        forge_state::ManagedState::Current(index) => index,
        forge_state::ManagedState::Missing => {
            return Err("managed instance state is missing".into());
        }
        forge_state::ManagedState::InitialCreateRecoveryRequired(manifest) => {
            return Err(format!(
                "initial create was interrupted after durable Preparing intent {}; run `forge state recover {instance_name} --dry-run`",
                manifest.generation_id
            ));
        }
        forge_state::ManagedState::Legacy(_) => {
            return Err("legacy state requires explicit migration before managed lifecycle".into());
        }
        forge_state::ManagedState::Conflict(reason) => return Err(reason),
    };
    let manifests = load_index_manifests(&layout, &index)?;
    if !allow_recovery {
        forge_state::require_normal_lifecycle(&index).map_err(|e| e.to_string())?;
    }
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

#[derive(Debug)]
enum DeleteFailure {
    Refused(String),
    Recoverable(String),
}

fn classify_domain_delete_error(error: forge_libvirt::DomainDeleteError) -> DeleteFailure {
    match error {
        forge_libvirt::DomainDeleteError::Conflict(reason)
        | forge_libvirt::DomainDeleteError::UnsafeState(reason) => DeleteFailure::Refused(reason),
        forge_libvirt::DomainDeleteError::Backend(reason) => DeleteFailure::Recoverable(reason),
    }
}

fn classify_volume_delete_error(error: forge_libvirt::ManagedVolumeDeleteError) -> DeleteFailure {
    match error {
        forge_libvirt::ManagedVolumeDeleteError::IdentityMismatch(reason)
        | forge_libvirt::ManagedVolumeDeleteError::Referenced(reason) => {
            DeleteFailure::Refused(reason)
        }
        forge_libvirt::ManagedVolumeDeleteError::SharedBase => {
            DeleteFailure::Refused("shared base deletion is forbidden".to_owned())
        }
        forge_libvirt::ManagedVolumeDeleteError::Backend(reason) => {
            DeleteFailure::Recoverable(reason)
        }
    }
}

fn classify_volume_absence_error(error: forge_libvirt::ManagedVolumeAbsenceError) -> DeleteFailure {
    match error {
        forge_libvirt::ManagedVolumeAbsenceError::Present(reason) => DeleteFailure::Refused(reason),
        forge_libvirt::ManagedVolumeAbsenceError::Backend(reason) => {
            DeleteFailure::Recoverable(reason)
        }
    }
}

fn persist_delete_index(
    layout: &forge_state::StateLayout,
    expected: &forge_state::GenerationIndex,
    next: &forge_state::GenerationIndex,
) -> Result<(), String> {
    let current = forge_state::read_index(&layout.index)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "durable delete index disappeared".to_owned())?;
    if &current != expected {
        return Err("durable delete state changed before checkpoint".to_owned());
    }
    forge_state::write_index_atomic(&layout.index, next).map_err(|error| error.to_string())
}

fn build_delete_plan(
    instance: &InstanceName,
    layout: &forge_state::StateLayout,
    index: &forge_state::GenerationIndex,
) -> Result<forge_state::DeletePlan, String> {
    let manifests = load_index_manifests(layout, index)?;
    let active = active_manifest(index, &manifests)?;
    let backend = forge_libvirt::LibvirtBootBackend::connect_instance(instance.clone())
        .map_err(|error| error.to_string())?;
    let observed = backend
        .inspect_managed_state(active)
        .map_err(|error| error.to_string())?;
    let reconciliation = forge_state::reconcile_managed(index, &manifests, &observed);
    forge_state::plan_instance_delete(index, &manifests, &observed, reconciliation.status)
        .map_err(|error| error.to_string())
}

fn print_delete_plan(instance: &str, plan: &forge_state::DeletePlan, force: bool) {
    println!("Managed VM: {instance}");
    println!("Exact domain UUID: {}", plan.domain_uuid);
    println!("Resources to remove:");
    for item in &plan.resources {
        println!("- {:?}: {}", item.resource.role, item.resource.path);
    }
    println!("Shared/canonical base: preserved");
    if force {
        println!("Force mode: only an exact running domain may be force-stopped");
    }
}

fn delete_vm(instance_name: &str, force: bool) -> ExitCode {
    let instance = match InstanceName::new(instance_name) {
        Ok(instance) => instance,
        Err(error) => {
            eprintln!("delete refused: invalid instance name: {error}");
            return ExitCode::from(2);
        }
    };
    let layout = match managed_state_layout_for(&instance) {
        Ok(layout) => layout,
        Err(error) => {
            eprintln!("delete refused: {error}");
            return ExitCode::from(1);
        }
    };
    let state = match forge_state::inspect_layout(&layout) {
        Ok(state) => state,
        Err(error) => {
            eprintln!("delete refused: durable state is invalid: {error}");
            return ExitCode::from(1);
        }
    };
    let index = match state {
        forge_state::ManagedState::Current(index) => index,
        forge_state::ManagedState::Missing => {
            eprintln!("delete refused: Forge ownership state is missing");
            return ExitCode::from(1);
        }
        forge_state::ManagedState::InitialCreateRecoveryRequired(_) => {
            eprintln!("delete refused: initial create recovery is required");
            return ExitCode::from(1);
        }
        forge_state::ManagedState::Legacy(_) => {
            eprintln!("delete refused: legacy state requires explicit migration");
            return ExitCode::from(1);
        }
        forge_state::ManagedState::Conflict(reason) => {
            eprintln!("delete refused: {reason}");
            return ExitCode::from(1);
        }
    };
    match &index.delete_state {
        Some(forge_state::DeleteState::Deleted(_)) => {
            println!("already deleted: {instance_name}");
            return ExitCode::SUCCESS;
        }
        Some(forge_state::DeleteState::Deleting(progress)) => {
            println!("Resuming durable delete for {instance_name}.");
            return execute_delete_plan(&instance, &layout, &index, &progress.plan, force, false);
        }
        None => {}
    }

    let plan = match build_delete_plan(&instance, &layout, &index) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("delete refused: {error}");
            return ExitCode::from(1);
        }
    };
    let define = match forge_libvirt::LibvirtDefineBackend::connect_local() {
        Ok(backend) => backend,
        Err(error) => {
            eprintln!("delete refused: libvirt connection failed: {error}");
            return ExitCode::from(1);
        }
    };
    let identity = forge_libvirt::ExactDomainIdentity {
        name: plan.domain_name.clone(),
        uuid: plan.domain_uuid.clone(),
    };
    let observation = match define.observe_domain_for_delete(&identity) {
        Ok(observation) => observation,
        Err(error) => {
            eprintln!("delete refused: exact domain observation failed: {error}");
            return ExitCode::from(1);
        }
    };
    match &observation {
        forge_libvirt::DomainDeleteObservation::Absent => {
            eprintln!("delete refused: expected domain is absent before durable delete intent");
            return ExitCode::from(1);
        }
        forge_libvirt::DomainDeleteObservation::Conflict(reason) => {
            eprintln!("delete refused: domain identity conflict: {reason}");
            return ExitCode::from(1);
        }
        forge_libvirt::DomainDeleteObservation::ExactPresent { state, .. }
            if *state != forge_core::VmState::Shutoff
                && !(*state == forge_core::VmState::Running && force) =>
        {
            eprintln!("delete refused: exact domain is {state}; use --force only for a running VM");
            return ExitCode::from(1);
        }
        forge_libvirt::DomainDeleteObservation::ExactPresent { .. } => {}
    }
    print_delete_plan(instance_name, &plan, force);
    eprint!("Delete this exact managed VM? [y/N] ");
    let mut answer = String::new();
    if io::stdin().read_line(&mut answer).is_err() || !confirmation_accepted(&answer) {
        eprintln!("Delete cancelled.");
        return ExitCode::SUCCESS;
    }
    let fresh_index = match forge_state::read_index(&layout.index) {
        Ok(Some(index)) => index,
        Ok(None) => {
            eprintln!("delete refused: durable state disappeared before intent");
            return ExitCode::from(1);
        }
        Err(error) => {
            eprintln!("delete refused: state revalidation failed: {error}");
            return ExitCode::from(1);
        }
    };
    let fresh_plan = match build_delete_plan(&instance, &layout, &fresh_index) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("delete refused: pre-mutation ownership revalidation failed: {error}");
            return ExitCode::from(1);
        }
    };
    if fresh_index != index || fresh_plan != plan {
        eprintln!("delete refused: durable ownership or exact plan changed before intent");
        return ExitCode::from(1);
    }
    let next = match forge_state::begin_instance_delete(&index, &plan) {
        Ok(next) => next,
        Err(error) => {
            eprintln!("delete refused before mutation: {error}");
            return ExitCode::from(1);
        }
    };
    if let Err(error) = persist_delete_index(&layout, &index, &next) {
        eprintln!("delete refused before mutation: durable intent was not persisted: {error}");
        return ExitCode::from(1);
    }
    execute_delete_plan(&instance, &layout, &next, &plan, force, force)
}

fn execute_delete_plan(
    instance: &InstanceName,
    layout: &forge_state::StateLayout,
    index: &forge_state::GenerationIndex,
    plan: &forge_state::DeletePlan,
    force: bool,
    force_confirmed: bool,
) -> ExitCode {
    let result = execute_delete_plan_inner(instance, layout, index, plan, force, force_confirmed);
    match result {
        Ok(()) => {
            println!("Delete completed: {}", instance);
            ExitCode::SUCCESS
        }
        Err(DeleteFailure::Recoverable(error)) => {
            eprintln!("delete stopped: {error}");
            eprintln!(
                "VM remains in durable Deleting state; retry `forge delete {}` to resume the immutable plan.",
                instance
            );
            ExitCode::from(1)
        }
        Err(DeleteFailure::Refused(error)) => {
            eprintln!("delete refused: {error}");
            eprintln!("Durable state requires recovery or manual inspection; no plan was guessed.");
            ExitCode::from(1)
        }
    }
}

fn execute_delete_plan_inner(
    instance: &InstanceName,
    layout: &forge_state::StateLayout,
    index: &forge_state::GenerationIndex,
    plan: &forge_state::DeletePlan,
    force: bool,
    force_confirmed: bool,
) -> Result<(), DeleteFailure> {
    let mut current = index.clone();
    let mut boot = forge_libvirt::LibvirtBootBackend::connect_instance(instance.clone())
        .map_err(|error| DeleteFailure::Recoverable(error.to_string()))?;
    let define = forge_libvirt::LibvirtDefineBackend::connect_local()
        .map_err(|error| DeleteFailure::Recoverable(error.to_string()))?;
    let identity = forge_libvirt::ExactDomainIdentity {
        name: plan.domain_name.clone(),
        uuid: plan.domain_uuid.clone(),
    };
    let domain_pending = matches!(
        &current.delete_state,
        Some(forge_state::DeleteState::Deleting(progress))
            if progress.domain == forge_state::DeleteDomainProgress::UndefinePending
    );
    if domain_pending {
        let observation = define
            .observe_domain_for_delete(&identity)
            .map_err(DeleteFailure::Recoverable)?;
        match observation {
            forge_libvirt::DomainDeleteObservation::Absent => {
                let next = forge_state::record_delete_domain_absent(&current, plan)
                    .map_err(|error| DeleteFailure::Refused(error.to_string()))?;
                persist_delete_index(layout, &current, &next)
                    .map_err(DeleteFailure::Recoverable)?;
                current = next;
            }
            forge_libvirt::DomainDeleteObservation::Conflict(reason) => {
                return Err(DeleteFailure::Refused(format!(
                    "domain identity conflict during resume: {reason}"
                )));
            }
            forge_libvirt::DomainDeleteObservation::ExactPresent { state, .. } => {
                if state == forge_core::VmState::Running {
                    if !force {
                        return Err(DeleteFailure::Refused(
                            "exact domain is running; rerun with --force".to_owned(),
                        ));
                    }
                    if !force_confirmed {
                        eprint!(
                            "Force-stop exact domain {} before delete? [y/N] ",
                            plan.domain_uuid
                        );
                        let mut answer = String::new();
                        if io::stdin().read_line(&mut answer).is_err()
                            || !confirmation_accepted(&answer)
                        {
                            return Err(DeleteFailure::Recoverable(
                                "force-stop cancelled; no further mutation was attempted"
                                    .to_owned(),
                            ));
                        }
                    }
                    forge_provisioning::execute_force_stop(
                        &mut boot,
                        &plan.domain_uuid,
                        Duration::from_secs(
                            forge_provisioning::ShutdownTimeoutPolicy::default().force_seconds,
                        ),
                    )
                    .map_err(|error| DeleteFailure::Recoverable(error.to_string()))?;
                    match define
                        .observe_domain_for_delete(&identity)
                        .map_err(DeleteFailure::Recoverable)?
                    {
                        forge_libvirt::DomainDeleteObservation::ExactPresent {
                            state: forge_core::VmState::Shutoff,
                            ..
                        } => {}
                        forge_libvirt::DomainDeleteObservation::Conflict(reason) => {
                            return Err(DeleteFailure::Refused(format!(
                                "domain identity conflict after force-stop: {reason}"
                            )));
                        }
                        other => {
                            return Err(DeleteFailure::Recoverable(format!(
                                "exact domain was not verified shutoff after force-stop: {other:?}"
                            )));
                        }
                    }
                } else if state != forge_core::VmState::Shutoff {
                    return Err(DeleteFailure::Refused(format!(
                        "unsupported exact domain state for undefine: {state}"
                    )));
                }
                define
                    .undefine_domain_exact(&identity)
                    .map_err(classify_domain_delete_error)?;
                let next = forge_state::record_delete_domain_absent(&current, plan)
                    .map_err(|error| DeleteFailure::Refused(error.to_string()))?;
                persist_delete_index(layout, &current, &next)
                    .map_err(DeleteFailure::Recoverable)?;
                current = next;
            }
        }
    }

    let resources = match &current.delete_state {
        Some(forge_state::DeleteState::Deleting(progress)) => progress.resources.clone(),
        _ => {
            return Err(DeleteFailure::Refused(
                "delete state changed before storage execution".to_owned(),
            ));
        }
    };
    for (position, progress) in resources.iter().enumerate() {
        if *progress == forge_state::DeleteResourceProgress::Absent {
            continue;
        }
        let resource = &plan.resources[position].resource;
        if resource.role == forge_state::ResourceRole::SharedBase {
            return Err(DeleteFailure::Refused(
                "internal delete plan attempted to remove SharedBase".to_owned(),
            ));
        }
        match boot.delete_managed_volume_exact(resource) {
            Ok(()) => {}
            Err(error @ forge_libvirt::ManagedVolumeDeleteError::IdentityMismatch(_))
            | Err(error @ forge_libvirt::ManagedVolumeDeleteError::Referenced(_))
            | Err(error @ forge_libvirt::ManagedVolumeDeleteError::SharedBase) => {
                return Err(classify_volume_delete_error(error));
            }
            Err(forge_libvirt::ManagedVolumeDeleteError::Backend(delete_error)) => {
                if let Err(verify_error) = boot.verify_managed_volume_absent(resource) {
                    return Err(match verify_error {
                        forge_libvirt::ManagedVolumeAbsenceError::Present(reason) => {
                            DeleteFailure::Refused(reason)
                        }
                        forge_libvirt::ManagedVolumeAbsenceError::Backend(reason) => {
                            DeleteFailure::Recoverable(format!(
                                "exact volume delete failed for {}: {delete_error}; {reason}",
                                resource.path
                            ))
                        }
                    });
                }
            }
        }
        boot.verify_managed_volume_absent(resource)
            .map_err(classify_volume_absence_error)?;
        let next = forge_state::record_delete_resource_absent(&current, plan, resource)
            .map_err(|error| DeleteFailure::Refused(error.to_string()))?;
        persist_delete_index(layout, &current, &next).map_err(DeleteFailure::Recoverable)?;
        current = next;
    }
    let next = forge_state::complete_instance_delete(&current, plan)
        .map_err(|error| DeleteFailure::Refused(error.to_string()))?;
    persist_delete_index(layout, &current, &next).map_err(DeleteFailure::Recoverable)?;
    Ok(())
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
            } else if seed.is_empty() {
                backend.inspect_generation_overlay_only(overlay)
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
fn managed_cleanup(instance_name: &str, dry_run: bool) -> ExitCode {
    let instance = match InstanceName::new(instance_name) {
        Ok(instance) => instance,
        Err(error) => {
            eprintln!("invalid instance name: {error}");
            return ExitCode::from(2);
        }
    };
    let layout = match managed_state_layout_for(&instance) {
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
        forge_state::ManagedState::InitialCreateRecoveryRequired(_) => {
            eprintln!("cleanup refused: initial create recovery is required");
            return ExitCode::from(1);
        }
        forge_state::ManagedState::Conflict(reason) => {
            eprintln!("cleanup refused: {reason}");
            return ExitCode::from(1);
        }
    };
    let active = match active_manifest(&index, &manifests) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("cleanup refused: {error}");
            return ExitCode::from(1);
        }
    };
    if forge_state::classify_durable_product(active)
        == forge_state::DurableProductClassification::LegacyFedoraCloudNoCloud
    {
        eprintln!("cleanup refused: legacy Fedora retirement cleanup is deferred to Phase 4.9");
        return ExitCode::from(1);
    }
    let observed_backend =
        match forge_libvirt::LibvirtBootBackend::connect_instance(instance.clone()) {
            Ok(value) => value,
            Err(error) => {
                eprintln!("libvirt connection failed: {error}");
                return ExitCode::from(1);
            }
        };
    let observed_active = match observed_backend.inspect_managed_state(active) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("Forge state discovery failed: {error}");
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
    eprint!("Delete exact retained-owned resources for {instance_name}? [y/N] ");
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
    let final_active = match active_manifest(&execution.next_index, &final_manifests) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("cleanup completed but final reconciliation failed: {error}");
            return ExitCode::from(1);
        }
    };
    let final_backend = match forge_libvirt::LibvirtBootBackend::connect_instance(instance.clone())
    {
        Ok(value) => value,
        Err(error) => {
            eprintln!("cleanup completed but final reconciliation failed: {error}");
            return ExitCode::from(1);
        }
    };
    let final_observed = match final_backend.inspect_managed_state(final_active) {
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
    if let Err(reason) = require_new_product(&operational.profile) {
        eprintln!("instance lifecycle action refused: {reason}");
        return ExitCode::from(1);
    }
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

fn resolve_clone_source(source_name: &str) -> Result<CloneSourceProof, String> {
    let operational = operational_instance(source_name)?;
    if !clone_profile_supported(&operational.profile) {
        return Err(
            "persistent clone currently supports only the shutoff Kali ManualGuest profile"
                .to_owned(),
        );
    }
    let status = discover_lifecycle_status(&operational)?;
    if status.domain_state != forge_core::VmState::Shutoff {
        return Err(
            "clone source must be shutoff; Forge will not stop it automatically".to_owned(),
        );
    }
    if !status.persistent || status.autostart {
        return Err("clone source must be persistent with autostart disabled".to_owned());
    }
    let overlay = operational
        .active
        .resources
        .iter()
        .find(|resource| resource.role == forge_state::ResourceRole::WritableOverlay)
        .ok_or_else(|| "clone source lacks an exact writable overlay".to_owned())?;
    if overlay.path != status.active_overlay_path
        || overlay.backing_path != status.active_backing_path
        || status.active_backing_path.is_none()
    {
        return Err("clone source backing chain is not an understood Forge chain".to_owned());
    }
    Ok(CloneSourceProof {
        operational,
        status,
    })
}

fn clone_profile_supported(profile: &forge_core::VmProfile) -> bool {
    profile.kind == forge_core::GuestProfileKind::KaliLab
        && profile.provisioning == forge_core::ProvisioningPolicy::None
        && profile.first_boot_success == forge_core::FirstBootSuccessPolicy::ManualGuest
        && profile.persistence == forge_core::PersistencePolicy::Persistent
}

fn build_clone_plan(
    source: &CloneSourceProof,
    target_name: &str,
) -> Result<(forge_profiles::GenericCreatePlan, String, String), String> {
    let target =
        InstanceName::new(target_name).map_err(|error| format!("invalid target name: {error}"))?;
    let hardware = forge_hardware::collect().map_err(|error| error.to_string())?;
    let identity = forge_profiles::InstanceIdentity {
        name: target.clone(),
        profile_id: source.operational.profile.id.clone(),
    };
    let instance_plan =
        forge_profiles::plan_instance(&hardware, &source.operational.profile, identity)
            .map_err(|error| error.to_string())?;
    let generation_id = forge_state::new_generation_id();
    let generation = forge_state::plan_generation_resources(&target, generation_id, false)
        .map_err(|error| error.to_string())?;
    let factory = forge_profiles::plan_create(instance_plan, generation)
        .map_err(|error| error.to_string())?;
    let domain_uuid = forge_state::new_generation_id()
        .strip_prefix("gen-")
        .expect("generation IDs have a stable prefix")
        .to_owned();
    let domain = forge_domain::profile_spec(
        &source.operational.profile,
        &factory.instance.resources,
        forge_domain::DomainMetadata {
            name: target.to_string(),
            disk_path: format!("/var/lib/libvirt/images/{}", factory.generation.overlay),
        },
    )
    .map_err(|error| error.to_string())?;
    let mut domain = domain;
    domain.uuid = Some(domain_uuid.clone());
    let xml = forge_domain::render_xml(&domain).map_err(|error| error.to_string())?;
    Ok((factory, xml, domain_uuid))
}

#[allow(clippy::too_many_lines)]
fn clone_vm(source_name: &str, target_name: &str, dry_run: bool) -> ExitCode {
    if source_name == target_name {
        eprintln!("clone source and target must be different instances");
        return ExitCode::from(2);
    }
    let source = match resolve_clone_source(source_name) {
        Ok(source) => source,
        Err(error) => {
            eprintln!("clone source refused: {error}");
            return ExitCode::from(1);
        }
    };
    let target = match InstanceName::new(target_name) {
        Ok(target) => target,
        Err(error) => {
            eprintln!("invalid target name: {error}");
            return ExitCode::from(2);
        }
    };
    let layout = match managed_state_layout_for(&target) {
        Ok(layout) => layout,
        Err(error) => {
            eprintln!("target state path failed: {error}");
            return ExitCode::from(1);
        }
    };
    if !matches!(
        forge_state::inspect_layout(&layout),
        Ok(forge_state::ManagedState::Missing)
    ) {
        eprintln!("clone target already has Forge durable state");
        return ExitCode::from(1);
    }
    let mut storage = match forge_libvirt::LibvirtDefineBackend::connect_local() {
        Ok(storage) => storage,
        Err(error) => {
            eprintln!("libvirt connection failed: {error}");
            return ExitCode::from(1);
        }
    };
    if DefineBackend::domain_exists(&mut storage, target_name).unwrap_or(true) {
        eprintln!("clone target domain or volume already exists");
        return ExitCode::from(1);
    }
    let (factory, xml, domain_uuid) = match build_clone_plan(&source, target_name) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("clone planning refused: {error}");
            return ExitCode::from(1);
        }
    };
    if ImagePrepareBackend::inspect_volume(
        &mut storage,
        forge_storage::DEFAULT_POOL,
        &factory.generation.overlay,
    )
    .map_or(true, |volume| volume.is_some())
    {
        eprintln!("clone target planned volume already exists");
        return ExitCode::from(1);
    }
    println!(
        "Mode: {}",
        if dry_run {
            "clone dry-run (zero mutation)"
        } else {
            "clone real"
        }
    );
    println!("Source instance: {}", source.operational.instance);
    println!(
        "Source generation: {}",
        source.operational.index.active_generation_id
    );
    println!("Source profile: {}", source.operational.profile.id);
    println!("Source state: {}", source.status.domain_state);
    println!("Source reconciliation: Consistent");
    println!("Source disk: {}", source.status.active_overlay_path);
    println!(
        "Source backing: {}",
        source
            .status
            .active_backing_path
            .as_deref()
            .unwrap_or("none")
    );
    println!("Clone strategy: full flattened copy; target has no source-overlay dependency");
    println!("Clone storage backend: libvirt system volume create-from");
    println!("Direct source filesystem access by Forge CLI: no");
    println!("Target instance: {target}");
    println!("Target generation: {}", factory.generation.generation_id);
    println!("Target domain UUID: {domain_uuid}");
    println!(
        "Target storage: /var/lib/libvirt/images/{}",
        factory.generation.overlay
    );
    println!(
        "Guest identity policy: disk state is copied; guest-level identity regeneration is not implemented for ManualGuest"
    );
    println!(
        "Cleanup policy: supported for target-owned flat clone disk only; shared bases and source overlays are protected"
    );
    println!(
        "Rebuild policy: unsupported for flat clones; refuse rather than reinterpret clone storage"
    );
    println!("Mutation: {}", !dry_run);
    if dry_run {
        return ExitCode::SUCCESS;
    }
    eprint!("Clone persistent VM {source_name} -> {target_name}? [y/N] ");
    let mut answer = String::new();
    if io::stdin().read_line(&mut answer).is_err() || !confirmation_accepted(&answer) {
        eprintln!("Clone cancelled.");
        return ExitCode::SUCCESS;
    }
    let created_unix_seconds =
        match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(value) => value.as_secs(),
            Err(error) => {
                eprintln!("clock error: {error}");
                return ExitCode::from(1);
            }
        };
    let mut backend = ManualGuestCreateBackend {
        storage: forge_libvirt::LibvirtDefineBackend::connect_local()
            .expect("libvirt connection checked"),
        boot: forge_libvirt::LibvirtBootBackend::connect_instance(target.clone())
            .expect("libvirt connection checked"),
        instance: target,
        domain_uuid,
        source: PreparedBaseArtifact {
            path: std::path::PathBuf::new(),
            file_bytes: 0,
            capacity_bytes: 0,
            kali_proof: None,
            whonix_gateway_proof: None,
            whonix_workstation_proof: None,
            promoted_workstation: None,
        },
        layout,
        workstation_pair_snapshot: None,
        base_created: false,
        overlay_created: false,
        clone_source: Some(source),
    };
    match forge_storage::execute_generic_create(
        &mut backend,
        &forge_storage::GenericCreateExecutionPlan {
            factory,
            created_unix_seconds,
            domain_xml: xml,
        },
    ) {
        Ok(result) => {
            println!("Active generation: {}", result.index.active_generation_id);
            println!(
                "Persistent clone created shut off; guest-level identity remains subject to the documented policy."
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("persistent clone failed: {error}");
            ExitCode::from(1)
        }
    }
}

fn rebuild_vm_dry_run() -> ExitCode {
    eprintln!("rebuild refused: {LEGACY_FEDORA_RETIRED}");
    return ExitCode::from(1);
    #[allow(unreachable_code)]
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

fn rebuild_instance_dry_run(instance_name: &str) -> ExitCode {
    if instance_name == "fedora-lab" {
        return rebuild_vm_dry_run();
    }
    let operational = match operational_instance(instance_name) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("rebuild refused: {error}");
            return ExitCode::from(1);
        }
    };
    let flat_clone = operational.active.resources.len() == 1
        && operational.active.resources[0].role == forge_state::ResourceRole::WritableOverlay
        && operational.active.resources[0].backing_path.is_none();
    if flat_clone {
        eprintln!("rebuild unsupported for flat clone: {instance_name}");
    } else {
        eprintln!("rebuild unsupported for profile-bound instance: {instance_name}");
    }
    ExitCode::from(1)
}

fn rebuild_vm() -> ExitCode {
    eprintln!("rebuild refused: {LEGACY_FEDORA_RETIRED}");
    return ExitCode::from(1);
    #[allow(unreachable_code)]
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
    let _ = dry_run;
    eprintln!("managed rebuild refused: {LEGACY_FEDORA_RETIRED}");
    return ExitCode::from(1);
    #[allow(unreachable_code)]
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
        forge_state::ManagedState::InitialCreateRecoveryRequired(_) => {
            eprintln!("managed rebuild refused: initial create recovery is required");
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
    let _ = dry_run;
    eprintln!("boot refused: {LEGACY_FEDORA_RETIRED}");
    return ExitCode::from(1);
    #[allow(unreachable_code)]
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
    let _ = dry_run;
    eprintln!("prepare refused: {LEGACY_FEDORA_RETIRED}");
    return ExitCode::from(1);
    #[allow(unreachable_code)]
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
            println!("PROFILE / IMAGE\tRELEASE\tARCH\tSTATUS\tTRUST / VERIFICATION\tGENERATION");
            let source = forge_images::resolve_fedora_workstation_iso(
                forge_images::FEDORA_WORKSTATION_RELEASE,
                forge_images::FEDORA_WORKSTATION_COMPOSE,
                forge_images::FedoraIsoArchitecture::X86_64,
                forge_images::FedoraArtifactClass::WorkstationLiveIso,
            )
            .expect("built-in Workstation source must be valid");
            let workstation_status =
                match forge_images::inspect_fedora_workstation_iso(&directories, &source) {
                    Ok(forge_images::FedoraWorkstationIsoState::Missing { .. }) => "Missing",
                    Ok(forge_images::FedoraWorkstationIsoState::Verified(_)) => "Verified",
                    Ok(forge_images::FedoraWorkstationIsoState::Conflict(_)) => "Conflict",
                    Err(_) => "Invalid",
                };
            let workstation_generation = workstation_inventory_generation();
            println!(
                "fedora-workstation / {}\t{}\tx86_64\t{workstation_status}\t{}\t{workstation_generation}",
                forge_images::FEDORA_WORKSTATION_PRODUCT_LABEL,
                source.release(),
                if workstation_status == "Verified" {
                    "signed CHECKSUM verified"
                } else {
                    "not verified"
                }
            );
            for image in images {
                println!(
                    "fedora-lab / Fedora Cloud Base (legacy)\t{}\t{}\t{}\tlegacy / retired\tn/a",
                    image.release, image.architecture, image.status
                );
            }
            print_kali_inventory(&directories);
            print_whonix_inventory(
                "whonix-gateway",
                forge_images::inspect_whonix_gateway_inventory(&directories),
            );
            print_whonix_inventory(
                "whonix-workstation",
                forge_images::inspect_whonix_workstation_inventory(&directories),
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("image listing failed: {error}");
            ExitCode::from(1)
        }
    }
}

fn workstation_inventory_generation() -> String {
    let Ok(path) = workstation_preparation_state_path() else {
        return "preparation state unavailable".to_owned();
    };
    let Ok(Some(preparation)) = forge_images::read_fedora_workstation_preparation(&path) else {
        return "not prepared".to_owned();
    };
    workstation_inventory_generation_from_evidence(
        preparation.status,
        exact_workstation_source(&preparation),
        preparation.execution.host_only_promotion.is_some(),
        preparation.execution.host_only_canonical.is_some(),
    )
}

fn workstation_inventory_generation_from_evidence(
    status: forge_images::FedoraWorkstationPreparationStatus,
    exact_source: bool,
    promotion_evidence: bool,
    canonical_evidence: bool,
) -> String {
    if status == forge_images::FedoraWorkstationPreparationStatus::Promoted
        && exact_source
        && promotion_evidence
        && canonical_evidence
    {
        "promoted canonical base (durable evidence)".to_owned()
    } else {
        format!("preparation stage {status:?}")
    }
}

fn recorded_inventory_fields(
    state: Result<forge_images::RecordedPreparationState, forge_images::ImageError>,
) -> (&'static str, &'static str, String) {
    match state {
        Ok(forge_images::RecordedPreparationState::Missing) => {
            ("Missing", "not acquired", "not prepared".to_owned())
        }
        Ok(forge_images::RecordedPreparationState::Preparing) => (
            "Preparing",
            "recorded state incomplete",
            "not prepared".to_owned(),
        ),
        Ok(forge_images::RecordedPreparationState::Interrupted) => (
            "Interrupted",
            "recorded state incomplete",
            "recovery required".to_owned(),
        ),
        Ok(forge_images::RecordedPreparationState::Orphaned) => {
            ("Orphaned", "not trusted", "recovery required".to_owned())
        }
        Ok(forge_images::RecordedPreparationState::RecordedVerified) => (
            "RecordedVerified",
            "durable recorded verification; not freshly reverified",
            "prepared artifact".to_owned(),
        ),
        Ok(forge_images::RecordedPreparationState::Conflict(reason)) => {
            ("Conflict", "not trusted", reason)
        }
        Err(_) => (
            "Invalid",
            "inspection failed",
            "recovery required".to_owned(),
        ),
    }
}

fn print_kali_inventory(directories: &forge_images::ImageDirectories) {
    let (status, trust, generation) =
        recorded_inventory_fields(forge_images::inspect_kali_inventory(directories));
    println!(
        "kali-lab / Kali QEMU\t{}\tx86_64\t{status}\t{trust}\t{generation}",
        forge_images::KALI_RELEASE
    );
}

fn print_whonix_inventory(
    profile: &str,
    state: Result<forge_images::RecordedPreparationState, forge_images::ImageError>,
) {
    let (status, trust, generation) = recorded_inventory_fields(state);
    println!(
        "{profile} / Whonix bundle role\t{}\tx86_64\t{status}\t{trust}\t{generation}",
        forge_images::WHONIX_RELEASE
    );
}

fn image_inspect_kali() -> ExitCode {
    let Ok(directories) = image_directories() else {
        return ExitCode::from(2);
    };
    println!("Product: Kali Lab");
    println!("Artifact class: Kali QEMU archive with one qcow2 member");
    println!("Release: {}", forge_images::KALI_RELEASE);
    println!("Architecture: x86_64");
    println!("Source: {}", forge_images::KALI_SOURCE_URL);
    println!(
        "Archive: {}",
        directories
            .downloads
            .join(forge_images::KALI_ARCHIVE_FILENAME)
            .display()
    );
    println!(
        "Prepared image: {}",
        directories
            .images
            .join(forge_images::KALI_QCOW2_FILENAME)
            .display()
    );
    println!(
        "Signing key: {}",
        forge_images::KALI_SIGNING_KEY_FINGERPRINT
    );
    println!(
        "Verification chain: detached signature → authenticated SHA256SUMS → archive checksum → extracted qcow2 checksum"
    );
    match forge_images::inspect_kali_preparation(&directories) {
        Ok(forge_images::KaliPreparationState::Verified(metadata)) => {
            println!("Status: Verified");
            println!(
                "Archive SHA-256: {}",
                metadata
                    .actual_archive_checksum
                    .as_deref()
                    .unwrap_or("unavailable")
            );
            println!(
                "Prepared qcow2 SHA-256: {}",
                metadata
                    .prepared_qcow2_checksum
                    .as_deref()
                    .unwrap_or("unavailable")
            );
            println!("Trusted prepared base: yes");
            println!("Next: forge vm create kali-lab <instance>");
            ExitCode::SUCCESS
        }
        Ok(state) => {
            println!("Status: {state:?}");
            println!("Trusted prepared base: no");
            println!("Next: forge image fetch kali");
            kali_inspect_exit_code(&state)
        }
        Err(error) => {
            eprintln!("Kali image inspection failed: {error}");
            ExitCode::from(1)
        }
    }
}

fn kali_inspect_exit_code(state: &forge_images::KaliPreparationState) -> ExitCode {
    match state {
        forge_images::KaliPreparationState::Verified(_)
        | forge_images::KaliPreparationState::Missing
        | forge_images::KaliPreparationState::Preparing => ExitCode::SUCCESS,
        forge_images::KaliPreparationState::Conflict(_)
        | forge_images::KaliPreparationState::OrphanedPreparedImage
        | forge_images::KaliPreparationState::InterruptedPreparation => ExitCode::from(1),
    }
}

fn image_fetch_kali() -> ExitCode {
    let Ok(directories) = image_directories() else {
        return ExitCode::from(2);
    };
    println!(
        "Acquiring and preparing official Kali QEMU image {}...",
        forge_images::KALI_RELEASE
    );
    println!("Source: {}", forge_images::KALI_SOURCE_URL);
    println!(
        "Verification: detached SHA256SUMS signature with pinned key {}",
        forge_images::KALI_SIGNING_KEY_FINGERPRINT
    );
    match forge_images::fetch_kali(&directories, &mut forge_images::SystemArtifactFetcher) {
        Ok(metadata) => {
            println!("Status: Verified");
            println!("Prepared qcow2: {}", metadata.prepared_qcow2_path.display());
            println!(
                "Archive SHA-256: {}",
                metadata
                    .actual_archive_checksum
                    .as_deref()
                    .unwrap_or("unavailable")
            );
            println!(
                "Prepared qcow2 SHA-256: {}",
                metadata
                    .prepared_qcow2_checksum
                    .as_deref()
                    .unwrap_or("unavailable")
            );
            println!("Shared libvirt base: created/reused during forge vm create");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Kali image fetch failed: {error}");
            ExitCode::from(1)
        }
    }
}

fn workstation_source() -> forge_images::FedoraWorkstationIsoSource {
    forge_images::resolve_fedora_workstation_iso(
        forge_images::FEDORA_WORKSTATION_RELEASE,
        forge_images::FEDORA_WORKSTATION_COMPOSE,
        forge_images::FedoraIsoArchitecture::X86_64,
        forge_images::FedoraArtifactClass::WorkstationLiveIso,
    )
    .expect("built-in Workstation source must be valid")
}

fn image_inspect_workstation() -> ExitCode {
    let Ok(directories) = image_directories() else {
        return ExitCode::from(2);
    };
    let source = workstation_source();
    println!("Product: Fedora Workstation");
    println!("Artifact class: Workstation Live ISO");
    println!("Release: {}", source.release());
    println!("Compose: {}", source.compose());
    println!("Architecture: {}", source.architecture());
    println!("Expected filename: {}", source.filename());
    println!("Signing key: {}", source.signing_key_fingerprint());
    match forge_images::inspect_fedora_workstation_iso(&directories, &source) {
        Ok(forge_images::FedoraWorkstationIsoState::Missing { local_path, .. }) => {
            println!("Local ISO: {}", local_path.display());
            println!("Verification status: Missing");
            println!("Signed CHECKSUM: Not verified");
            println!("SHA-256: unavailable until signed CHECKSUM verification");
        }
        Ok(forge_images::FedoraWorkstationIsoState::Verified(metadata)) => {
            println!("Local ISO: {}", metadata.local_path.display());
            println!("Verification status: Verified");
            println!("Signed CHECKSUM: Verified");
            println!("SHA-256: {}", metadata.sha256);
            println!("Bytes: {}", metadata.byte_size);
        }
        Ok(forge_images::FedoraWorkstationIsoState::Conflict(reason)) => {
            println!("Verification status: Conflict");
            eprintln!("{reason}");
            return ExitCode::from(1);
        }
        Err(error) => {
            eprintln!("Workstation ISO inspection failed: {error}");
            return ExitCode::from(1);
        }
    }
    match resolve_promoted_workstation_base() {
        Ok(base) => {
            println!("Canonical base: {}", base.volume.name);
            println!("Canonical status: Prepared");
            println!("Canonical proof: Verified");
        }
        Err(error) if error == "no Promoted Fedora Workstation preparation exists" => {
            println!("Canonical base: Not prepared");
        }
        Err(error) if error == "Fedora Workstation preparation is not Promoted" => {
            match workstation_preparation_state_path()
                .ok()
                .and_then(|path| forge_images::read_fedora_workstation_preparation(&path).ok())
                .flatten()
            {
                Some(preparation) => {
                    println!("Canonical base: Not prepared");
                    println!(
                        "Canonical status: preparation stage {:?}",
                        preparation.status
                    );
                }
                None => println!("Canonical base: Not prepared"),
            }
        }
        Err(error) => {
            println!("Canonical base: Recovery required");
            eprintln!("Promoted canonical proof failed: {error}");
            return ExitCode::from(1);
        }
    }
    ExitCode::SUCCESS
}

fn image_fetch_workstation() -> ExitCode {
    let Ok(directories) = image_directories() else {
        return ExitCode::from(2);
    };
    let source = workstation_source();
    println!(
        "Fetching official Fedora Workstation {} {} Live ISO...",
        source.release(),
        source.architecture()
    );
    let mut fetcher = forge_images::SystemArtifactFetcher;
    match forge_images::fetch_fedora_workstation_iso(&directories, &source, &mut fetcher) {
        Ok(proof) => {
            let metadata = proof.metadata();
            println!("Verified ISO: {}", metadata.local_path.display());
            println!("SHA-256: {}", metadata.sha256);
            println!("Signing key: {}", metadata.signing_key_fingerprint);
            println!("Canonical base: Not prepared");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Fedora Workstation ISO fetch failed: {error}");
            ExitCode::from(1)
        }
    }
}

fn image_prepare_workstation_dry_run() -> ExitCode {
    let Ok(directories) = image_directories() else {
        return ExitCode::from(2);
    };
    let source = workstation_source();
    let source_status = match forge_images::inspect_fedora_workstation_iso(&directories, &source) {
        Ok(forge_images::FedoraWorkstationIsoState::Verified(_)) => "verified",
        Ok(forge_images::FedoraWorkstationIsoState::Missing { .. }) => {
            "acquisition required (not downloaded by dry-run)"
        }
        Ok(forge_images::FedoraWorkstationIsoState::Conflict(_)) => "conflict; preparation refused",
        Err(_) => "invalid; preparation refused",
    };
    println!("Mode: Fedora Workstation preparation dry-run");
    println!(
        "Source: Fedora Workstation {} compose {} {} ({source_status})",
        source.release(),
        source.compose(),
        source.architecture()
    );
    println!("Installer: operator-assisted Anaconda in a temporary preparation-owned domain");
    println!("Installer topology: Q35, UEFI, virtio network, SPICE, virtio-gpu, keyboard/tablet");
    println!(
        "Staging disk: forge-stage-fedora-workstation-{}-{}-<transaction>.qcow2",
        source.release(),
        source.compose()
    );
    println!(
        "Staging capacity: {} GiB, sparse qcow2, no backing, preparation-owned",
        forge_images::FEDORA_WORKSTATION_STAGING_CAPACITY_BYTES / 1024 / 1024 / 1024
    );
    println!("NoCloud: none");
    println!("Cloud-init: none");
    println!("SSH requirement: none");
    println!("QGA requirement: none");
    println!("Normalization: none (operator-assisted installation gate only)");
    println!("Promotion: exact copy/import to image-store-owned protected SharedBase");
    println!(
        "Canonical base: forge-base-fedora-workstation-{}-{}.qcow2 (not created)",
        source.release(),
        source.compose()
    );
    println!("Mutation: false");
    ExitCode::SUCCESS
}

fn workstation_preparation_state_path() -> Result<std::path::PathBuf, String> {
    let home = env::var_os("HOME").ok_or_else(|| "HOME is unavailable".to_owned())?;
    let home = std::path::Path::new(&home);
    let legacy = forge_images::fedora_workstation_preparation_state_path(home);
    let pointer = legacy.with_file_name("fedora-workstation-44-1.7.active");
    match std::fs::read_to_string(&pointer) {
        Ok(value) => {
            let path = std::path::PathBuf::from(value.trim());
            if path.is_absolute() && path.starts_with(legacy.parent().unwrap_or(home)) {
                Ok(path)
            } else {
                Err("active Fedora preparation pointer is unsafe".to_owned())
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(legacy),
        Err(error) => Err(format!(
            "cannot read active Fedora preparation pointer: {error}"
        )),
    }
}

fn publish_workstation_active_pointer(path: &std::path::Path) -> Result<(), String> {
    let state = workstation_preparation_state_path()?;
    let pointer = state
        .parent()
        .ok_or_else(|| "preparation state has no parent".to_owned())?
        .join("fedora-workstation-44-1.7.active");
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&pointer)
        .map_err(|error| format!("cannot publish active preparation pointer: {error}"))?;
    writeln!(file, "{}", path.display()).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())
}

trait WorkstationAbortBackend {
    fn canonical_base_exists(&mut self, name: &str) -> Result<bool, String>;
    fn inspect_domain(
        &mut self,
        name: &str,
    ) -> Result<Option<forge_images::InstallerDomainEvidence>, String>;
    fn inspect_volume(
        &mut self,
        name: &str,
    ) -> Result<Option<forge_images::PreparationVolumeEvidence>, String>;
    fn stream_installer_iso_digest(
        &mut self,
        name: &str,
        expected_bytes: u64,
    ) -> Result<(forge_images::PreparationVolumeEvidence, u64, String), String>;
    fn undefine_domain_exact(
        &mut self,
        expected: &forge_libvirt::ExactDomainIdentity,
    ) -> Result<(), String>;
    fn domain_absent(
        &mut self,
        expected: &forge_libvirt::ExactDomainIdentity,
    ) -> Result<bool, String>;
    fn delete_volume_exact(
        &mut self,
        expected: &forge_state::ManagedResource,
    ) -> Result<(), String>;
    fn verify_volume_absent(
        &mut self,
        expected: &forge_state::ManagedResource,
    ) -> Result<(), String>;
}

struct LibvirtWorkstationAbortBackend {
    define: forge_libvirt::LibvirtDefineBackend,
    boot: forge_libvirt::LibvirtBootBackend,
}

impl LibvirtWorkstationAbortBackend {
    fn connect() -> Result<Self, String> {
        Ok(Self {
            define: forge_libvirt::LibvirtDefineBackend::connect_local()
                .map_err(|error| error.to_string())?,
            boot: forge_libvirt::LibvirtBootBackend::connect_local()
                .map_err(|error| error.to_string())?,
        })
    }
}

impl WorkstationAbortBackend for LibvirtWorkstationAbortBackend {
    fn canonical_base_exists(&mut self, name: &str) -> Result<bool, String> {
        self.define.canonical_base_exists("default", name)
    }

    fn inspect_domain(
        &mut self,
        name: &str,
    ) -> Result<Option<forge_images::InstallerDomainEvidence>, String> {
        self.define.inspect_installer_domain(name)
    }

    fn inspect_volume(
        &mut self,
        name: &str,
    ) -> Result<Option<forge_images::PreparationVolumeEvidence>, String> {
        FedoraWorkstationPreparationBackend::inspect_volume(&mut self.define, "default", name)
    }

    fn stream_installer_iso_digest(
        &mut self,
        name: &str,
        expected_bytes: u64,
    ) -> Result<(forge_images::PreparationVolumeEvidence, u64, String), String> {
        FedoraWorkstationPreparationBackend::stream_installer_iso_digest(
            &mut self.define,
            "default",
            name,
            expected_bytes,
        )
    }

    fn undefine_domain_exact(
        &mut self,
        expected: &forge_libvirt::ExactDomainIdentity,
    ) -> Result<(), String> {
        self.define
            .undefine_domain_exact(expected)
            .map_err(|error| error.to_string())
    }

    fn domain_absent(
        &mut self,
        expected: &forge_libvirt::ExactDomainIdentity,
    ) -> Result<bool, String> {
        Ok(matches!(
            self.define
                .observe_domain_for_delete(expected)
                .map_err(|error| error.to_string())?,
            forge_libvirt::DomainDeleteObservation::Absent
        ))
    }

    fn delete_volume_exact(
        &mut self,
        expected: &forge_state::ManagedResource,
    ) -> Result<(), String> {
        self.boot
            .delete_managed_volume_exact(expected)
            .map_err(|error| error.to_string())
    }

    fn verify_volume_absent(
        &mut self,
        expected: &forge_state::ManagedResource,
    ) -> Result<(), String> {
        self.boot
            .verify_managed_volume_absent(expected)
            .map_err(|error| error.to_string())
    }
}

fn preparation_managed_resource(
    volume_name: &str,
    volume_key: &str,
    path: &std::path::Path,
    format: &str,
    capacity_bytes: u64,
) -> Result<forge_state::ManagedResource, String> {
    Ok(forge_state::ManagedResource {
        role: forge_state::ResourceRole::WritableOverlay,
        volume_name: volume_name.to_owned(),
        volume_key: volume_key.to_owned(),
        path: path
            .to_str()
            .ok_or_else(|| "preparation volume path is not UTF-8".to_owned())?
            .to_owned(),
        format: format.to_owned(),
        capacity_bytes,
        backing_path: None,
    })
}

fn validate_abort_preparation(
    preparation: &forge_images::FedoraWorkstationPreparation,
    requested_id: &str,
) -> Result<(), String> {
    if preparation.preparation_id.as_str() != requested_id {
        return Err("selected preparation ID differs from requested abort ID".to_owned());
    }
    if matches!(
        preparation.status,
        forge_images::FedoraWorkstationPreparationStatus::PromotionReady
            | forge_images::FedoraWorkstationPreparationStatus::Promoted
    ) {
        return Err(
            "Fedora Workstation preparation has reached promotion and cannot be aborted".to_owned(),
        );
    }
    Ok(())
}

fn abort_workstation_preparation<B: WorkstationAbortBackend>(
    backend: &mut B,
    preparation: &forge_images::FedoraWorkstationPreparation,
    requested_id: &str,
) -> Result<(), String> {
    validate_abort_preparation(preparation, requested_id)?;
    if backend.canonical_base_exists(&preparation.canonical.volume_name)? {
        return Err("canonical Fedora Workstation shared base exists; abort refused".to_owned());
    }
    let domain = backend
        .inspect_domain(&preparation.installer.name)?
        .ok_or_else(|| "preparation domain is absent; abort refused".to_owned())?;
    if domain.name != preparation.installer.name || domain.uuid != preparation.installer.uuid {
        return Err("preparation domain identity mismatch".to_owned());
    }
    if !domain.persistent || !domain.shutoff {
        return Err(
            "preparation domain must be persistent and shut off; abort will not stop it".to_owned(),
        );
    }
    forge_images::prove_fedora_workstation_abort_disk_binding(preparation, &domain)
        .map_err(|error| format!("preparation primary disk mismatch: {error}"))?;

    let staging = backend
        .inspect_volume(&preparation.staging.volume_name)?
        .ok_or_else(|| "preparation staging volume is absent; abort refused".to_owned())?;
    let staging_key = preparation
        .execution
        .staging_volume_key
        .as_deref()
        .ok_or_else(|| "preparation staging volume key was never durably recorded".to_owned())?;
    if staging.name != preparation.staging.volume_name
        || staging.key != staging_key
        || staging.path != preparation.staging.path
        || staging.format != preparation.staging.format
        || staging.capacity_bytes != preparation.staging.capacity_bytes
        || staging.backing_path != preparation.staging.backing_path
    {
        return Err("preparation staging volume identity mismatch".to_owned());
    }
    let staging_resource = preparation_managed_resource(
        &staging.name,
        &staging.key,
        &staging.path,
        &staging.format,
        staging.capacity_bytes,
    )?;

    let runtime_resource = if let Some(runtime) = preparation.execution.runtime_iso.as_ref() {
        let (volume, bytes, digest) =
            backend.stream_installer_iso_digest(&runtime.volume_name, runtime.destination_bytes)?;
        if runtime.preparation_id != preparation.preparation_id
            || volume.name != runtime.volume_name
            || volume.key != runtime.volume_key
            || volume.path != runtime.path
            || !matches!(volume.format.as_str(), "raw" | "iso")
            || volume.capacity_bytes != runtime.destination_bytes
            || volume.backing_path.is_some()
            || bytes != runtime.destination_bytes
            || digest != runtime.destination_sha256
            || runtime.source_sha256 != runtime.destination_sha256
            || runtime.source_bytes != runtime.destination_bytes
        {
            return Err("managed installer ISO identity or digest mismatch".to_owned());
        }
        Some(preparation_managed_resource(
            &volume.name,
            &volume.key,
            &volume.path,
            &volume.format,
            volume.capacity_bytes,
        )?)
    } else {
        None
    };

    let domain_identity = forge_libvirt::ExactDomainIdentity {
        name: preparation.installer.name.clone(),
        uuid: preparation.installer.uuid.clone(),
    };
    backend.undefine_domain_exact(&domain_identity)?;
    if !backend.domain_absent(&domain_identity)? {
        return Err("preparation domain remains after exact undefine".to_owned());
    }
    backend.delete_volume_exact(&staging_resource)?;
    backend.verify_volume_absent(&staging_resource)?;
    if let Some(runtime) = runtime_resource {
        backend.delete_volume_exact(&runtime)?;
        backend.verify_volume_absent(&runtime)?;
    }
    Ok(())
}

fn retire_workstation_preparation_state(path: &std::path::Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "preparation state has no parent".to_owned())?;
    let pointer = parent.join("fedora-workstation-44-1.7.active");
    if let Ok(value) = std::fs::read_to_string(&pointer) {
        if std::path::Path::new(value.trim()) == path {
            std::fs::remove_file(&pointer)
                .map_err(|error| format!("cannot retire active preparation pointer: {error}"))?;
        }
    }
    std::fs::remove_file(path).map_err(|error| format!("cannot retire preparation state: {error}"))
}

fn validate_workstation_active_pointer(path: &std::path::Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "preparation state has no parent".to_owned())?;
    let pointer = parent.join("fedora-workstation-44-1.7.active");
    match std::fs::read_to_string(&pointer) {
        Ok(value) if std::path::Path::new(value.trim()) == path => Ok(()),
        Ok(_) => Err("active preparation pointer identifies a different state file".to_owned()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("cannot read active preparation pointer: {error}")),
    }
}

fn image_abort_workstation(requested_id: &str) -> ExitCode {
    let result = (|| -> Result<(), String> {
        let state_path = workstation_preparation_state_path()?;
        let preparation = forge_images::read_fedora_workstation_preparation(&state_path)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "no active Fedora Workstation preparation exists".to_owned())?;
        validate_workstation_active_pointer(&state_path)?;
        println!(
            "Preparation selected: {}",
            preparation.preparation_id.as_str()
        );
        let mut backend = LibvirtWorkstationAbortBackend::connect()?;
        println!("Validation: exact durable identities required");
        abort_workstation_preparation(&mut backend, &preparation, requested_id)?;
        println!("Domain retired: {}", preparation.installer.name);
        println!("Staging retired: {}", preparation.staging.volume_name);
        println!(
            "Managed installer ISO retired: {}",
            if preparation.execution.runtime_iso.is_some() {
                "yes"
            } else {
                "not present"
            }
        );
        retire_workstation_preparation_state(&state_path)?;
        println!("Durable state retired: {}", state_path.display());
        println!("Abort completed");
        Ok(())
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Fedora Workstation preparation abort refused: {error}");
            ExitCode::from(1)
        }
    }
}

fn new_preparation_identity() -> Result<forge_images::FedoraWorkstationPreparationId, String> {
    let value = forge_state::new_generation_id()
        .strip_prefix("gen-")
        .ok_or_else(|| "generated identity has unexpected shape".to_owned())?
        .replace('-', "");
    forge_images::FedoraWorkstationPreparationId::new(value).map_err(|error| error.to_string())
}

fn new_domain_uuid() -> Result<String, String> {
    forge_state::new_generation_id()
        .strip_prefix("gen-")
        .map(str::to_owned)
        .ok_or_else(|| "generated domain UUID has unexpected shape".to_owned())
}

fn exact_workstation_source(preparation: &forge_images::FedoraWorkstationPreparation) -> bool {
    let source = workstation_source();
    preparation.source.release == source.release()
        && preparation.source.compose == source.compose()
        && preparation.source.architecture == source.architecture()
        && preparation.source.filename == source.filename()
        && preparation.source.iso_sha256 == forge_images::FEDORA_WORKSTATION_ISO_SHA256
        && preparation.source.iso_bytes == forge_images::FEDORA_WORKSTATION_ISO_BYTES
        && preparation.source.signing_key_fingerprint == source.signing_key_fingerprint()
}

#[allow(clippy::too_many_lines)]
fn image_prepare_workstation() -> ExitCode {
    let total_started = Instant::now();
    let result = (|| -> Result<(), String> {
        let directories = forge_images::default_directories()
            .ok_or_else(|| "Forge image directories are unavailable".to_owned())?;
        let mut state_path = workstation_preparation_state_path()?;
        let mut backend = forge_libvirt::LibvirtDefineBackend::connect_local()
            .map_err(|error| error.to_string())?;
        if let Some(mut preparation) =
            forge_images::read_fedora_workstation_preparation(&state_path)
                .map_err(|error| error.to_string())?
        {
            if preparation.preparation_id.as_str() == "5d87db391be74e86bd0c7dca042295c3" {
                let fresh = new_preparation_identity()?;
                let parent = state_path
                    .parent()
                    .ok_or_else(|| "preparation state has no parent".to_owned())?;
                state_path =
                    parent.join(format!("fedora-workstation-44-1.7-{}.json", fresh.as_str()));
            } else {
                if !exact_workstation_source(&preparation) {
                    return Err("active preparation has conflicting source provenance".to_owned());
                }
                let proof = forge_images::verified_fedora_workstation_iso(
                    &directories,
                    &workstation_source(),
                )
                .map_err(|error| format!("existing ISO proof is stale: {error}"))?;
                if proof.metadata().local_path != preparation.source.iso_path
                    || proof.metadata().sha256 != preparation.source.iso_sha256
                    || proof.metadata().byte_size != preparation.source.iso_bytes
                {
                    return Err("existing ISO proof differs from preparation authority".to_owned());
                }
                let disposition = forge_images::execute_to_installer_ready(
                    &mut backend,
                    &mut preparation,
                    |value| {
                        forge_images::update_fedora_workstation_preparation(&state_path, value)
                            .map_err(|error| error.to_string())
                    },
                )
                .map_err(|error| error.to_string())?;
                println!("Preparation: {disposition:?}");
                print_workstation_preparation_ready(&preparation);
                return Ok(());
            }
        }

        let source = workstation_source();
        let acquisition_started = Instant::now();
        let mut fetcher = forge_images::SystemArtifactFetcher;
        let proof = forge_images::fetch_fedora_workstation_iso(&directories, &source, &mut fetcher)
            .map_err(|error| error.to_string())?;
        let acquisition_elapsed = acquisition_started.elapsed();
        let hash_started = Instant::now();
        forge_images::revalidate_fedora_workstation_iso_proof(&proof)
            .map_err(|error| error.to_string())?;
        let hash_elapsed = hash_started.elapsed();

        let pool = FedoraWorkstationPreparationBackend::inspect_pool(&mut backend, "default")?;
        if !pool.active {
            return Err("default storage pool is inactive".to_owned());
        }
        let preparation_id = new_preparation_identity()?;
        let suffix = &preparation_id.as_str()[..8];
        let staging_name = format!(
            "forge-stage-fedora-workstation-{}-{}-{suffix}.qcow2",
            source.release(),
            source.compose()
        );
        let installer_name = format!(
            "forge-prepare-fedora-workstation-{}-{}-{suffix}",
            source.release(),
            source.compose()
        );
        let canonical_name = format!(
            "forge-base-fedora-workstation-{}-{}.qcow2",
            source.release(),
            source.compose()
        );
        let collisions = forge_images::PreparationCollisions {
            active_transaction: false,
            staging_disk: FedoraWorkstationPreparationBackend::inspect_volume(
                &mut backend,
                "default",
                &staging_name,
            )?
            .is_some(),
            installer_domain: backend.inspect_installer_domain(&installer_name)?.is_some(),
            canonical_base: backend.canonical_base_exists("default", &canonical_name)?,
        };
        let plan = forge_images::plan_fedora_workstation_preparation(
            Some(&proof),
            preparation_id,
            &new_domain_uuid()?,
            &pool.target_path,
            &pool.target_path,
            collisions,
        )
        .map_err(|error| error.to_string())?;
        let mut preparation = forge_images::durable_preparation(plan);
        forge_images::publish_new_fedora_workstation_preparation(&state_path, &preparation)
            .map_err(|error| error.to_string())?;
        if state_path.file_name().and_then(|name| name.to_str())
            != Some("fedora-workstation-44-1.7.json")
        {
            publish_workstation_active_pointer(&state_path)?;
        }
        let execution_started = Instant::now();
        let disposition =
            forge_images::execute_to_installer_ready(&mut backend, &mut preparation, |value| {
                forge_images::update_fedora_workstation_preparation(&state_path, value)
                    .map_err(|error| error.to_string())
            })
            .map_err(|error| error.to_string())?;
        println!("Preparation: {disposition:?}");
        println!("ISO acquisition bytes: {}", proof.metadata().byte_size);
        println!(
            "ISO acquisition/proof elapsed: {:.3}s",
            acquisition_elapsed.as_secs_f64()
        );
        println!(
            "ISO identity revalidation bytes: {}",
            proof.metadata().byte_size
        );
        println!(
            "ISO identity revalidation elapsed: {:.3}s",
            hash_elapsed.as_secs_f64()
        );
        println!(
            "Staging/domain execution elapsed: {:.3}s",
            execution_started.elapsed().as_secs_f64()
        );
        print_workstation_preparation_ready(&preparation);
        Ok(())
    })();
    match result {
        Ok(()) => {
            println!(
                "Total preparation elapsed: {:.3}s",
                total_started.elapsed().as_secs_f64()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Fedora Workstation preparation failed: {error}");
            eprintln!("No automatic cleanup was attempted; inspect prepare-status for recovery.");
            ExitCode::from(1)
        }
    }
}

fn print_workstation_preparation_ready(preparation: &forge_images::FedoraWorkstationPreparation) {
    println!("Preparation ID: {}", preparation.preparation_id.as_str());
    println!("Source ISO verified: yes");
    println!("Source ISO: {}", preparation.source.iso_path.display());
    println!("Staging disk: {}", preparation.staging.path.display());
    println!("Installer domain: {}", preparation.installer.name);
    println!("Current stage: {:?}", preparation.status);
    println!("Installer domain state: shut off");
    println!("Canonical base: not prepared");
    println!("Fedora Workstation installer environment is ready.");
    println!(
        "Open the temporary installer domain in virt-manager and complete normal graphical installation."
    );
    println!(
        "Before starting the installer with Forge, run: forge image prepare-start fedora-workstation"
    );
}

fn workstation_preparation_next_action(
    status: forge_images::FedoraWorkstationPreparationStatus,
) -> &'static str {
    use forge_images::FedoraWorkstationPreparationStatus as Status;

    match status {
        Status::InstallerReady => {
            "If installation was performed manually or outside Forge and the VM is shut off, run: forge image prepare-confirm-installed fedora-workstation"
        }
        Status::InstallerRunning => {
            "Complete graphical Anaconda, shut down the VM, then run: forge image prepare-continue fedora-workstation"
        }
        Status::InstallationConfirmed | Status::InstalledDiskBootPending => {
            "Run: forge image prepare-continue fedora-workstation"
        }
        Status::InstalledDiskBooting => {
            "Wait for the installed system to reach graphical first boot, then run: forge image prepare-confirm-graphical fedora-workstation"
        }
        Status::AwaitingGraphicalBootConfirmation => {
            "Confirm the running graphical installed system with: forge image prepare-confirm-graphical fedora-workstation"
        }
        Status::InstalledSystemProven => {
            "Graphical proof is complete. Shut down the preparation guest normally, then run: forge image prepare-promote fedora-workstation"
        }
        _ => "Inspect the durable preparation state before taking another action.",
    }
}

fn installed_disk_boot_message(
    disposition: forge_images::InstalledDiskBootDisposition,
) -> &'static str {
    match disposition {
        forge_images::InstalledDiskBootDisposition::DiskOnlyPrepared => {
            "Installed system: disk-only topology prepared; domain not started"
        }
        forge_images::InstalledDiskBootDisposition::Started
        | forge_images::InstalledDiskBootDisposition::AlreadyRunning => {
            "Installed system: running from preparation staging disk"
        }
    }
}

fn workstation_status_expects_running_domain(
    status: forge_images::FedoraWorkstationPreparationStatus,
) -> bool {
    matches!(
        status,
        forge_images::FedoraWorkstationPreparationStatus::InstalledDiskBooting
            | forge_images::FedoraWorkstationPreparationStatus::AwaitingGraphicalBootConfirmation
            | forge_images::FedoraWorkstationPreparationStatus::InstalledSystemProven
            | forge_images::FedoraWorkstationPreparationStatus::NormalizationPlanned
            | forge_images::FedoraWorkstationPreparationStatus::NormalizationRunning
            | forge_images::FedoraWorkstationPreparationStatus::NormalizationGuestComplete
    )
}

fn prove_promoted_workstation_status(
    preparation_id: &forge_images::FedoraWorkstationPreparationId,
    canonical_plan: &forge_images::CanonicalWorkstationBasePlan,
    promotion: Option<&forge_images::HostOnlyPromotionEvidence>,
    canonical: Option<&forge_images::HostOnlyCanonicalEvidence>,
    canonical_volume: &forge_images::PreparationVolumeEvidence,
    canonical_proof: &forge_images::Qcow2VolumeProof,
    canonical_protected: bool,
    staging_present: bool,
    preparation_domain_present: bool,
) -> Result<(), String> {
    let promotion = promotion
        .ok_or_else(|| "host-only promotion evidence absent; recovery required".to_owned())?;
    let canonical = canonical
        .ok_or_else(|| "canonical publication evidence absent; recovery required".to_owned())?;
    if promotion.preparation_id != *preparation_id
        || canonical.staging_sha256 != promotion.staging_sha256
        || canonical.staging_streamed_bytes != promotion.staging_streamed_bytes
        || canonical.canonical_volume_name != canonical_plan.volume_name
        || canonical.canonical_path != canonical_plan.path
        || canonical.canonical_format != "qcow2"
        || canonical.canonical_capacity_bytes != canonical_plan.capacity_bytes
        || canonical_volume.name != canonical.canonical_volume_name
        || canonical_volume.key != canonical.canonical_volume_key
        || canonical_volume.path != canonical.canonical_path
        || canonical_volume.format != canonical.canonical_format
        || canonical_volume.capacity_bytes != canonical.canonical_capacity_bytes
        || canonical_volume.backing_path.is_some()
        || canonical_proof.volume != *canonical_volume
        || canonical_proof.sha256 != canonical.canonical_sha256
        || canonical_proof.streamed_bytes != canonical.canonical_streamed_bytes
        || !canonical_protected
    {
        return Err("canonical promotion evidence or identity drift; recovery required".to_owned());
    }
    if preparation_domain_present {
        return Err("preparation domain remains after promotion; recovery required".to_owned());
    }
    if staging_present {
        return Err("staging volume remains after promotion; recovery required".to_owned());
    }
    Ok(())
}

fn require_promoted_canonical_volume(
    canonical: Option<forge_images::PreparationVolumeEvidence>,
) -> Result<forge_images::PreparationVolumeEvidence, String> {
    canonical.ok_or_else(|| "canonical volume absent; recovery required".to_owned())
}

fn image_prepare_workstation_status() -> ExitCode {
    let result = (|| -> Result<(), String> {
        let state_path = workstation_preparation_state_path()?;
        let preparation = forge_images::read_fedora_workstation_preparation(&state_path)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "no Fedora Workstation preparation exists".to_owned())?;
        if !exact_workstation_source(&preparation) {
            return Err("preparation provenance conflicts with the pinned source".to_owned());
        }
        let mut backend = forge_libvirt::LibvirtDefineBackend::connect_local()
            .map_err(|error| error.to_string())?;
        if preparation.status == forge_images::FedoraWorkstationPreparationStatus::Promoted {
            let canonical_volume = require_promoted_canonical_volume(
                FedoraWorkstationPreparationBackend::inspect_volume(
                    &mut backend,
                    "default",
                    &preparation.canonical.volume_name,
                )?,
            )?;
            backend.verify_exact_protected_qcow2_volume("default", &canonical_volume)?;
            let canonical_proof =
                backend.stream_exact_qcow2_volume("default", &canonical_volume)?;
            // List-based discovery keeps successful terminal absence checks quiet.
            let staging_present = DefineBackend::volume_exists(
                &mut backend,
                "default",
                &preparation.staging.volume_name,
            )
            .map_err(|error| error.to_string())?;
            let preparation_domain_present =
                DefineBackend::domain_exists(&mut backend, &preparation.installer.name)
                    .map_err(|error| error.to_string())?;
            prove_promoted_workstation_status(
                &preparation.preparation_id,
                &preparation.canonical,
                preparation.execution.host_only_promotion.as_ref(),
                preparation.execution.host_only_canonical.as_ref(),
                &canonical_volume,
                &canonical_proof,
                true,
                staging_present,
                preparation_domain_present,
            )?;
            println!("Preparation ID: {}", preparation.preparation_id.as_str());
            println!("Source ISO verified: yes (durable exact provenance)");
            println!("Current stage: Promoted");
            println!("Canonical base: {}", canonical_volume.name);
            println!("Canonical proof: verified");
            println!("Preparation domain: retired");
            println!("Staging volume: retired");
            println!("Recovery required: no");
            println!("Next action: create a normal Fedora Workstation VM from the canonical base");
            println!("Mutation: none");
            return Ok(());
        }
        let volume = FedoraWorkstationPreparationBackend::inspect_volume(
            &mut backend,
            "default",
            &preparation.staging.volume_name,
        )?
        .ok_or_else(|| "staging volume absent; recovery required".to_owned())?;
        let domain = backend
            .inspect_installer_domain(&preparation.installer.name)?
            .ok_or_else(|| "installer domain absent; recovery required".to_owned())?;
        if workstation_status_expects_running_domain(preparation.status) {
            forge_images::prove_fedora_workstation_running_disk_only_topology(
                &preparation,
                &domain,
            )
            .map_err(|error| error.to_string())?;
        } else {
            forge_images::prove_fedora_workstation_installer_topology(&preparation, &domain)
                .map_err(|error| error.to_string())?;
        }
        println!("Preparation ID: {}", preparation.preparation_id.as_str());
        println!("Source ISO verified: yes (durable exact provenance)");
        println!("Staging disk: {} ({})", volume.path.display(), volume.key);
        println!("Installer domain: {} ({})", domain.name, domain.uuid);
        println!("Current stage: {:?}", preparation.status);
        println!(
            "Installer domain state: {}",
            if domain.shutoff {
                "shut off"
            } else {
                "not shut off"
            }
        );
        let next_action = if preparation.status
            == forge_images::FedoraWorkstationPreparationStatus::InstalledSystemProven
            && domain.shutoff
        {
            "Graphical proof is complete and the preparation guest is shut off. Run: forge image prepare-promote fedora-workstation"
        } else {
            workstation_preparation_next_action(preparation.status)
        };
        println!("Next action: {next_action}");
        println!("Canonical base: not prepared");
        println!("Mutation: none");
        Ok(())
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Fedora Workstation preparation status failed: {error}");
            ExitCode::from(1)
        }
    }
}

#[allow(clippy::too_many_lines)]
fn image_prepare_workstation_start() -> ExitCode {
    let result = (|| -> Result<(), String> {
        let directories = forge_images::default_directories()
            .ok_or_else(|| "Forge image directories are unavailable".to_owned())?;
        let state_path = workstation_preparation_state_path()?;
        let mut preparation = forge_images::read_fedora_workstation_preparation(&state_path)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "no Fedora Workstation preparation exists".to_owned())?;
        if preparation.status != forge_images::FedoraWorkstationPreparationStatus::InstallerReady {
            return Err(format!(
                "installer start refused from durable stage {:?}",
                preparation.status
            ));
        }
        if !exact_workstation_source(&preparation) {
            return Err("preparation provenance conflicts with the pinned source".to_owned());
        }
        let source = workstation_source();
        let forge_images::FedoraWorkstationIsoState::Verified(metadata) =
            forge_images::inspect_fedora_workstation_iso(&directories, &source)
                .map_err(|error| error.to_string())?
        else {
            return Err("verified Workstation ISO is no longer available".to_owned());
        };
        if metadata.local_path != preparation.source.iso_path
            || metadata.sha256 != preparation.source.iso_sha256
            || metadata.byte_size != preparation.source.iso_bytes
        {
            return Err("ISO provenance differs from preparation authority".to_owned());
        }
        let mut backend = forge_libvirt::LibvirtDefineBackend::connect_local()
            .map_err(|error| error.to_string())?;
        let disposition =
            forge_images::execute_to_installer_ready(&mut backend, &mut preparation, |_| Ok(()))
                .map_err(|error| error.to_string())?;
        if disposition != forge_images::InstallerReadyDisposition::Resumed {
            return Err(
                "installer start requires an existing InstallerReady transaction".to_owned(),
            );
        }
        let runtime = preparation
            .execution
            .runtime_iso
            .as_ref()
            .ok_or_else(|| "installer-ready state lacks its managed runtime ISO".to_owned())?;
        if runtime.preparation_id != preparation.preparation_id
            || runtime.source_sha256 != preparation.source.iso_sha256
            || runtime.source_bytes != preparation.source.iso_bytes
        {
            return Err("runtime installer ISO provenance conflict".to_owned());
        }
        let (volume, bytes, digest) =
            FedoraWorkstationPreparationBackend::stream_installer_iso_digest(
                &mut backend,
                "default",
                &runtime.volume_name,
                preparation.source.iso_bytes,
            )?;
        if bytes != preparation.source.iso_bytes
            || digest != preparation.source.iso_sha256
            || volume.key != runtime.volume_key
            || volume.path != runtime.path
            || volume.capacity_bytes != runtime.destination_bytes
        {
            return Err("runtime installer ISO identity drift".to_owned());
        }
        backend.start_preparation_domain(&preparation.installer.name)?;
        if !backend.preparation_domain_running(&preparation.installer.name)? {
            return Err("installer domain did not reach running state".to_owned());
        }
        forge_images::record_installer_started(&mut preparation, true)
            .map_err(|error| error.to_string())?;
        forge_images::update_fedora_workstation_preparation(&state_path, &preparation)
            .map_err(|error| error.to_string())?;
        println!("Installer domain started: {}", preparation.installer.name);
        println!("Preparation ID: {}", preparation.preparation_id.as_str());
        println!("Current stage: {:?}", preparation.status);
        println!(
            "Open the domain in virt-manager and perform graphical Fedora Workstation installation onto the existing 80 GiB staging disk."
        );
        println!(
            "Do not reboot into another installer cycle. After Anaconda completes, shut the domain down and report explicit installation completion."
        );
        println!(
            "Next Forge boundary: installation confirmation; no success is inferred from running state."
        );
        Ok(())
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Fedora Workstation installer start failed: {error}");
            ExitCode::from(1)
        }
    }
}

fn image_prepare_workstation_continue() -> ExitCode {
    let result = (|| -> Result<(), String> {
        let state_path = workstation_preparation_state_path()?;
        let mut preparation = forge_images::read_fedora_workstation_preparation(&state_path)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "no active preparation".to_owned())?;
        if !exact_workstation_source(&preparation) {
            return Err("preparation provenance conflicts with the pinned source".to_owned());
        }
        let mut backend = forge_libvirt::LibvirtDefineBackend::connect_local()
            .map_err(|error| error.to_string())?;
        let disposition = forge_images::execute_to_installed_disk_running(
            &mut backend,
            &mut preparation,
            true,
            |value| {
                forge_images::update_fedora_workstation_preparation(&state_path, value)
                    .map_err(|error| error.to_string())
            },
        )
        .map_err(|error| error.to_string())?;
        println!("Installed-disk boot: {disposition:?}");
        println!("Anaconda installation: operator-confirmed complete");
        println!("Installer ISO: detached (retained as an unattached managed volume)");
        println!("{}", installed_disk_boot_message(disposition));
        println!("Graphical Fedora proof: operator confirmation required");
        println!("Canonical Workstation base: not created");
        Ok(())
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Fedora Workstation continuation refused: {error}");
            ExitCode::from(1)
        }
    }
}

fn image_prepare_workstation_confirm_installed() -> ExitCode {
    let result = (|| -> Result<(), String> {
        let directories = forge_images::default_directories()
            .ok_or_else(|| "Forge image directories are unavailable".to_owned())?;
        let state_path = workstation_preparation_state_path()?;
        let mut preparation = forge_images::read_fedora_workstation_preparation(&state_path)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "no active preparation".to_owned())?;
        if !exact_workstation_source(&preparation) {
            return Err("preparation provenance conflicts with the pinned source".to_owned());
        }
        let proof =
            forge_images::verified_fedora_workstation_iso(&directories, &workstation_source())
                .map_err(|error| format!("existing ISO proof is stale: {error}"))?;
        if proof.metadata().local_path != preparation.source.iso_path
            || proof.metadata().sha256 != preparation.source.iso_sha256
            || proof.metadata().byte_size != preparation.source.iso_bytes
        {
            return Err("ISO provenance differs from preparation authority".to_owned());
        }
        let mut backend = forge_libvirt::LibvirtDefineBackend::connect_local()
            .map_err(|error| error.to_string())?;
        let volume = FedoraWorkstationPreparationBackend::inspect_volume(
            &mut backend,
            "default",
            &preparation.staging.volume_name,
        )?
        .ok_or_else(|| "staging volume absent".to_owned())?;
        if volume.format != "qcow2"
            || volume.capacity_bytes != forge_images::FEDORA_WORKSTATION_STAGING_CAPACITY_BYTES
            || volume.backing_path.is_some()
        {
            return Err("staging storage shape is unsafe".to_owned());
        }
        if volume.name != preparation.staging.volume_name
            || volume.path != preparation.staging.path
            || preparation.execution.staging_volume_key.as_deref() != Some(volume.key.as_str())
        {
            return Err("durable staging identity drift".to_owned());
        }
        attest_operator_qcow2_check(&volume.path)?;
        forge_images::record_qemu_img_check_attestation(&mut preparation);
        forge_images::update_fedora_workstation_preparation(&state_path, &preparation)
            .map_err(|error| error.to_string())?;
        let disposition = forge_images::confirm_manually_installed_from_installer_ready(
            &mut backend,
            &mut preparation,
            true,
            |value| {
                forge_images::update_fedora_workstation_preparation(&state_path, value)
                    .map_err(|error| error.to_string())
            },
        )
        .map_err(|error| error.to_string())?;
        println!("Manual installation confirmation: {disposition:?}");
        println!("Operator attestation: graphical Fedora Workstation installation completed");
        println!("Fedora Initial Setup: NOT completed");
        println!("Personal user: NOT intentionally created by Forge");
        println!("Forge InstallerRunning observation: none (history preserved)");
        println!("Current stage: {:?}", preparation.status);
        println!("Canonical base: not created");
        Ok(())
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Fedora Workstation manual installation confirmation refused: {error}");
            ExitCode::from(1)
        }
    }
}

fn attest_operator_qcow2_check(path: &std::path::Path) -> Result<(), String> {
    println!(
        "Run this exact command in a separate terminal and inspect its result:\n\n  sudo /usr/bin/qemu-img check -- {}\n",
        path.display()
    );
    println!("Forge will not execute sudo or accept an operator-supplied path.");
    print!("Type CHECKED after qemu-img reports success: ");
    io::stdout()
        .flush()
        .map_err(|error| format!("failed to flush operator prompt: {error}"))?;
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(|error| format!("failed to read operator attestation: {error}"))?;
    if operator_qemu_img_check_answer(&answer) {
        Ok(())
    } else {
        Err("operator qemu-img check attestation refused".to_owned())
    }
}

fn operator_qemu_img_check_answer(answer: &str) -> bool {
    answer.trim() == "CHECKED"
}

fn image_prepare_workstation_confirm_graphical() -> ExitCode {
    let result = (|| -> Result<(), String> {
        let state_path = workstation_preparation_state_path()?;
        let mut preparation = forge_images::read_fedora_workstation_preparation(&state_path)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "no active preparation".to_owned())?;
        if !exact_workstation_source(&preparation) {
            return Err("preparation provenance conflicts with the pinned source".to_owned());
        }
        let mut backend = forge_libvirt::LibvirtDefineBackend::connect_local()
            .map_err(|error| error.to_string())?;
        if backend.canonical_base_exists("default", &preparation.canonical.volume_name)? {
            return Err("canonical Workstation base already exists".to_owned());
        }
        if let Some(runtime) = preparation.execution.runtime_iso.as_ref() {
            let retained = FedoraWorkstationPreparationBackend::inspect_volume(
                &mut backend,
                "default",
                &runtime.volume_name,
            )?
            .ok_or_else(|| "retained runtime ISO absent".to_owned())?;
            if retained.name != runtime.volume_name
                || retained.key != runtime.volume_key
                || retained.path != runtime.path
                || retained.capacity_bytes != runtime.destination_bytes
            {
                return Err("retained runtime ISO identity drift".to_owned());
            }
        }
        let domain = backend
            .inspect_installer_domain(&preparation.installer.name)?
            .ok_or_else(|| "preparation domain absent".to_owned())?;
        let disposition = forge_images::record_graphical_installed_system_confirmation(
            &mut preparation,
            &domain,
            true,
            true,
        )
        .map_err(|error| error.to_string())?;
        forge_images::update_fedora_workstation_preparation(&state_path, &preparation)
            .map_err(|error| error.to_string())?;
        println!("Graphical confirmation: {disposition:?}");
        println!("Installed system: proven from machine plus operator evidence");
        println!("GNOME Initial Setup: not completed");
        println!("Normalization: not started");
        println!("Domain: left running");
        Ok(())
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Fedora Workstation graphical confirmation refused: {error}");
            ExitCode::from(1)
        }
    }
}

fn image_prepare_workstation_promote() -> ExitCode {
    let result = (|| -> Result<(), String> {
        let state_path = workstation_preparation_state_path()?;
        let mut preparation = forge_images::read_fedora_workstation_preparation(&state_path)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "no active preparation".to_owned())?;
        if preparation.status
            != forge_images::FedoraWorkstationPreparationStatus::InstalledSystemProven
        {
            return Err("promotion requires InstalledSystemProven".to_owned());
        }
        if !exact_workstation_source(&preparation) {
            return Err("preparation provenance conflicts with the pinned source".to_owned());
        }
        let mut define = forge_libvirt::LibvirtDefineBackend::connect_local()
            .map_err(|error| error.to_string())?;
        if define.canonical_base_exists("default", &preparation.canonical.volume_name)? {
            return Err("canonical Workstation base already exists; promotion refused".to_owned());
        }
        let domain = define
            .inspect_installer_domain(&preparation.installer.name)?
            .ok_or_else(|| "preparation domain absent".to_owned())?;
        if !domain.shutoff || domain.running {
            return Err("shut down the preparation guest normally, then rerun forge image prepare-promote fedora-workstation".to_owned());
        }
        forge_images::prove_fedora_workstation_disk_only_topology(&preparation, &domain)
            .map_err(|error| error.to_string())?;
        let volume = FedoraWorkstationPreparationBackend::inspect_volume(
            &mut define,
            "default",
            &preparation.staging.volume_name,
        )?
        .ok_or_else(|| "staging volume absent".to_owned())?;
        if volume.name != preparation.staging.volume_name
            || volume.path != preparation.staging.path
            || volume.format != preparation.staging.format
            || volume.capacity_bytes != preparation.staging.capacity_bytes
            || volume.backing_path != preparation.staging.backing_path
            || preparation.execution.staging_volume_key.as_deref() != Some(volume.key.as_str())
        {
            return Err("durable staging identity drift".to_owned());
        }
        attest_operator_qcow2_check(&volume.path)?;
        let staging_proof = define.stream_exact_qcow2_volume("default", &volume)?;
        let topology = preparation
            .execution
            .disk_only_topology
            .as_ref()
            .ok_or_else(|| "disk-only topology proof absent".to_owned())?;
        let evidence = forge_images::HostOnlyPromotionEvidence {
            preparation_id: preparation.preparation_id.clone(),
            staging_volume_name: volume.name.clone(),
            staging_volume_key: volume.key.clone(),
            staging_path: volume.path.clone(),
            staging_format: volume.format.clone(),
            staging_capacity_bytes: volume.capacity_bytes,
            staging_allocation_bytes: staging_proof.volume.allocation_bytes,
            staging_streamed_bytes: staging_proof.streamed_bytes,
            staging_sha256: staging_proof.sha256.clone(),
            domain_name: domain.name.clone(),
            domain_uuid: domain.uuid.clone(),
            disk_only_topology_xml_sha256: topology.xml_sha256.clone(),
            domain_shutoff: domain.shutoff,
            qemu_img_check_attested: true,
        };
        forge_images::record_host_only_promotion_ready(&mut preparation, evidence)
            .map_err(|error| error.to_string())?;
        forge_images::update_fedora_workstation_preparation(&state_path, &preparation)
            .map_err(|error| error.to_string())?;
        define.clone_protected_workstation_volume(
            "default",
            &preparation.staging.path.to_string_lossy(),
            &preparation.canonical.volume_name,
            preparation.canonical.capacity_bytes,
        )?;
        let canonical_volume = FedoraWorkstationPreparationBackend::inspect_volume(
            &mut define,
            "default",
            &preparation.canonical.volume_name,
        )?
        .ok_or_else(|| "canonical volume absent after creation".to_owned())?;
        let canonical_proof = define.stream_exact_qcow2_volume("default", &canonical_volume)?;
        forge_images::record_host_only_canonical_publication(
            &mut preparation,
            forge_images::HostOnlyCanonicalEvidence {
                staging_sha256: staging_proof.sha256,
                staging_streamed_bytes: staging_proof.streamed_bytes,
                canonical_volume_name: canonical_proof.volume.name,
                canonical_volume_key: canonical_proof.volume.key,
                canonical_path: canonical_proof.volume.path,
                canonical_format: canonical_proof.volume.format,
                canonical_capacity_bytes: canonical_proof.volume.capacity_bytes,
                canonical_allocation_bytes: canonical_proof.volume.allocation_bytes,
                canonical_streamed_bytes: canonical_proof.streamed_bytes,
                canonical_sha256: canonical_proof.sha256,
            },
        )
        .map_err(|error| error.to_string())?;
        forge_images::update_fedora_workstation_preparation(&state_path, &preparation)
            .map_err(|error| error.to_string())?;
        let expected_domain = forge_libvirt::ExactDomainIdentity {
            name: preparation.installer.name.clone(),
            uuid: preparation.installer.uuid.clone(),
        };
        define
            .undefine_domain_exact(&expected_domain)
            .map_err(|error| error.to_string())?;
        let expected_staging = preparation_managed_resource(
            &volume.name,
            &volume.key,
            &volume.path,
            &volume.format,
            volume.capacity_bytes,
        )?;
        let boot = forge_libvirt::LibvirtBootBackend::connect_local()
            .map_err(|error| error.to_string())?;
        boot.delete_managed_volume_exact(&expected_staging)
            .map_err(|error| error.to_string())?;
        boot.verify_managed_volume_absent(&expected_staging)
            .map_err(|error| error.to_string())?;
        println!(
            "Promotion completed: canonical base {}",
            preparation.canonical.volume_name
        );
        Ok(())
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Fedora Workstation promotion refused: {error}");
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
            println!("Product status: Legacy/Retired Fedora Cloud Base compatibility artifact");
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
    eprintln!("image fetch refused: {LEGACY_FEDORA_RETIRED}");
    ExitCode::from(1)
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
    let _ = dry_run;
    eprintln!("define refused: {LEGACY_FEDORA_RETIRED}");
    return ExitCode::from(1);
    #[allow(unreachable_code)]
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
    if let Err(reason) = require_new_product(&profile) {
        eprintln!("domain rendering refused: {reason}");
        return ExitCode::from(1);
    }
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
    if let Err(reason) = require_new_product(&profile) {
        eprintln!("profile planning refused: {reason}");
        return ExitCode::from(1);
    }
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
    println!("Product availability: {:?}", profile.availability);
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
    if let Err(reason) = require_new_product(&profile) {
        eprintln!("instance planning refused: {reason}");
        return ExitCode::from(1);
    }
    let instance = match InstanceName::new(instance_name) {
        Ok(instance) => instance,
        Err(error) => {
            eprintln!("invalid instance name: {error}");
            return ExitCode::from(2);
        }
    };
    if let Err(error) = validate_whonix_canonical_instance(&profile, &instance) {
        eprintln!("instance planning refused: {error}");
        return ExitCode::from(1);
    }
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
    if profile.kind == forge_core::GuestProfileKind::FedoraWorkstation {
        match resolve_promoted_workstation_base() {
            Ok(base) => println!(
                "Promoted canonical base: {} (verified; reuse without import)",
                base.volume.name
            ),
            Err(error) => {
                eprintln!("promoted Fedora Workstation base is not usable: {error}");
                return ExitCode::from(1);
            }
        }
    }
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
    if let Err(error) = validate_whonix_canonical_instance(&profile, &instance) {
        eprintln!("create refused: {error}");
        return ExitCode::from(1);
    }
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
    forge_state::require_normal_lifecycle(&index)
        .map_err(|_| "matching Gateway durable state is deleted or recovery-required".to_owned())?;
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
    if matches!(
        plan.prepared_base.source,
        forge_core::ImageSourcePolicy::PromotedFedoraWorkstation { .. }
    ) {
        println!(
            "Prepared base semantics: reuse the exact promoted Fedora Workstation canonical base; no import"
        );
    } else {
        println!(
            "Prepared base semantics: prove and reuse an exact existing trusted base; otherwise prepare it when absent"
        );
    }
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
    whonix_gateway_proof: Option<forge_images::WhonixGatewayExecuteProof>,
    whonix_workstation_proof: Option<forge_images::WhonixWorkstationExecuteProof>,
    promoted_workstation: Option<PromotedWorkstationBaseProof>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PromotedWorkstationBaseProof {
    preparation_id: forge_images::FedoraWorkstationPreparationId,
    volume: forge_images::PreparationVolumeEvidence,
    canonical_sha256: String,
    canonical_streamed_bytes: u64,
    source_iso_sha256: String,
}

fn promoted_workstation_shared_base_resource(
    proof: &PromotedWorkstationBaseProof,
) -> forge_state::ManagedResource {
    forge_state::ManagedResource {
        role: forge_state::ResourceRole::SharedBase,
        volume_name: proof.volume.name.clone(),
        volume_key: proof.volume.key.clone(),
        path: proof.volume.path.to_string_lossy().into_owned(),
        format: proof.volume.format.clone(),
        capacity_bytes: proof.volume.capacity_bytes,
        backing_path: proof
            .volume
            .backing_path
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned()),
    }
}

fn resolve_promoted_workstation_base() -> Result<PromotedWorkstationBaseProof, String> {
    let state_path = workstation_preparation_state_path()?;
    let preparation = forge_images::read_fedora_workstation_preparation(&state_path)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "no Promoted Fedora Workstation preparation exists".to_owned())?;
    if preparation.status != forge_images::FedoraWorkstationPreparationStatus::Promoted {
        return Err("Fedora Workstation preparation is not Promoted".to_owned());
    }
    if !exact_workstation_source(&preparation) {
        return Err("promoted Workstation source provenance mismatch".to_owned());
    }
    let promotion = preparation
        .execution
        .host_only_promotion
        .as_ref()
        .ok_or_else(|| "host-only promotion evidence is absent".to_owned())?;
    let canonical = preparation
        .execution
        .host_only_canonical
        .as_ref()
        .ok_or_else(|| "host-only canonical evidence is absent".to_owned())?;
    if promotion.preparation_id != preparation.preparation_id
        || canonical.staging_sha256 != promotion.staging_sha256
        || canonical.staging_streamed_bytes != promotion.staging_streamed_bytes
        || canonical.canonical_volume_name != preparation.canonical.volume_name
        || canonical.canonical_path != preparation.canonical.path
        || canonical.canonical_format != "qcow2"
        || canonical.canonical_capacity_bytes != preparation.canonical.capacity_bytes
    {
        return Err("promoted Workstation evidence is incoherent".to_owned());
    }
    let define =
        forge_libvirt::LibvirtDefineBackend::connect_local().map_err(|error| error.to_string())?;
    let mut define = define;
    let volume = FedoraWorkstationPreparationBackend::inspect_volume(
        &mut define,
        forge_storage::DEFAULT_POOL,
        &preparation.canonical.volume_name,
    )?
    .ok_or_else(|| "promoted canonical volume is absent".to_owned())?;
    define.verify_exact_protected_qcow2_volume(forge_storage::DEFAULT_POOL, &volume)?;
    let proof = define.stream_exact_qcow2_volume(forge_storage::DEFAULT_POOL, &volume)?;
    if volume.name != canonical.canonical_volume_name
        || volume.key != canonical.canonical_volume_key
        || volume.path != canonical.canonical_path
        || volume.format != canonical.canonical_format
        || volume.capacity_bytes != canonical.canonical_capacity_bytes
        || volume.backing_path.is_some()
        || proof.sha256 != canonical.canonical_sha256
        || proof.streamed_bytes != canonical.canonical_streamed_bytes
    {
        return Err("promoted canonical live proof differs from durable evidence".to_owned());
    }
    Ok(PromotedWorkstationBaseProof {
        preparation_id: preparation.preparation_id,
        volume,
        canonical_sha256: canonical.canonical_sha256.clone(),
        canonical_streamed_bytes: canonical.canonical_streamed_bytes,
        source_iso_sha256: preparation.source.iso_sha256,
    })
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
        (
            ImageSourcePolicy::PromotedFedoraWorkstation { release, compose },
            ImageVerificationPolicy::Sha256Digest,
            SourceImageFormat::Qcow2,
            PrepareBaseStrategy::PromotedFedoraWorkstationCanonical,
        ) if release == forge_images::FEDORA_WORKSTATION_RELEASE
            && compose == forge_images::FEDORA_WORKSTATION_COMPOSE
            && plan.base_volume_name
                == format!("forge-base-fedora-workstation-{release}-{compose}.qcow2") =>
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
    let (path, kali_proof, whonix_gateway_proof, whonix_workstation_proof, promoted_workstation) =
        match validate_preparation_strategy(plan)? {
            forge_profiles::PrepareBaseStrategy::SevenZipSingleQcow2 => {
                let (metadata, proof) = forge_images::prepare_kali_for_execute(
                    &directories,
                    &mut forge_images::SystemArtifactFetcher,
                )
                .map_err(|error| error.to_string())?;
                (metadata.prepared_qcow2_path, Some(proof), None, None, None)
            }
            forge_profiles::PrepareBaseStrategy::WhonixBundleGateway => {
                let (metadata, proof) = forge_images::prepare_whonix_gateway_for_execute(
                    &directories,
                    &mut forge_images::SystemArtifactFetcher,
                )
                .map_err(|error| error.to_string())?;
                (metadata.prepared_qcow2_path, None, Some(proof), None, None)
            }
            forge_profiles::PrepareBaseStrategy::WhonixBundleWorkstation => {
                let (metadata, proof) = forge_images::prepare_whonix_workstation_for_execute(
                    &directories,
                    &mut forge_images::SystemArtifactFetcher,
                )
                .map_err(|error| error.to_string())?;
                (metadata.prepared_qcow2_path, None, None, Some(proof), None)
            }
            forge_profiles::PrepareBaseStrategy::VerifiedQcow2 => {
                return Err("verified direct-qcow2 real create is not implemented".to_owned());
            }
            forge_profiles::PrepareBaseStrategy::PromotedFedoraWorkstationCanonical => {
                let proof = resolve_promoted_workstation_base()?;
                (proof.volume.path.clone(), None, None, None, Some(proof))
            }
        };
    let (file_bytes, capacity_bytes) = if let Some(proof) = &promoted_workstation {
        (proof.canonical_streamed_bytes, proof.volume.capacity_bytes)
    } else {
        (
            std::fs::metadata(&path)
                .map_err(|error| error.to_string())?
                .len(),
            forge_images::qcow2_virtual_size(&path).map_err(|error| error.to_string())?,
        )
    };
    let artifact = PreparedBaseArtifact {
        path,
        file_bytes,
        capacity_bytes,
        kali_proof,
        whonix_gateway_proof,
        whonix_workstation_proof,
        promoted_workstation,
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
    let (path, promoted_workstation) = match validate_preparation_strategy(plan)? {
        forge_profiles::PrepareBaseStrategy::SevenZipSingleQcow2 => (
            forge_images::verified_kali(&directories)
                .map_err(|error| error.to_string())?
                .prepared_qcow2_path,
            None,
        ),
        forge_profiles::PrepareBaseStrategy::WhonixBundleGateway => (
            forge_images::verified_whonix_gateway(&directories)
                .map_err(|error| error.to_string())?
                .prepared_qcow2_path,
            None,
        ),
        forge_profiles::PrepareBaseStrategy::WhonixBundleWorkstation => (
            forge_images::verified_whonix_workstation(&directories)
                .map_err(|error| error.to_string())?
                .prepared_qcow2_path,
            None,
        ),
        forge_profiles::PrepareBaseStrategy::VerifiedQcow2 => {
            return Err("verified direct-qcow2 real create is not implemented".to_owned());
        }
        forge_profiles::PrepareBaseStrategy::PromotedFedoraWorkstationCanonical => {
            let proof = resolve_promoted_workstation_base()?;
            (proof.volume.path.clone(), Some(proof))
        }
    };
    let (file_bytes, capacity_bytes) = if let Some(proof) = &promoted_workstation {
        (proof.canonical_streamed_bytes, proof.volume.capacity_bytes)
    } else {
        (
            std::fs::metadata(&path)
                .map_err(|error| error.to_string())?
                .len(),
            forge_images::qcow2_virtual_size(&path).map_err(|error| error.to_string())?,
        )
    };
    Ok(PreparedBaseArtifact {
        path,
        file_bytes,
        capacity_bytes,
        kali_proof: None,
        whonix_gateway_proof: None,
        whonix_workstation_proof: None,
        promoted_workstation,
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
            let proof = source.whonix_gateway_proof.as_ref().ok_or_else(|| {
                "Gateway execute proof is absent after full validation".to_owned()
            })?;
            forge_images::revalidate_whonix_gateway_execute_proof(&directories, proof).map(|_| ())
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
        forge_profiles::PrepareBaseStrategy::PromotedFedoraWorkstationCanonical => {
            let expected = source.promoted_workstation.as_ref().ok_or_else(|| {
                "promoted Workstation proof is absent after full validation".to_owned()
            })?;
            let current = resolve_promoted_workstation_base()?;
            if current != *expected {
                return Err("promoted Workstation canonical drifted before create".to_owned());
            }
            Ok(())
        }
    }
    .map_err(|error| error.to_string())
}

struct ManualGuestCreateBackend {
    storage: forge_libvirt::LibvirtDefineBackend,
    boot: forge_libvirt::LibvirtBootBackend,
    instance: InstanceName,
    domain_uuid: String,
    source: PreparedBaseArtifact,
    layout: forge_state::StateLayout,
    workstation_pair_snapshot: Option<forge_profiles::WhonixPairSnapshot>,
    base_created: bool,
    overlay_created: bool,
    clone_source: Option<CloneSourceProof>,
}

struct ManualGuestCreateConnections {
    storage: forge_libvirt::LibvirtDefineBackend,
    boot: forge_libvirt::LibvirtBootBackend,
}

fn establish_manual_guest_create_connections(
    instance: &InstanceName,
) -> Result<ManualGuestCreateConnections, String> {
    eprintln!("[forge] Host authorization may be required before long-running verification.");
    eprintln!("[forge] phase start: system libvirt authorization preflight");
    let storage =
        forge_libvirt::LibvirtDefineBackend::connect_local().map_err(|error| error.to_string())?;
    let boot = forge_libvirt::LibvirtBootBackend::connect_instance(instance.clone())
        .map_err(|error| error.to_string())?;
    eprintln!("[forge] phase done: system libvirt authorization preflight");
    Ok(ManualGuestCreateConnections { storage, boot })
}

fn authorize_before_prepared_base<A, T>(
    authorize: impl FnOnce() -> Result<A, String>,
    preflight: impl FnOnce(&mut A) -> Result<(), String>,
    acquire: impl FnOnce() -> Result<T, String>,
) -> Result<(A, T), String> {
    let mut authorization = authorize()?;
    preflight(&mut authorization)?;
    let prepared_base = acquire()?;
    Ok((authorization, prepared_base))
}

fn validate_execute_boundary_preconditions(
    managed_state: &forge_state::ManagedState,
    target_domain_exists: bool,
    default_network_active: Option<bool>,
) -> Result<(), String> {
    let mut failures = Vec::new();
    if !matches!(managed_state, forge_state::ManagedState::Missing) {
        let observed = match managed_state {
            forge_state::ManagedState::Legacy(_) => "Legacy",
            forge_state::ManagedState::Current(_) => "Current",
            forge_state::ManagedState::InitialCreateRecoveryRequired(_) => {
                "InitialCreateRecoveryRequired"
            }
            forge_state::ManagedState::Conflict(_) => "Conflict",
            forge_state::ManagedState::Missing => unreachable!(),
        };
        failures.push(format!(
            "managed state precondition: expected Missing, observed {observed}"
        ));
    }
    if target_domain_exists {
        failures.push("target domain precondition: expected absent, observed present".to_owned());
    }
    if default_network_active == Some(false) {
        failures
            .push("default network precondition: expected active, observed inactive".to_owned());
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "execute-boundary precondition refused: {}",
            failures.join("; ")
        ))
    }
}

fn validate_manual_guest_create_target_preconditions(
    storage: &mut forge_libvirt::LibvirtDefineBackend,
    layout: &forge_state::StateLayout,
    instance: &InstanceName,
    network: &forge_core::NetworkPolicy,
    overlay: &str,
) -> Result<(), String> {
    let managed_state = forge_state::inspect_layout(layout).map_err(|error| error.to_string())?;
    let target_domain_exists =
        forge_storage::DefineBackend::domain_exists(storage, instance.as_str())
            .map_err(|error| error.to_string())?;
    let default_network_active = if matches!(network, forge_core::NetworkPolicy::DefaultNat) {
        Some(
            storage
                .default_network_active()
                .map_err(|error| error.to_string())?,
        )
    } else {
        None
    };
    validate_execute_boundary_preconditions(
        &managed_state,
        target_domain_exists,
        default_network_active,
    )?;
    if forge_storage::ImagePrepareBackend::inspect_volume(
        storage,
        forge_storage::DEFAULT_POOL,
        overlay,
    )
    .map_err(|error| error.to_string())?
    .is_some()
    {
        return Err(format!(
            "target overlay precondition: expected absent, observed present: {overlay}"
        ));
    }
    Ok(())
}

/// A completed delete tombstone retains exact historical evidence for the
/// shared base, but its domain must never be re-observed as a live consumer.
/// An in-progress delete remains live so a concurrent create fails closed
/// rather than racing that transaction.
fn shared_base_consumer_requires_live_reconciliation(index: &forge_state::GenerationIndex) -> bool {
    !matches!(
        index.delete_state,
        Some(forge_state::DeleteState::Deleted(_))
    )
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
        if shared_base_consumer_requires_live_reconciliation(&index) {
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
    if plan.prepared_base.preparation
        == forge_profiles::PrepareBaseStrategy::PromotedFedoraWorkstationCanonical
    {
        let source = verified_prepared_base_read_only(&plan.prepared_base)?;
        let existing = ImagePrepareBackend::inspect_volume(
            &mut storage,
            forge_storage::DEFAULT_POOL,
            &plan.prepared_base.base_volume_name,
        )
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "promoted Workstation canonical base is absent".to_owned())?;
        let promoted = source
            .promoted_workstation
            .as_ref()
            .ok_or_else(|| "promoted Workstation proof is absent".to_owned())?;
        let expected = forge_storage::BaseImageVolume {
            name: plan.prepared_base.base_volume_name.clone(),
            path: path.clone(),
            imported_bytes: promoted.canonical_streamed_bytes,
            capacity_bytes: promoted.volume.capacity_bytes,
            format: "qcow2".to_owned(),
        };
        let durable = promoted_workstation_shared_base_resource(promoted);
        forge_storage::classify_shared_base(&expected, Some(&existing), Some(&durable))?;
        return Ok(SharedBaseDryRunResolution {
            disposition: forge_storage::SharedBaseDisposition::ReuseProven,
            path,
            proof_source: format!(
                "durable Promoted Fedora Workstation preparation {}",
                promoted.preparation_id.as_str()
            ),
        });
    }
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
    #[allow(clippy::too_many_lines)]
    fn revalidate_targets(
        &mut self,
        plan: &forge_storage::GenericCreateExecutionPlan,
    ) -> Result<forge_storage::SharedBaseDisposition, String> {
        use forge_storage::ImagePrepareBackend;
        let started = Instant::now();
        eprintln!("[forge] phase start: execute boundary revalidation");
        if let Some(planned) = &self.workstation_pair_snapshot {
            let current = workstation_pair_snapshot(&plan.factory)?;
            forge_profiles::revalidate_whonix_snapshot(planned, &current)
                .map_err(|error| error.to_string())?;
        }
        validate_manual_guest_create_target_preconditions(
            &mut self.storage,
            &self.layout,
            &self.instance,
            &plan.factory.instance.network,
            &plan.factory.generation.overlay,
        )?;
        let pool =
            ImagePrepareBackend::inspect_pool(&mut self.storage, forge_storage::DEFAULT_POOL)
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "default pool is absent".to_owned())?;
        if !pool.active || pool.available_bytes < plan.factory.instance.resources.disk_bytes {
            return Err("default pool is inactive or lacks required capacity".to_owned());
        }
        if let Some(promoted) = &self.source.promoted_workstation {
            let current = resolve_promoted_workstation_base()?;
            if current != *promoted {
                return Err("promoted Workstation canonical drifted before create".to_owned());
            }
            let base = ImagePrepareBackend::inspect_volume(
                &mut self.storage,
                forge_storage::DEFAULT_POOL,
                &plan.factory.prepared_base.base_volume_name,
            )
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "promoted Workstation canonical base is absent".to_owned())?;
            let pool =
                ImagePrepareBackend::inspect_pool(&mut self.storage, forge_storage::DEFAULT_POOL)
                    .map_err(|error| error.to_string())?
                    .ok_or_else(|| "default pool is absent".to_owned())?;
            let expected = forge_storage::BaseImageVolume {
                name: plan.factory.prepared_base.base_volume_name.clone(),
                path: format!(
                    "{}/{}",
                    pool.target_path.trim_end_matches('/'),
                    plan.factory.prepared_base.base_volume_name
                ),
                imported_bytes: promoted.canonical_streamed_bytes,
                capacity_bytes: promoted.volume.capacity_bytes,
                format: "qcow2".to_owned(),
            };
            let durable = promoted_workstation_shared_base_resource(promoted);
            let disposition =
                forge_storage::classify_shared_base(&expected, Some(&base), Some(&durable))?;
            if disposition != forge_storage::SharedBaseDisposition::ReuseProven {
                return Err("promoted Workstation canonical base is not reusable".to_owned());
            }
            return Ok(disposition);
        }
        if let Some(source) = &self.clone_source {
            let backend = forge_libvirt::LibvirtBootBackend::connect_instance(
                source.operational.instance.clone(),
            )
            .map_err(|error| error.to_string())?;
            let observed = backend
                .inspect_managed_state(&source.operational.active)
                .map_err(|error| error.to_string())?;
            let reconciliation = forge_state::reconcile_managed(
                &source.operational.index,
                &source.operational.manifests,
                &observed,
            );
            if reconciliation.status != forge_state::ManagedReconciliationStatus::Consistent {
                return Err("source became non-Consistent before clone mutation".to_owned());
            }
            let status = backend
                .inspect_managed_lifecycle(&source.operational.active)
                .map_err(|error| error.to_string())?;
            if status != source.status || status.domain_state != forge_core::VmState::Shutoff {
                return Err("source identity or state changed before clone mutation".to_owned());
            }
            eprintln!(
                "[forge] phase done: execute boundary revalidation clone source elapsed={:.1}s",
                started.elapsed().as_secs_f64()
            );
            return Ok(forge_storage::SharedBaseDisposition::ReuseProven);
        }
        if self.clone_source.is_none() {
            prove_prepared_base(&plan.factory.prepared_base, &self.source)?;
        }
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

    #[allow(clippy::too_many_lines)]
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
        if let Some(source) = &self.clone_source {
            self.storage.clone_flattened_volume(
                forge_storage::DEFAULT_POOL,
                &source.status.active_overlay_path,
                &plan.factory.generation.overlay,
                plan.factory.instance.resources.disk_bytes,
            )?;
            self.overlay_created = true;
            eprintln!(
                "[forge] phase done: storage clone and independent disk creation elapsed={:.1}s",
                started.elapsed().as_secs_f64()
            );
            return Ok(());
        }
        match disposition {
            forge_storage::SharedBaseDisposition::Prepare => {
                let directories = forge_images::default_directories()
                    .ok_or_else(|| "Forge image directories are unavailable".to_owned())?;
                let pinned_source = if let Some(proof) = self.source.kali_proof.as_ref() {
                    Some(
                        forge_images::open_kali_prepared_base_execute_source(&directories, proof)
                            .map_err(|error| error.to_string())?,
                    )
                } else if let Some(proof) = self.source.whonix_gateway_proof.as_ref() {
                    Some(
                        forge_images::open_whonix_gateway_execute_source(&directories, proof)
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
                let durable = if let Some(promoted) = &self.source.promoted_workstation {
                    promoted_workstation_shared_base_resource(promoted)
                } else {
                    existing_shared_base_proof(&self.layout, &base.name, &existing)?.resource
                };
                forge_storage::classify_shared_base(&base, Some(&existing), Some(&durable))?;
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
                None,
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
        if self.clone_source.is_some() {
            self.boot
                .inspect_generation_flat_overlay_only(&format!(
                    "/var/lib/libvirt/images/{}",
                    plan.factory.generation.overlay
                ))
                .map_err(|error| error.to_string())
        } else {
            self.boot
                .inspect_generation_overlay_only(&format!(
                    "/var/lib/libvirt/images/{}",
                    plan.factory.generation.overlay
                ))
                .map_err(|error| error.to_string())
        }
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
    if let Some(profile) = forge_profiles::find(profile_name)
        && let Err(reason) = require_new_product(&profile)
    {
        eprintln!("create refused: {reason}");
        return ExitCode::from(1);
    }
    if !matches!(
        profile_name,
        "kali-lab" | "fedora-workstation" | "whonix-gateway" | "whonix-workstation"
    ) {
        eprintln!("real generic create is unavailable for this profile's image strategy");
        return ExitCode::from(2);
    }
    let Some(profile) = forge_profiles::find(profile_name) else {
        eprintln!("unknown VM profile: {profile_name}");
        return ExitCode::from(2);
    };
    let instance = match InstanceName::new(instance_name) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("create refused: invalid instance name: {error}");
            return ExitCode::from(2);
        }
    };
    if let Err(error) = validate_whonix_canonical_instance(&profile, &instance) {
        eprintln!("create refused: {error}");
        return ExitCode::from(1);
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

fn validate_whonix_canonical_instance(
    profile: &forge_core::VmProfile,
    instance: &InstanceName,
) -> Result<(), String> {
    let expected = match profile.kind {
        forge_core::GuestProfileKind::WhonixGateway => Some("whonix-gateway"),
        forge_core::GuestProfileKind::WhonixWorkstation => Some("whonix-workstation"),
        _ => None,
    };
    if let Some(expected) = expected
        && instance.as_str() != expected
    {
        return Err(format!(
            "V2.5 built-in Whonix pairing requires canonical instance `{expected}` for profile `{}`; custom-named pairs require an explicit durable pair binding and are unsupported",
            profile.id
        ));
    }
    Ok(())
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
    let home = env::var_os("HOME").ok_or_else(|| "HOME is unavailable".to_owned())?;
    let layout = forge_state::StateLayout::for_instance(
        &forge_state::state_directory(std::path::Path::new(&home)),
        &instance,
    );
    let (connections, source) = authorize_before_prepared_base(
        || establish_manual_guest_create_connections(&instance),
        |connections| {
            validate_manual_guest_create_target_preconditions(
                &mut connections.storage,
                &layout,
                &instance,
                &factory.instance.network,
                &factory.generation.overlay,
            )
        },
        || acquire_prepared_base(&factory.prepared_base),
    )?;
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
    let mut backend = ManualGuestCreateBackend {
        storage: connections.storage,
        boot: connections.boot,
        instance,
        domain_uuid,
        source,
        layout,
        workstation_pair_snapshot,
        base_created: false,
        overlay_created: false,
        clone_source: None,
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
    eprintln!("  forge vm status <instance>");
    eprintln!("  forge vm create <profile> <instance> --dry-run");
    eprintln!("  forge vm create <profile> <instance>");
    eprintln!("  forge vm clone <source-instance> <target-instance> [--dry-run]");
    eprintln!("  forge vm fresh <instance> [--dry-run]");
    eprintln!("  forge vm start <instance> [--dry-run]");
    eprintln!("  forge vm shutdown <instance> [--dry-run]");
    eprintln!("  forge vm stop <instance> --force [--dry-run]");
    eprintln!("  forge delete <instance> [--force]");
    eprintln!("  forge vm cleanup <instance> [--dry-run]");
    eprintln!("  forge state show fedora-lab");
    eprintln!("  forge state reconcile <instance>");
    eprintln!("  forge state recover <instance> [--dry-run]");
    eprintln!("  forge state adopt fedora-lab [--dry-run] (maintenance)");
    eprintln!("  forge vm define fedora-lab [--dry-run] (legacy maintenance)");
    eprintln!("  forge vm prepare fedora-lab [--dry-run] (legacy maintenance)");
    eprintln!("  forge vm boot fedora-lab [--dry-run] (legacy maintenance)");
    eprintln!("  forge vm rebuild <instance> --dry-run (maintenance)");
    eprintln!("  forge vm rebuild fedora-lab [--managed] [--dry-run] (legacy maintenance)");
    eprintln!("  forge domain render <profile> (diagnostic)");
    eprintln!("  forge image list");
    eprintln!("  forge image inspect fedora");
    eprintln!("  forge image inspect kali");
    eprintln!("  forge image fetch kali");
    eprintln!("  forge image inspect fedora-workstation");
    eprintln!("  forge image fetch fedora-workstation");
    eprintln!("  forge image prepare fedora-workstation --dry-run");
    eprintln!("  forge image prepare fedora-workstation");
    eprintln!("  forge image prepare-status fedora-workstation");
    eprintln!("  forge image prepare-start fedora-workstation");
    eprintln!("  forge image prepare-continue fedora-workstation");
    eprintln!("  forge image prepare-confirm-installed fedora-workstation");
    eprintln!("  forge image prepare-confirm-graphical fedora-workstation");
    eprintln!("  forge image prepare-promote fedora-workstation");
    eprintln!("  forge image abort fedora-workstation <preparation-id> (recovery)");
    eprintln!("  forge image recover whonix-workstation [--dry-run]");
    eprintln!(
        "Legacy Fedora Cloud/NoCloud is retired; compatibility inspection remains available."
    );
}

fn doctor_host_status(state: HostState, storage_ready: bool) -> &'static str {
    match state {
        // Storage is an additional prerequisite, not evidence that an
        // unsupported operating system is merely incomplete.
        HostState::Unsupported => "Unsupported",
        HostState::Incomplete => "Incomplete",
        HostState::Ready if !storage_ready => "Incomplete",
        HostState::Degraded if !storage_ready => "Incomplete",
        HostState::Ready => "Ready",
        HostState::Degraded => "Degraded",
    }
}

fn print_report(report: &DoctorReport, storage_ready: bool) {
    let distro = &report.host.distribution;
    let host_status = doctor_host_status(report.state, storage_ready);
    println!("Host status: {host_status}");
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
    fn delete_parser_accepts_only_the_public_root_command() {
        assert_eq!(
            parse_delete_command(&["delete", "fedora-lab"]),
            Some(DeleteCommand {
                instance: "fedora-lab".into(),
                force: false,
            })
        );
        assert_eq!(
            parse_delete_command(&["delete", "fedora-lab", "--force"]),
            Some(DeleteCommand {
                instance: "fedora-lab".into(),
                force: true,
            })
        );
        assert_eq!(parse_delete_command(&["vm", "delete", "fedora-lab"]), None);
        assert_eq!(
            parse_delete_command(&["delete", "fedora-lab", "--force", "extra"]),
            None
        );
    }

    #[test]
    fn help_request_is_a_successful_public_entrypoint() {
        assert!(is_help_request(&["--help"]));
        assert!(is_help_request(&["-h"]));
        assert!(!is_help_request(&[]));
        assert!(!is_help_request(&["--help", "extra"]));
    }

    #[test]
    fn unsupported_doctor_state_is_never_masked_by_storage_readiness() {
        assert_eq!(
            doctor_host_status(HostState::Unsupported, false),
            "Unsupported"
        );
        assert_eq!(
            doctor_host_status(HostState::Unsupported, true),
            "Unsupported"
        );
        assert_eq!(doctor_host_status(HostState::Ready, false), "Incomplete");
    }

    #[test]
    fn inventory_labels_recorded_verification_without_claiming_a_fresh_proof() {
        assert_eq!(
            recorded_inventory_fields(Ok(forge_images::RecordedPreparationState::RecordedVerified)),
            (
                "RecordedVerified",
                "durable recorded verification; not freshly reverified",
                "prepared artifact".to_owned()
            )
        );
    }

    #[test]
    fn inventory_reports_a_complete_promoted_workstation_as_prepared() {
        assert_eq!(
            workstation_inventory_generation_from_evidence(
                forge_images::FedoraWorkstationPreparationStatus::Promoted,
                true,
                true,
                true,
            ),
            "promoted canonical base (durable evidence)"
        );
    }

    #[test]
    fn kali_inspect_refuses_untrusted_or_interrupted_states() {
        assert_eq!(
            kali_inspect_exit_code(&forge_images::KaliPreparationState::Missing),
            ExitCode::SUCCESS
        );
        assert_eq!(
            kali_inspect_exit_code(&forge_images::KaliPreparationState::Preparing),
            ExitCode::SUCCESS
        );
        for state in [
            forge_images::KaliPreparationState::InterruptedPreparation,
            forge_images::KaliPreparationState::OrphanedPreparedImage,
            forge_images::KaliPreparationState::Conflict("drift".to_owned()),
        ] {
            assert_ne!(kali_inspect_exit_code(&state), ExitCode::SUCCESS);
        }
    }

    #[test]
    fn authorization_preflight_precedes_prepared_base_and_failure_skips_it() {
        let events = std::cell::RefCell::new(Vec::new());
        let result = authorize_before_prepared_base(
            || {
                events.borrow_mut().push("authorize");
                Ok::<_, String>(())
            },
            |_| {
                events.borrow_mut().push("target-preflight");
                Ok(())
            },
            || {
                events.borrow_mut().push("prepared-base-proof");
                Ok::<_, String>(())
            },
        );
        assert!(result.is_ok());
        assert_eq!(
            events.into_inner(),
            vec!["authorize", "target-preflight", "prepared-base-proof"]
        );

        let proof_started = std::cell::Cell::new(false);
        let result = authorize_before_prepared_base(
            || Err::<(), _>("host authorization refused".to_owned()),
            |_| Ok(()),
            || {
                proof_started.set(true);
                Ok::<_, String>(())
            },
        );
        assert_eq!(result.unwrap_err(), "host authorization refused");
        assert!(!proof_started.get());

        let proof_started = std::cell::Cell::new(false);
        let result = authorize_before_prepared_base(
            || Ok::<_, String>(()),
            |_| Err("target preflight refused".to_owned()),
            || {
                proof_started.set(true);
                Ok::<_, String>(())
            },
        );
        assert_eq!(result.unwrap_err(), "target preflight refused");
        assert!(!proof_started.get());
    }

    #[test]
    fn execute_boundary_preconditions_are_exact_and_fail_closed() {
        assert!(
            validate_execute_boundary_preconditions(
                &forge_state::ManagedState::Missing,
                false,
                None,
            )
            .is_ok()
        );

        let current = forge_state::ManagedState::Current(forge_state::GenerationIndex {
            schema_version: forge_state::INDEX_SCHEMA_VERSION,
            domain_name: "whonix-gateway".to_owned(),
            domain_uuid: "uuid".to_owned(),
            active_generation_id: "gen-existing".to_owned(),
            generations: vec![forge_state::GenerationEntry {
                generation_id: "gen-existing".to_owned(),
                status: forge_state::GenerationStatus::Active,
                manifest_file: "generations/gen-existing.json".to_owned(),
            }],
            cleanup_progress: vec![],
            delete_state: None,
        });
        assert_eq!(
            validate_execute_boundary_preconditions(&current, false, None).unwrap_err(),
            "execute-boundary precondition refused: managed state precondition: expected Missing, observed Current"
        );
        assert_eq!(
            validate_execute_boundary_preconditions(
                &forge_state::ManagedState::Missing,
                true,
                None,
            )
            .unwrap_err(),
            "execute-boundary precondition refused: target domain precondition: expected absent, observed present"
        );
        assert_eq!(
            validate_execute_boundary_preconditions(
                &forge_state::ManagedState::Missing,
                false,
                Some(false),
            )
            .unwrap_err(),
            "execute-boundary precondition refused: default network precondition: expected active, observed inactive"
        );
    }

    #[test]
    fn deleted_historical_gateway_proves_shared_base_without_live_domain_lookup() {
        let root = std::env::temp_dir().join(format!(
            "forge-deleted-gateway-shared-base-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let old_instance = InstanceName::new("whonix-gw-test").unwrap();
        let old_layout = forge_state::StateLayout::for_instance(&root, &old_instance);
        let generation_id = "gen-deleted-gateway".to_owned();
        let base = forge_state::ManagedResource {
            role: forge_state::ResourceRole::SharedBase,
            volume_name: "forge-base-whonix-gateway.qcow2".to_owned(),
            volume_key: "/pool/forge-base-whonix-gateway.qcow2".to_owned(),
            path: "/pool/forge-base-whonix-gateway.qcow2".to_owned(),
            format: "qcow2".to_owned(),
            capacity_bytes: 100,
            backing_path: None,
        };
        let overlay = forge_state::ManagedResource {
            role: forge_state::ResourceRole::WritableOverlay,
            volume_name: "whonix-gw-test-overlay.qcow2".to_owned(),
            volume_key: "/pool/whonix-gw-test-overlay.qcow2".to_owned(),
            path: "/pool/whonix-gw-test-overlay.qcow2".to_owned(),
            format: "qcow2".to_owned(),
            capacity_bytes: 100,
            backing_path: Some(base.path.clone()),
        };
        let manifest = forge_state::GenerationManifest {
            schema_version: forge_state::SCHEMA_VERSION,
            domain_name: old_instance.to_string(),
            domain_uuid: "deleted-gateway-uuid".to_owned(),
            generation_id: generation_id.clone(),
            created_unix_seconds: 1,
            libvirt_uri: "qemu:///system".to_owned(),
            storage_pool_name: "default".to_owned(),
            storage_pool_uuid: "pool-uuid".to_owned(),
            status: forge_state::GenerationStatus::Preparing,
            resources: vec![base.clone(), overlay.clone()],
            fresh_domain_evidence: None,
        };
        forge_state::publish_initial_preparing(&old_layout, &manifest).unwrap();
        let index = forge_state::GenerationIndex {
            schema_version: forge_state::INDEX_SCHEMA_VERSION,
            domain_name: "whonix-gw-test".to_owned(),
            domain_uuid: "deleted-gateway-uuid".to_owned(),
            active_generation_id: generation_id.clone(),
            generations: vec![forge_state::GenerationEntry {
                generation_id: generation_id.clone(),
                status: forge_state::GenerationStatus::Active,
                manifest_file: "generations/gen-deleted-gateway.json".to_owned(),
            }],
            cleanup_progress: vec![],
            delete_state: Some(forge_state::DeleteState::Deleted(
                forge_state::DeleteTombstone {
                    plan: forge_state::DeletePlan {
                        domain_name: "whonix-gw-test".to_owned(),
                        domain_uuid: "deleted-gateway-uuid".to_owned(),
                        storage_pool_name: "default".to_owned(),
                        storage_pool_uuid: "pool-uuid".to_owned(),
                        generation_id: generation_id.clone(),
                        resources: vec![forge_state::DeleteResourcePlan {
                            generation_id: generation_id.clone(),
                            resource: overlay,
                        }],
                    },
                },
            )),
        };
        forge_state::write_index_atomic(&old_layout.index, &index).unwrap();
        assert!(!shared_base_consumer_requires_live_reconciliation(&index));
        assert!(forge_state::require_normal_lifecycle(&index).is_err());

        let target_layout = forge_state::StateLayout::for_instance(
            &root,
            &InstanceName::new("whonix-gateway").unwrap(),
        );
        let expected = forge_storage::OverlayVolume {
            name: base.volume_name.clone(),
            path: base.path.clone(),
            capacity_bytes: base.capacity_bytes,
            allocation_bytes: 0,
            format: base.format.clone(),
            backing_path: None,
        };
        let proof = existing_shared_base_proof(&target_layout, &base.volume_name, &expected)
            .expect("deleted durable evidence must not require the absent historical domain");
        assert_eq!(proof.consumer, "whonix-gw-test");
        assert_eq!(proof.resource, base);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn delete_integrity_errors_refuse_and_backend_errors_can_resume() {
        assert!(matches!(
            classify_domain_delete_error(forge_libvirt::DomainDeleteError::Conflict(
                "UUID mismatch".to_owned()
            )),
            DeleteFailure::Refused(_)
        ));
        assert!(matches!(
            classify_domain_delete_error(forge_libvirt::DomainDeleteError::UnsafeState(
                "running".to_owned()
            )),
            DeleteFailure::Refused(_)
        ));
        assert!(matches!(
            classify_domain_delete_error(forge_libvirt::DomainDeleteError::Backend(
                "libvirt unavailable".to_owned()
            )),
            DeleteFailure::Recoverable(_)
        ));
        assert!(matches!(
            classify_volume_delete_error(
                forge_libvirt::ManagedVolumeDeleteError::IdentityMismatch("wrong key".to_owned())
            ),
            DeleteFailure::Refused(_)
        ));
        assert!(matches!(
            classify_volume_delete_error(forge_libvirt::ManagedVolumeDeleteError::Referenced(
                "backing reference".to_owned()
            )),
            DeleteFailure::Refused(_)
        ));
        assert!(matches!(
            classify_volume_delete_error(forge_libvirt::ManagedVolumeDeleteError::Backend(
                "storage unavailable".to_owned()
            )),
            DeleteFailure::Recoverable(_)
        ));
        assert!(matches!(
            classify_volume_absence_error(forge_libvirt::ManagedVolumeAbsenceError::Present(
                "still exists".to_owned()
            )),
            DeleteFailure::Refused(_)
        ));
        assert!(matches!(
            classify_volume_absence_error(forge_libvirt::ManagedVolumeAbsenceError::Backend(
                "lookup failed".to_owned()
            )),
            DeleteFailure::Recoverable(_)
        ));
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
    fn workstation_create_strategy_is_typed_and_not_legacy_fedora() {
        let profile = forge_profiles::fedora_workstation();
        assert!(matches!(
            profile.image_source,
            ImageSourcePolicy::PromotedFedoraWorkstation { .. }
        ));
        assert!(!matches!(
            profile.image_source,
            ImageSourcePolicy::FedoraCloudBase { .. }
        ));
        let plan = forge_profiles::PreparedBaseImagePlan {
            source: profile.image_source,
            verification: profile.image_verification,
            source_format: SourceImageFormat::Qcow2,
            preparation: PrepareBaseStrategy::PromotedFedoraWorkstationCanonical,
            base_volume_name: "forge-base-fedora-workstation-44-1.7.qcow2".to_owned(),
        };
        assert_eq!(
            validate_preparation_strategy(&plan).unwrap(),
            PrepareBaseStrategy::PromotedFedoraWorkstationCanonical
        );
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
    fn qemu_img_check_attestation_requires_exact_checked_answer() {
        assert!(operator_qemu_img_check_answer("CHECKED\n"));
        assert!(!operator_qemu_img_check_answer("yes\n"));
        assert!(!operator_qemu_img_check_answer("CHECKED extra\n"));
    }

    #[test]
    fn workstation_status_guidance_follows_the_durable_stage() {
        use forge_images::FedoraWorkstationPreparationStatus as Status;

        assert_eq!(
            workstation_preparation_next_action(Status::InstallerReady),
            "If installation was performed manually or outside Forge and the VM is shut off, run: forge image prepare-confirm-installed fedora-workstation"
        );
        assert_eq!(
            workstation_preparation_next_action(Status::InstallerRunning),
            "Complete graphical Anaconda, shut down the VM, then run: forge image prepare-continue fedora-workstation"
        );
        assert!(
            workstation_preparation_next_action(Status::AwaitingGraphicalBootConfirmation)
                .contains("prepare-confirm-graphical")
        );
    }

    #[test]
    fn disk_only_prepared_output_never_claims_the_domain_is_running() {
        assert_eq!(
            installed_disk_boot_message(
                forge_images::InstalledDiskBootDisposition::DiskOnlyPrepared
            ),
            "Installed system: disk-only topology prepared; domain not started"
        );
        assert!(
            installed_disk_boot_message(forge_images::InstalledDiskBootDisposition::Started)
                .contains("running")
        );
    }

    #[test]
    fn workstation_status_routes_only_known_running_boundaries_to_running_proof() {
        use forge_images::FedoraWorkstationPreparationStatus as Status;

        for status in [
            Status::InstalledDiskBooting,
            Status::AwaitingGraphicalBootConfirmation,
            Status::InstalledSystemProven,
            Status::NormalizationPlanned,
            Status::NormalizationRunning,
            Status::NormalizationGuestComplete,
        ] {
            assert!(workstation_status_expects_running_domain(status));
        }
        assert!(!workstation_status_expects_running_domain(
            Status::InstalledDiskBootPending
        ));
        assert!(!workstation_status_expects_running_domain(
            Status::OfflineProofPending
        ));
        assert!(!workstation_status_expects_running_domain(
            Status::ShutdownPending
        ));
    }

    fn promoted_workstation_status_fixture() -> (
        forge_images::FedoraWorkstationPreparationId,
        forge_images::CanonicalWorkstationBasePlan,
        forge_images::HostOnlyPromotionEvidence,
        forge_images::HostOnlyCanonicalEvidence,
        forge_images::PreparationVolumeEvidence,
        forge_images::Qcow2VolumeProof,
    ) {
        let preparation_id = forge_images::FedoraWorkstationPreparationId::new("a1b2c3d4")
            .expect("fixture preparation ID");
        let canonical_plan = forge_images::CanonicalWorkstationBasePlan {
            volume_name: "forge-base-fedora-workstation.qcow2".to_owned(),
            path: "/var/lib/libvirt/images/forge-base-fedora-workstation.qcow2".into(),
            format: "qcow2".to_owned(),
            capacity_bytes: 80,
            backing_path: None,
            role: forge_images::FedoraWorkstationArtifactRole::CanonicalSharedBase,
            logical_read_only: true,
            direct_writable_attachment_allowed: false,
        };
        let promotion = forge_images::HostOnlyPromotionEvidence {
            preparation_id: preparation_id.clone(),
            staging_volume_name: "forge-stage.qcow2".to_owned(),
            staging_volume_key: "/var/lib/libvirt/images/forge-stage.qcow2".to_owned(),
            staging_path: "/var/lib/libvirt/images/forge-stage.qcow2".into(),
            staging_format: "qcow2".to_owned(),
            staging_capacity_bytes: 80,
            staging_allocation_bytes: 20,
            staging_streamed_bytes: 24,
            staging_sha256: "a".repeat(64),
            domain_name: "forge-prepare".to_owned(),
            domain_uuid: "domain-uuid".to_owned(),
            disk_only_topology_xml_sha256: "b".repeat(64),
            domain_shutoff: true,
            qemu_img_check_attested: true,
        };
        let canonical = forge_images::HostOnlyCanonicalEvidence {
            staging_sha256: promotion.staging_sha256.clone(),
            staging_streamed_bytes: promotion.staging_streamed_bytes,
            canonical_volume_name: canonical_plan.volume_name.clone(),
            canonical_volume_key: canonical_plan.path.to_string_lossy().into_owned(),
            canonical_path: canonical_plan.path.clone(),
            canonical_format: "qcow2".to_owned(),
            canonical_capacity_bytes: canonical_plan.capacity_bytes,
            canonical_allocation_bytes: 18,
            canonical_streamed_bytes: 22,
            canonical_sha256: "c".repeat(64),
        };
        let volume = forge_images::PreparationVolumeEvidence {
            name: canonical.canonical_volume_name.clone(),
            key: canonical.canonical_volume_key.clone(),
            path: canonical.canonical_path.clone(),
            format: canonical.canonical_format.clone(),
            capacity_bytes: canonical.canonical_capacity_bytes,
            allocation_bytes: canonical.canonical_allocation_bytes,
            backing_path: None,
        };
        let proof = forge_images::Qcow2VolumeProof {
            volume: volume.clone(),
            streamed_bytes: canonical.canonical_streamed_bytes,
            sha256: canonical.canonical_sha256.clone(),
        };
        (
            preparation_id,
            canonical_plan,
            promotion,
            canonical,
            volume,
            proof,
        )
    }

    #[test]
    fn promoted_status_accepts_exact_canonical_and_retired_preparation_resources() {
        let (id, plan, promotion, canonical, volume, proof) = promoted_workstation_status_fixture();
        assert!(
            prove_promoted_workstation_status(
                &id,
                &plan,
                Some(&promotion),
                Some(&canonical),
                &volume,
                &proof,
                true,
                false,
                false,
            )
            .is_ok()
        );
    }

    #[test]
    fn promoted_status_refuses_canonical_identity_or_representation_drift() {
        let (id, plan, promotion, canonical, volume, mut proof) =
            promoted_workstation_status_fixture();
        proof.sha256 = "d".repeat(64);
        assert!(
            prove_promoted_workstation_status(
                &id,
                &plan,
                Some(&promotion),
                Some(&canonical),
                &volume,
                &proof,
                true,
                false,
                false,
            )
            .is_err()
        );

        let (_, _, _, _, mut drifted_volume, proof) = promoted_workstation_status_fixture();
        drifted_volume.backing_path = Some("/unexpected/backing.qcow2".into());
        assert!(
            prove_promoted_workstation_status(
                &id,
                &plan,
                Some(&promotion),
                Some(&canonical),
                &drifted_volume,
                &proof,
                true,
                false,
                false,
            )
            .is_err()
        );
    }

    #[test]
    fn promoted_status_refuses_stream_length_or_cleanup_drift() {
        let (id, plan, promotion, canonical, volume, mut proof) =
            promoted_workstation_status_fixture();
        proof.streamed_bytes += 1;
        assert!(
            prove_promoted_workstation_status(
                &id,
                &plan,
                Some(&promotion),
                Some(&canonical),
                &volume,
                &proof,
                true,
                false,
                false,
            )
            .is_err()
        );
        assert!(
            prove_promoted_workstation_status(
                &id,
                &plan,
                Some(&promotion),
                Some(&canonical),
                &volume,
                &proof,
                true,
                true,
                false,
            )
            .is_err()
        );
        assert!(
            prove_promoted_workstation_status(
                &id,
                &plan,
                Some(&promotion),
                Some(&canonical),
                &volume,
                &proof,
                true,
                false,
                true,
            )
            .is_err()
        );
    }

    #[test]
    fn promoted_status_refuses_each_canonical_identity_and_protection_drift() {
        let (id, plan, promotion, canonical, volume, proof) = promoted_workstation_status_fixture();
        let mut cases = Vec::new();

        let mut name = volume.clone();
        name.name = "foreign.qcow2".to_owned();
        cases.push(name);
        let mut key = volume.clone();
        key.key = "/var/lib/libvirt/images/foreign.qcow2".to_owned();
        cases.push(key);
        let mut path = volume.clone();
        path.path = "/var/lib/libvirt/images/foreign.qcow2".into();
        cases.push(path);
        let mut format = volume.clone();
        format.format = "raw".to_owned();
        cases.push(format);
        let mut capacity = volume.clone();
        capacity.capacity_bytes += 1;
        cases.push(capacity);

        for drifted in cases {
            assert!(
                prove_promoted_workstation_status(
                    &id,
                    &plan,
                    Some(&promotion),
                    Some(&canonical),
                    &drifted,
                    &proof,
                    true,
                    false,
                    false,
                )
                .is_err()
            );
        }
        assert!(
            prove_promoted_workstation_status(
                &id,
                &plan,
                Some(&promotion),
                Some(&canonical),
                &volume,
                &proof,
                false,
                false,
                false,
            )
            .is_err()
        );
    }

    #[test]
    fn promoted_status_requires_a_canonical_volume_without_mutating_resources() {
        assert!(require_promoted_canonical_volume(None).is_err());
        let (_, _, _, _, volume, _) = promoted_workstation_status_fixture();
        assert_eq!(
            require_promoted_canonical_volume(Some(volume.clone())).unwrap(),
            volume
        );
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
            delete_state: None,
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
            fresh_domain_evidence: None,
        };
        let profile = validate_profile_binding("kali-2", &index, &active).unwrap();
        assert_eq!(profile.id.as_str(), "kali-lab");
    }

    #[test]
    fn clone_profile_scope_is_typed_and_refuses_other_families() {
        assert!(clone_profile_supported(
            &forge_profiles::find("kali-lab").unwrap()
        ));
        assert!(!clone_profile_supported(
            &forge_profiles::find("fedora-lab").unwrap()
        ));
        assert!(!clone_profile_supported(
            &forge_profiles::find("whonix-gateway").unwrap()
        ));
    }

    #[test]
    fn workstation_abort_never_removes_a_foreign_active_pointer() {
        let root = std::env::temp_dir().join(format!(
            "forge-workstation-abort-pointer-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let state = root.join("fedora-workstation-44-1.7.json");
        let foreign = root.join("fedora-workstation-44-1.7-other.json");
        std::fs::write(&state, "state").unwrap();
        std::fs::write(&foreign, "foreign").unwrap();
        let pointer = root.join("fedora-workstation-44-1.7.active");
        std::fs::write(&pointer, format!("{}\n", foreign.display())).unwrap();
        assert!(validate_workstation_active_pointer(&state).is_err());
        retire_workstation_preparation_state(&state).unwrap();
        assert!(!state.exists());
        assert_eq!(
            std::fs::read_to_string(&pointer).unwrap(),
            format!("{}\n", foreign.display())
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn built_in_whonix_pair_rejects_noncanonical_instance_names_before_mutation() {
        let gateway = forge_profiles::whonix_gateway();
        let workstation = forge_profiles::whonix_workstation();
        assert!(
            validate_whonix_canonical_instance(
                &gateway,
                &InstanceName::new("whonix-gw-test").unwrap()
            )
            .is_err()
        );
        assert!(
            validate_whonix_canonical_instance(
                &workstation,
                &InstanceName::new("whonix-ws-test").unwrap()
            )
            .is_err()
        );
        assert!(
            validate_whonix_canonical_instance(
                &gateway,
                &InstanceName::new("whonix-gateway").unwrap()
            )
            .is_ok()
        );
        assert!(
            validate_whonix_canonical_instance(
                &workstation,
                &InstanceName::new("whonix-workstation").unwrap()
            )
            .is_ok()
        );
    }
}
