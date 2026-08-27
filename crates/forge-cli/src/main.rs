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
        ["vm", "cleanup", "fedora-lab"] => managed_cleanup(false),
        ["vm", "start", "fedora-lab", "--dry-run"] => lifecycle_action(true, true),
        ["vm", "start", "fedora-lab"] => lifecycle_action(true, false),
        ["vm", "shutdown", "fedora-lab", "--dry-run"] => lifecycle_action(false, true),
        ["vm", "shutdown", "fedora-lab"] => lifecycle_action(false, false),
        ["state", "show", "fedora-lab"] => state_show(),
        ["state", "reconcile", "fedora-lab"] => state_reconcile(),
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
    let layout = match managed_state_layout() {
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
    let observed = match discover_state() {
        Ok(observed) => observed,
        Err(error) => {
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
    managed_cleanup(true)
}

fn managed_state_layout() -> Result<forge_state::StateLayout, String> {
    let home = env::var_os("HOME").ok_or_else(|| "HOME is unavailable".to_owned())?;
    Ok(forge_state::StateLayout::new(
        &forge_state::state_directory(std::path::Path::new(&home)),
        "fedora-lab",
    ))
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
    let mut evidence = Vec::new();
    for manifest in &manifests {
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
                        referenced_by_domains: found
                            .map(|item| item.referenced_by_domains.clone())
                            .unwrap_or_default(),
                        backing_for_volumes: found
                            .map(|item| item.backing_for_volumes.clone())
                            .unwrap_or_default(),
                        identity_matches: found.is_some_and(|item| {
                            item.volume_name == expected.volume_name
                                && item.volume_key == expected.volume_key
                                && item.path == expected.path
                                && item.format == expected.format
                                && item.capacity_bytes == expected.capacity_bytes
                                && item.backing_path == expected.backing_path
                        }),
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
                    referenced_by_domains: Vec::new(),
                    backing_for_volumes: Vec::new(),
                    identity_matches: false,
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
        evidence.push(forge_state::RetainedEvidence {
            manifest: authoritative,
            resources,
        });
    }
    let plan = match forge_state::plan_managed_cleanup(
        &index,
        &evidence,
        observed_active.unmanaged_resources.clone(),
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
    println!("ACTIVE OWNED GENERATION\n- {}", plan.active_generation_id);
    println!("RETAINED OWNED GENERATIONS");
    if plan.retained_generation_ids.is_empty() {
        println!("- none");
    } else {
        for id in &plan.retained_generation_ids {
            println!("- {id}");
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
    // Re-run the complete read-only plan immediately before exact deletion.
    let Ok(Some(fresh)) = forge_state::read_index(&layout.index) else {
        eprintln!("cleanup revalidation failed: index changed");
        return ExitCode::from(1);
    };
    if fresh != index {
        eprintln!("cleanup revalidation failed: generation index changed");
        return ExitCode::from(1);
    }
    let mut next = index.clone();
    for candidate in &plan.candidates {
        for resource in &candidate.resources {
            if let Err(error) = backend.delete_managed_volume_exact(resource) {
                eprintln!(
                    "partial cleanup stopped at {}: {error}; no further resource was deleted",
                    resource.path
                );
                return ExitCode::from(1);
            }
        }
        next = match forge_state::remove_generation(&next, &candidate.generation_id) {
            Ok(value) => value,
            Err(error) => {
                eprintln!("resources deleted but state update requires recovery: {error}");
                return ExitCode::from(1);
            }
        };
        if let Err(error) = forge_state::write_index_atomic(&layout.index, &next) {
            eprintln!("resources deleted but state update requires recovery: {error}");
            return ExitCode::from(1);
        }
    }
    println!(
        "Exact retained-owned cleanup completed; shared base and unmanaged legacy were untouched."
    );
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
        backend
            .shutdown_and_wait(Duration::from_secs(plan.timeout_seconds))
            .map(|_| ())
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
