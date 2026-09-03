use forge_images::FedoraWorkstationPreparationBackend;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const HELPER: &str = "/usr/libexec/forge-preparation-control";
const GENERATOR: &str = "/usr/lib/systemd/system-generators/forge-preparation-control-generator";
const BINDING: &str = "/usr/lib/forge-preparation-control/binding.json";
const CHANNEL: &str = "org.majorforge.preparation.0";
const EXPECTED_PREPARATION: &str = "5d87db391be74e86bd0c7dca042295c3";
const EXPECTED_DOMAIN: &str = "forge-prepare-fedora-workstation-44-1.7-5d87db39";
const EXPECTED_UUID: &str = "ae82467d-10dd-4d33-b6ab-52f67e11e795";
const EXPECTED_STAGING: &str =
    "/var/lib/libvirt/images/forge-stage-fedora-workstation-44-1.7-5d87db39.qcow2";

#[derive(Serialize)]
struct BootstrapBinding<'a> {
    protocol_version: u32,
    preparation_id: &'a str,
    domain_name: &'a str,
    domain_uuid: &'a str,
    staging_path: &'a str,
    expected_state: &'static str,
    bootstrap_transaction_id: &'a str,
    helper_sha256: &'a str,
}

#[derive(Deserialize)]
struct Handshake {
    kind: String,
    protocol_version: u32,
    preparation_id: String,
    domain_uuid: String,
    bootstrap_transaction_id: String,
    helper_sha256: String,
}

fn main() -> ExitCode {
    let arguments = env::args().collect::<Vec<_>>();
    let result = match arguments.as_slice().get(1).map(String::as_str) {
        Some("discover") => read_only_recovery(),
        Some("execute") => execute(),
        _ => {
            eprintln!("usage: forge-b1 discover|execute");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("B1_STOP: {error}");
            ExitCode::from(1)
        }
    }
}

#[allow(clippy::too_many_lines)]
fn read_only_recovery() -> Result<(), String> {
    require_kernel_selinux()?;
    let home = env::var_os("HOME").ok_or("HOME unavailable")?;
    let state_path = forge_images::fedora_workstation_preparation_state_path(Path::new(&home));
    let preparation = forge_images::read_fedora_workstation_preparation(&state_path)
        .map_err(|e| e.to_string())?
        .ok_or("preparation absent")?;
    validate_binding(&preparation)?;
    let mut backend =
        forge_libvirt::LibvirtDefineBackend::connect_local().map_err(|e| e.to_string())?;
    if backend.canonical_base_exists("default", &preparation.canonical.volume_name)? {
        return Err("canonical base exists".to_owned());
    }
    let domain = backend
        .inspect_installer_domain(EXPECTED_DOMAIN)?
        .ok_or("preparation domain absent")?;
    if !domain.shutoff
        || domain.running
        || domain.autostart
        || domain.uuid != EXPECTED_UUID
        || domain.xml.contains("<channel")
        || domain.xml.contains("device='cdrom'")
    {
        return Err("offline domain prevalidation refused".to_owned());
    }
    forge_images::prove_fedora_workstation_disk_only_topology(&preparation, &domain)
        .map_err(|e| e.to_string())?;
    let volume = FedoraWorkstationPreparationBackend::inspect_volume(
        &mut backend,
        "default",
        &preparation.staging.volume_name,
    )?
    .ok_or("staging volume absent")?;
    if volume.path != preparation.staging.path
        || volume.key
            != preparation
                .execution
                .staging_volume_key
                .clone()
                .unwrap_or_default()
        || volume.format != "qcow2"
        || volume.capacity_bytes != preparation.staging.capacity_bytes
        || volume.backing_path.is_some()
    {
        return Err("staging volume identity/ownership drift".to_owned());
    }
    let qemu = Command::new("/usr/bin/pgrep")
        .args(["-af", "qemu-system"])
        .output()
        .map_err(|e| e.to_string())?;
    if String::from_utf8_lossy(&qemu.stdout).contains(EXPECTED_STAGING) {
        return Err("competing QEMU process owns staging".to_owned());
    }
    let proof = guestfish(&[
        "--ro",
        "-v",
        "-x",
        "-c",
        "qemu:///system",
        "-d",
        EXPECTED_DOMAIN,
        "-i",
        "echo",
        "FORGE_ROOTS_BEGIN",
        ":",
        "inspect-get-roots",
        ":",
        "echo",
        "FORGE_ROOTS_END",
        ":",
        "echo",
        "FORGE_OS_RELEASE_BEGIN",
        ":",
        "cat",
        "/etc/os-release",
        ":",
        "echo",
        "FORGE_OS_RELEASE_END",
        ":",
        "file-architecture",
        "/usr/bin/bash",
        ":",
        "list-filesystems",
        ":",
        "cat",
        "/etc/selinux/config",
    ])?;
    let roots = between(&proof, "FORGE_ROOTS_BEGIN", "FORGE_ROOTS_END")?
        .lines()
        .filter(|line| line.starts_with("/dev/"))
        .collect::<Vec<_>>();
    let os_release = between(&proof, "FORGE_OS_RELEASE_BEGIN", "FORGE_OS_RELEASE_END")?;
    if roots.len() != 1
        || !os_release.contains("ID=fedora")
        || !os_release.contains("VERSION_ID=44")
        || !os_release.to_ascii_lowercase().contains("workstation")
        || !proof.lines().any(|line| line.trim() == "x86_64")
        || !proof.contains("SELINUX=enforcing")
    {
        return Err("read-only Fedora Workstation discovery mismatch".to_owned());
    }
    println!("READ_ONLY_DISCOVERY_ROOT={}", roots[0]);
    println!("READ_ONLY_DISCOVERY=Fedora Workstation 44 x86_64");
    println!("READ_ONLY_DISCOVERY_OUTPUT={}", proof.replace('\n', " | "));
    Ok(())
}

fn between<'a>(value: &'a str, start: &str, end: &str) -> Result<&'a str, String> {
    value
        .split_once(start)
        .and_then(|(_, rest)| rest.split_once(end).map(|(middle, _)| middle))
        .ok_or_else(|| "structured guestfish output markers absent".to_owned())
}

#[allow(clippy::too_many_lines)]
fn execute() -> Result<(), String> {
    require_kernel_selinux()?;
    let home = env::var_os("HOME").ok_or("HOME unavailable")?;
    let state_path = forge_images::fedora_workstation_preparation_state_path(Path::new(&home));
    let mut preparation = forge_images::read_fedora_workstation_preparation(&state_path)
        .map_err(|e| e.to_string())?
        .ok_or("preparation absent")?;
    validate_binding(&preparation)?;
    if preparation.execution.helper_bootstrap.is_some()
        || preparation.execution.preparation_channel.is_some()
        || preparation.execution.read_only_guest_inventory.is_some()
    {
        return Err("B1 evidence already exists; no retry".to_owned());
    }

    let mut backend =
        forge_libvirt::LibvirtDefineBackend::connect_local().map_err(|e| e.to_string())?;
    if backend.canonical_base_exists("default", &preparation.canonical.volume_name)? {
        return Err("canonical base exists".to_owned());
    }
    let domain = backend
        .inspect_installer_domain(EXPECTED_DOMAIN)?
        .ok_or("preparation domain absent")?;
    if !domain.shutoff
        || domain.running
        || domain.autostart
        || domain.uuid != EXPECTED_UUID
        || domain.xml.contains("<channel")
        || domain.xml.contains("device='cdrom'")
    {
        return Err("offline domain prevalidation refused".to_owned());
    }
    let volume = FedoraWorkstationPreparationBackend::inspect_volume(
        &mut backend,
        "default",
        &preparation.staging.volume_name,
    )?
    .ok_or("staging volume absent")?;
    if volume.path != preparation.staging.path
        || volume.key
            != preparation
                .execution
                .staging_volume_key
                .clone()
                .unwrap_or_default()
        || volume.format != "qcow2"
        || volume.capacity_bytes != preparation.staging.capacity_bytes
        || volume.backing_path.is_some()
    {
        return Err("staging volume identity/ownership drift".to_owned());
    }
    let qemu = Command::new("/usr/bin/pgrep")
        .args(["-af", "qemu-system"])
        .output()
        .map_err(|e| e.to_string())?;
    if String::from_utf8_lossy(&qemu.stdout).contains(EXPECTED_STAGING) {
        return Err("competing QEMU process owns staging".to_owned());
    }
    let proven = forge_images::prove_fedora_workstation_disk_only_topology(&preparation, &domain)
        .map_err(|e| e.to_string())?;
    if preparation.execution.disk_only_topology.as_ref() != Some(&proven) {
        return Err("disk-only topology evidence drift".to_owned());
    }
    println!("PREVALIDATION=proven-offline-exclusive");

    let helper = helper_artifact()?;
    let helper_bytes = fs::metadata(&helper).map_err(|e| e.to_string())?.len();
    let helper_sha256 = digest(&helper)?;
    let transaction = identity(
        "bootstrap",
        &[EXPECTED_PREPARATION, EXPECTED_UUID, &helper_sha256],
    );
    let operation_id = identity("inventory", &[EXPECTED_PREPARATION, &transaction]);
    let nonce = identity(
        "nonce",
        &[EXPECTED_UUID, &operation_id, &now()?.to_string()],
    );

    let root = discover(&preparation.staging.path)?;
    println!("DISCOVERY_ROOT={root}");
    inject(
        &preparation.staging.path,
        &helper,
        &helper_sha256,
        &transaction,
    )?;
    prove_injection(&preparation.staging.path, &helper_sha256, helper_bytes)?;

    let cleanup = forge_images::guest_channel_cleanup_inventory();
    preparation.execution.helper_bootstrap = Some(forge_images::PreparationHelperBootstrap {
        preparation_id: preparation.preparation_id.clone(),
        domain_uuid: preparation.installer.uuid.clone(),
        staging_path: preparation.staging.path.clone(),
        helper_sha256: helper_sha256.clone(),
        helper_bytes,
        generator_sha256: helper_sha256.clone(),
        generator_bytes: helper_bytes,
        binding_sha256: String::new(),
        binding_bytes: 0,
        guest_paths: vec![HELPER.into(), GENERATOR.into(), BINDING.into()],
        guest_modes: vec!["0:0:0755".into(), "0:0:0755".into(), "0:0:0600".into()],
        guest_selinux_labels: vec![
            "bin_t".into(),
            "systemd_generic_generator_exec_t".into(),
            "lib_t".into(),
        ],
        structured_verification_proven: true,
        clean_close: true,
        unexpected_paths_modified: false,
        helper_protocol_version: forge_images::FORGE_GUEST_CONTROL_PROTOCOL_VERSION,
        bootstrap_transaction_id: transaction.clone(),
        guest_installation_path: HELPER.into(),
        persistent_activation_path: GENERATOR.into(),
        temporary_activation_path: "/run/systemd/system/forge-preparation-control.service".into(),
        channel_name: CHANNEL.to_owned(),
        expected_state: forge_images::FedoraWorkstationPreparationStatus::InstalledSystemProven,
        cleanup_inventory: cleanup.clone(),
    });
    forge_images::update_fedora_workstation_preparation(&state_path, &preparation)
        .map_err(|e| e.to_string())?;
    println!("BOOTSTRAP_EVIDENCE=published");

    backend.attach_preparation_control_channel(EXPECTED_DOMAIN)?;
    let channel_xml = backend.preparation_domain_xml(EXPECTED_DOMAIN)?;
    prove_channel_xml(&channel_xml)?;
    preparation.execution.preparation_channel = Some(forge_images::PreparationChannelEvidence {
        preparation_id: preparation.preparation_id.clone(),
        domain_uuid: preparation.installer.uuid.clone(),
        staging_path: preparation.staging.path.clone(),
        bootstrap_transaction_id: transaction.clone(),
        protocol_version: forge_images::FORGE_GUEST_CONTROL_PROTOCOL_VERSION,
        channel_name: CHANNEL.to_owned(),
        host_endpoint: format!("libvirt-stream:qemu:///system/{EXPECTED_DOMAIN}/{CHANNEL}"),
    });
    forge_images::update_fedora_workstation_preparation(&state_path, &preparation)
        .map_err(|e| e.to_string())?;
    println!("CHANNEL_EVIDENCE=published");

    backend.start_preparation_domain(EXPECTED_DOMAIN)?;
    if !backend.preparation_domain_running(EXPECTED_DOMAIN)? {
        return Err("single boot did not reach running".to_owned());
    }
    println!("BOOT=running");
    let request = forge_images::create_read_only_guest_inventory_request(
        &preparation,
        &operation_id,
        &nonce,
        true,
        true,
    )
    .map_err(|e| e.to_string())?;
    let request_bytes = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
    let (handshake_json, result_json) =
        backend.preparation_control_exchange(EXPECTED_DOMAIN, &request_bytes)?;
    let handshake: Handshake = serde_json::from_str(&handshake_json).map_err(|e| e.to_string())?;
    if handshake.kind != "Handshake"
        || handshake.protocol_version != 1
        || handshake.preparation_id != EXPECTED_PREPARATION
        || handshake.domain_uuid != EXPECTED_UUID
        || handshake.bootstrap_transaction_id != transaction
        || handshake.helper_sha256 != helper_sha256
    {
        return Err("typed handshake mismatch".to_owned());
    }
    println!("HANDSHAKE=proven");
    let result: forge_images::GuestControlResult =
        serde_json::from_str(&result_json).map_err(|e| e.to_string())?;
    let guest_sequence = result.guest_sequence;
    let evidence = forge_images::prove_read_only_guest_inventory(
        &preparation,
        &request,
        result,
        forge_images::GuestOperationLedgerState::SentAwaitingResult,
    )
    .map_err(|e| e.to_string())?;
    preparation.execution.read_only_guest_inventory =
        Some(forge_images::PublishedReadOnlyGuestInventory {
            operation_id,
            nonce,
            guest_sequence,
            inventory: evidence.inventory().clone(),
        });
    forge_images::update_fedora_workstation_preparation(&state_path, &preparation)
        .map_err(|e| e.to_string())?;
    println!("INVENTORY_EVIDENCE=published");
    println!(
        "INVENTORY={}",
        serde_json::to_string(evidence.inventory()).map_err(|e| e.to_string())?
    );
    Ok(())
}

fn validate_binding(p: &forge_images::FedoraWorkstationPreparation) -> Result<(), String> {
    if p.preparation_id.as_str() != EXPECTED_PREPARATION
        || p.status != forge_images::FedoraWorkstationPreparationStatus::InstalledSystemProven
        || p.installer.name != EXPECTED_DOMAIN
        || p.installer.uuid != EXPECTED_UUID
        || p.staging.path != Path::new(EXPECTED_STAGING)
        || p.installer.disk_path != p.staging.path
        || p.installer.seed.is_some()
        || p.installer.qga_required
        || p.installer.filesystem_passthrough
        || p.execution
            .graphical_boot_confirmation
            .as_ref()
            .is_none_or(|v| v.gnome_initial_setup_completed)
    {
        return Err("durable preparation binding refused".to_owned());
    }
    Ok(())
}

fn require_kernel_selinux() -> Result<(), String> {
    (fs::read_to_string("/sys/fs/selinux/enforce")
        .map_err(|e| e.to_string())?
        .trim()
        == "1")
        .then_some(())
        .ok_or_else(|| "SELinux kernel enforcement is not 1".to_owned())
}

fn helper_artifact() -> Result<PathBuf, String> {
    let path = PathBuf::from("target/debug/forge-preparation-control");
    path.is_file()
        .then_some(path)
        .ok_or_else(|| "validated helper artifact absent".to_owned())
}

fn digest(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0_u8; 131_072];
    loop {
        let n = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn now() -> Result<u128, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_nanos())
        .map_err(|e| e.to_string())
}
fn identity(kind: &str, values: &[&str]) -> String {
    let mut h = Sha256::new();
    h.update(kind);
    for value in values {
        h.update([0]);
        h.update(value);
    }
    format!("{kind}-{:x}", h.finalize())
}

fn discover(staging: &Path) -> Result<String, String> {
    let staging = staging.to_str().ok_or("non-UTF8 staging path")?;
    let roots = guestfish(&[
        "--ro",
        "--format=qcow2",
        "-a",
        staging,
        "run",
        ":",
        "inspect-os",
    ])?;
    let roots = roots
        .lines()
        .filter(|v| !v.trim().is_empty())
        .collect::<Vec<_>>();
    if roots.len() != 1 {
        return Err("ambiguous guest OS roots".to_owned());
    }
    let root = roots[0].trim().to_owned();
    let facts = guestfish(&[
        "--ro",
        "--format=qcow2",
        "-a",
        staging,
        "-i",
        "cat",
        "/etc/os-release",
        ":",
        "inspect-get-arch",
        &root,
        ":",
        "is-file",
        HELPER,
    ])?;
    if !facts.contains("ID=fedora")
        || !facts.contains("VERSION_ID=44")
        || !facts.to_ascii_lowercase().contains("workstation")
        || !facts.lines().any(|v| v.trim() == "x86_64")
        || !facts.lines().any(|v| v.trim() == "false")
    {
        return Err("Fedora Workstation 44 x86_64 discovery mismatch".to_owned());
    }
    Ok(root)
}

fn inject(
    staging: &Path,
    helper: &Path,
    helper_sha256: &str,
    transaction: &str,
) -> Result<(), String> {
    let temporary = PathBuf::from(format!("/tmp/forge-b1-{}", std::process::id()));
    if temporary.exists() {
        return Err("bootstrap temporary collision".to_owned());
    }
    let libexec = temporary.join("libexec");
    let generators = temporary.join("generators");
    let bindings = temporary.join("binding");
    fs::create_dir_all(&libexec)
        .and_then(|()| fs::create_dir_all(&generators))
        .and_then(|()| fs::create_dir_all(&bindings))
        .map_err(|e| e.to_string())?;
    fs::copy(helper, libexec.join("forge-preparation-control")).map_err(|e| e.to_string())?;
    fs::copy(
        helper,
        generators.join("forge-preparation-control-generator"),
    )
    .map_err(|e| e.to_string())?;
    let binding = BootstrapBinding {
        protocol_version: 1,
        preparation_id: EXPECTED_PREPARATION,
        domain_name: EXPECTED_DOMAIN,
        domain_uuid: EXPECTED_UUID,
        staging_path: EXPECTED_STAGING,
        expected_state: "InstalledSystemProven",
        bootstrap_transaction_id: transaction,
        helper_sha256,
    };
    fs::write(
        bindings.join("binding.json"),
        serde_json::to_vec_pretty(&binding).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let staging = staging.to_str().ok_or("non-UTF8 staging path")?;
    let output = guestfish(&[
        "--rw",
        "--format=qcow2",
        "-a",
        staging,
        "-i",
        "mkdir-p",
        "/usr/lib/forge-preparation-control",
        ":",
        "copy-in",
        libexec
            .join("forge-preparation-control")
            .to_str()
            .ok_or("temp path")?,
        "/usr/libexec",
        ":",
        "copy-in",
        generators
            .join("forge-preparation-control-generator")
            .to_str()
            .ok_or("temp path")?,
        "/usr/lib/systemd/system-generators",
        ":",
        "copy-in",
        bindings.join("binding.json").to_str().ok_or("temp path")?,
        "/usr/lib/forge-preparation-control",
        ":",
        "chmod",
        "0755",
        HELPER,
        ":",
        "chmod",
        "0755",
        GENERATOR,
        ":",
        "chmod",
        "0600",
        BINDING,
        ":",
        "setxattr",
        "security.selinux",
        "system_u:object_r:bin_t:s0",
        "26",
        HELPER,
        ":",
        "setxattr",
        "security.selinux",
        "system_u:object_r:systemd_generic_generator_exec_t:s0",
        "53",
        GENERATOR,
        ":",
        "setxattr",
        "security.selinux",
        "system_u:object_r:lib_t:s0",
        "26",
        BINDING,
    ])?;
    fs::remove_dir_all(&temporary).map_err(|e| e.to_string())?;
    if !output.trim().is_empty() {
        println!("INJECTION_DIAGNOSTIC={}", output.trim());
    }
    Ok(())
}

fn prove_injection(staging: &Path, digest: &str, bytes: u64) -> Result<(), String> {
    let staging = staging.to_str().ok_or("non-UTF8 staging path")?;
    let proof = guestfish(&[
        "--ro",
        "--format=qcow2",
        "-a",
        staging,
        "-i",
        "checksum",
        "sha256",
        HELPER,
        ":",
        "statns",
        HELPER,
        ":",
        "getxattr",
        HELPER,
        "security.selinux",
        ":",
        "checksum",
        "sha256",
        GENERATOR,
        ":",
        "getxattr",
        GENERATOR,
        "security.selinux",
        ":",
        "cat",
        BINDING,
    ])?;
    if !proof.contains(digest)
        || !proof.contains(&bytes.to_string())
        || !proof.contains("bin_t")
        || !proof.contains("systemd_generic_generator_exec_t")
        || !proof.contains(EXPECTED_PREPARATION)
    {
        return Err("offline helper proof mismatch".to_owned());
    }
    println!("OFFLINE_HELPER_PROOF={}", proof.replace('\n', " | "));
    Ok(())
}

fn prove_channel_xml(xml: &str) -> Result<(), String> {
    if xml.matches("<channel").count() != 1
        || !xml.contains(CHANNEL)
        || xml.contains("org.qemu.guest_agent.0")
        || xml.matches("device='disk'").count() != 1
        || xml.contains("device='cdrom'")
        || !xml.contains(EXPECTED_STAGING)
        || !xml.contains("52:54:00:28:d0:55")
    {
        return Err("post-channel topology mismatch".to_owned());
    }
    Ok(())
}

fn guestfish(arguments: &[&str]) -> Result<String, String> {
    let mut child = Command::new("/usr/bin/guestfish")
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    loop {
        if child.try_wait().map_err(|e| e.to_string())?.is_some() {
            break;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().map_err(|e| e.to_string())?;
            return Err("guestfish timeout".to_owned());
        }
        thread::sleep(Duration::from_millis(50));
    }
    let output = child.wait_with_output().map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(format!(
            "guestfish exit {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let diagnostics = String::from_utf8_lossy(&output.stderr)
        .lines()
        .filter(|line| {
            line.contains("backend=")
                || line.contains("opening libvirt handle")
                || line.contains("appliance is up")
                || line.contains("readonly")
                || line.contains("shutdown =")
        })
        .collect::<Vec<_>>()
        .join(" | ");
    if !diagnostics.is_empty() {
        println!("GUESTFISH_DIAGNOSTICS={diagnostics}");
    }
    String::from_utf8(output.stdout).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_topology_requires_one_fixed_non_qga_channel() {
        let xml = format!(
            "<domain><devices><disk device='disk'><source file='{EXPECTED_STAGING}'/></disk><interface><mac address='52:54:00:28:d0:55'/></interface><channel><target name='{CHANNEL}'/></channel></devices></domain>"
        );
        assert!(prove_channel_xml(&xml).is_ok());
        assert!(prove_channel_xml(&xml.replace("</devices>", "<channel/></devices>")).is_err());
        assert!(prove_channel_xml(&xml.replace(CHANNEL, "org.qemu.guest_agent.0")).is_err());
    }

    #[test]
    fn deterministic_identities_bind_all_inputs() {
        let a = identity(
            "bootstrap",
            &[EXPECTED_PREPARATION, EXPECTED_UUID, "digest"],
        );
        assert_eq!(
            a,
            identity(
                "bootstrap",
                &[EXPECTED_PREPARATION, EXPECTED_UUID, "digest"]
            )
        );
        assert_ne!(
            a,
            identity("bootstrap", &[EXPECTED_PREPARATION, EXPECTED_UUID, "other"])
        );
    }

    #[test]
    fn structured_discovery_markers_refuse_missing_or_ambiguous_output() {
        assert_eq!(between("A\nroot\nB", "A", "B").unwrap().trim(), "root");
        assert!(between("root", "A", "B").is_err());
    }
}
