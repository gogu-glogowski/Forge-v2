use forge_images::FedoraWorkstationPreparationBackend;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{Command, ExitCode, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const SOCKET_DIR: &str = "/run/forge-preparation-broker";
const SOCKET: &str = "/run/forge-preparation-broker/broker.sock";
const LEDGER_DIR: &str = "/var/lib/forge-preparation-broker";
const LEDGER: &str = "/var/lib/forge-preparation-broker/ledger";
const SERVICE_STATE_DIR: &str = "/var/lib/forge-preparation-broker";
const LIBGUESTFS_CACHE_DIR: &str = "/var/cache/forge-preparation-broker";
const LIBGUESTFS_TMP_DIR: &str = "/var/tmp";
const STATE: &str =
    "/home/majorforge/.local/share/forge/preparations/fedora-workstation-44-1.7.json";
const PREPARATION: &str = "5d87db391be74e86bd0c7dca042295c3";
const DOMAIN: &str = "forge-prepare-fedora-workstation-44-1.7-5d87db39";
const UUID: &str = "ae82467d-10dd-4d33-b6ab-52f67e11e795";
const STAGING: &str =
    "/var/lib/libvirt/images/forge-stage-fedora-workstation-44-1.7-5d87db39.qcow2";
const SYNTHETIC: &str = "/var/lib/forge-preparation-broker/direct-backend-test.qcow2";
const BROKER_VERSION: &str = "forge-preparation-broker/1";
const MAX_MESSAGE: usize = 64 * 1024;
const MAX_OUTPUT: usize = 1024 * 1024;
const ROOT_BEGIN: &str = "FORGE_ROOT_BEGIN";
const ROOT_END: &str = "FORGE_ROOT_END";

enum BrokerSuccess {
    Inspection(Box<forge_images::PreparationBrokerResult>),
    ApplianceSelfTest(forge_images::PreparationBrokerApplianceSelfTestResult),
    SyntheticDirectSelfTest(forge_images::PreparationBrokerSyntheticDirectResult),
}

enum BrokerFailure {
    Code(String),
    Identity(Box<forge_images::PreparationGuestIdentityDiagnostics>),
}

impl From<String> for BrokerFailure {
    fn from(value: String) -> Self {
        Self::Code(value)
    }
}

impl From<&str> for BrokerFailure {
    fn from(value: &str) -> Self {
        Self::Code(value.to_owned())
    }
}

#[derive(Clone)]
#[allow(clippy::struct_excessive_bools)]
struct PrivilegedObservation {
    shutoff: bool,
    autostart: bool,
    uuid: String,
    disk_count: usize,
    disk_path: String,
    installer_cdrom: bool,
    channel: bool,
    canonical_base: bool,
    competing_qemu: bool,
    volume_key_matches: bool,
    qcow2: bool,
    capacity: u64,
    backing: bool,
    owner: u32,
    group: u32,
    mode: u32,
    selinux_label: String,
    kernel_selinux_enforcing: bool,
}

#[derive(Debug, PartialEq, Eq)]
struct HostStorageIdentity {
    inode: u64,
    owner: u32,
    group: u32,
    mode: u32,
    size: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
    acl: String,
    selinux_label: Vec<u8>,
    qcow2_capacity: u64,
    qcow2_backing: Option<String>,
    qcow2_dirty: bool,
    qcow2_corrupt: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum RootDiscoveryFailure {
    InspectCommandFailed,
    ParserFailed,
}

fn validate_privileged_observation(value: &PrivilegedObservation) -> Result<(), String> {
    if !value.shutoff
        || value.autostart
        || value.uuid != UUID
        || value.disk_count != 1
        || value.disk_path != STAGING
        || value.installer_cdrom
        || value.channel
        || value.canonical_base
        || value.competing_qemu
        || !value.volume_key_matches
        || !value.qcow2
        || value.capacity != 80 * 1024 * 1024 * 1024
        || value.backing
        || value.owner != 0
        || value.group != 0
        || value.mode != 0o600
        || !value
            .selinux_label
            .starts_with("system_u:object_r:virt_image_t:s0")
        || !value.kernel_selinux_enforcing
    {
        return Err("PrivilegedObservationRefused".to_owned());
    }
    Ok(())
}

fn main() -> ExitCode {
    match serve() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("forge-preparation-broker: {error}");
            ExitCode::from(1)
        }
    }
}

fn serve() -> Result<(), String> {
    if !rustix::process::geteuid().is_root() {
        return Err("broker must run as root".to_owned());
    }
    prepare_service_environment()?;
    fs::create_dir_all(SOCKET_DIR).map_err(|e| e.to_string())?;
    fs::set_permissions(SOCKET_DIR, fs::Permissions::from_mode(0o770))
        .map_err(|e| e.to_string())?;
    if Path::new(SOCKET).exists() {
        fs::remove_file(SOCKET).map_err(|e| e.to_string())?;
    }
    let listener = UnixListener::bind(SOCKET).map_err(|e| e.to_string())?;
    fs::set_permissions(SOCKET, fs::Permissions::from_mode(0o660)).map_err(|e| e.to_string())?;
    for connection in listener.incoming() {
        let mut stream = connection.map_err(|e| e.to_string())?;
        let response = match handle(&mut stream) {
            Ok(BrokerSuccess::Inspection(result)) => {
                forge_images::PreparationBrokerResponse::Success { result }
            }
            Ok(BrokerSuccess::ApplianceSelfTest(result)) => {
                forge_images::PreparationBrokerResponse::ApplianceSelfTestSuccess { result }
            }
            Ok(BrokerSuccess::SyntheticDirectSelfTest(result)) => {
                forge_images::PreparationBrokerResponse::SyntheticDirectSelfTestSuccess { result }
            }
            Err(BrokerFailure::Identity(diagnostics)) => {
                forge_images::PreparationBrokerResponse::IdentityRefusal {
                    error_code: "GuestIdentityPredicateRefused".to_owned(),
                    diagnostics: *diagnostics,
                }
            }
            Err(BrokerFailure::Code(error)) if is_refusal(&error) => {
                forge_images::PreparationBrokerResponse::Refusal { error_code: error }
            }
            Err(BrokerFailure::Code(error)) => {
                forge_images::PreparationBrokerResponse::InternalError { error_code: error }
            }
        };
        serde_json::to_writer(&mut stream, &response).map_err(|e| e.to_string())?;
        stream.write_all(b"\n").map_err(|e| e.to_string())?;
        stream.flush().map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn prepare_service_environment() -> Result<(), String> {
    let state = fs::metadata(SERVICE_STATE_DIR).map_err(|e| e.to_string())?;
    if state.uid() != 0 || state.mode() & 0o777 != 0o700 {
        return Err("ServiceStateDirectoryRefused".to_owned());
    }
    fs::create_dir_all(LIBGUESTFS_CACHE_DIR).map_err(|e| e.to_string())?;
    fs::set_permissions(LIBGUESTFS_CACHE_DIR, fs::Permissions::from_mode(0o755))
        .map_err(|e| e.to_string())?;
    let readiness = Path::new(LIBGUESTFS_CACHE_DIR).join(".forge-write-readiness");
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&readiness)
        .map_err(|e| e.to_string())?;
    fs::remove_file(readiness).map_err(|e| e.to_string())
}

fn handle(stream: &mut UnixStream) -> Result<BrokerSuccess, BrokerFailure> {
    let credentials =
        rustix::net::sockopt::get_socket_peercred(&*stream).map_err(|e| e.to_string())?;
    if credentials.uid.as_raw() != 1000 && !credentials.uid.is_root() {
        return Err("UnauthorizedPeer".into());
    }
    let mut line = String::new();
    BufReader::new(stream.try_clone().map_err(|e| e.to_string())?)
        .take(MAX_MESSAGE as u64)
        .read_line(&mut line)
        .map_err(|e| e.to_string())?;
    if line.is_empty() || line.len() >= MAX_MESSAGE {
        return Err("MalformedProtocol".into());
    }
    if let Ok(request) =
        serde_json::from_str::<forge_images::PreparationBrokerDiagnosticRequest>(&line)
    {
        return match request.operation {
            forge_images::PreparationBrokerDiagnosticOperation::SelfTestLibguestfsAppliance => {
                appliance_self_test(&request)
                    .map(BrokerSuccess::ApplianceSelfTest)
                    .map_err(BrokerFailure::Code)
            }
            forge_images::PreparationBrokerDiagnosticOperation::SelfTestDirectBackendSynthetic => {
                synthetic_direct_self_test(&request)
                    .map(BrokerSuccess::SyntheticDirectSelfTest)
                    .map_err(BrokerFailure::Code)
            }
        };
    }
    let request: forge_images::PreparationBrokerRequest =
        serde_json::from_str(&line).map_err(|_| "MalformedProtocol".to_owned())?;
    inspect(&request).map(|result| BrokerSuccess::Inspection(Box::new(result)))
}

fn is_refusal(error: &str) -> bool {
    error == "MalformedProtocol"
        || error == "UnauthorizedPeer"
        || error.ends_with("Refused")
        || error == "CanonicalBasePresent"
        || error == "ReplayRefused"
        || error == "CompetingQemuRefused"
}

fn appliance_self_test(
    request: &forge_images::PreparationBrokerDiagnosticRequest,
) -> Result<forge_images::PreparationBrokerApplianceSelfTestResult, String> {
    if request.protocol_version != forge_images::FORGE_PREPARATION_BROKER_PROTOCOL_VERSION
        || request.operation
            != forge_images::PreparationBrokerDiagnosticOperation::SelfTestLibguestfsAppliance
        || request.operation_id.len() < 16
        || request.operation_id.len() > 128
        || request.nonce.len() < 32
        || request.nonce.len() > 128
    {
        return Err("DiagnosticRequestRefused".to_owned());
    }
    let started = Instant::now();
    let (stdout, _stderr) = diagnostic_output(
        "/usr/bin/guestfish",
        &["run", ":", "echo", "FORGE_APPLIANCE_READY"],
        Duration::from_secs(120),
    )?;
    if String::from_utf8_lossy(&stdout).trim() != "FORGE_APPLIANCE_READY" {
        return Err("DiagnosticApplianceMarkerRefused".to_owned());
    }
    let version = fixed_output("/usr/bin/guestfish", &["--version"], Duration::from_secs(5))?;
    Ok(forge_images::PreparationBrokerApplianceSelfTestResult {
        protocol_version: request.protocol_version,
        operation: request.operation,
        operation_id: request.operation_id.clone(),
        nonce: request.nonce.clone(),
        broker_version: BROKER_VERSION.to_owned(),
        libguestfs_version: String::from_utf8_lossy(&version.0).trim().to_owned(),
        backend: "libvirt:qemu:///system".to_owned(),
        elapsed_millis: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
        appliance_initialized: true,
        disk_count: 0,
    })
}

fn synthetic_direct_self_test(
    request: &forge_images::PreparationBrokerDiagnosticRequest,
) -> Result<forge_images::PreparationBrokerSyntheticDirectResult, String> {
    if request.protocol_version != forge_images::FORGE_PREPARATION_BROKER_PROTOCOL_VERSION
        || request.operation
            != forge_images::PreparationBrokerDiagnosticOperation::SelfTestDirectBackendSynthetic
        || request.operation_id.len() < 16
        || request.operation_id.len() > 128
        || request.nonce.len() < 32
        || request.nonce.len() > 128
    {
        return Err("DiagnosticRequestRefused".to_owned());
    }
    let path = Path::new(SYNTHETIC);
    let before = fs::metadata(path).map_err(|e| e.to_string())?;
    if before.uid() != 0 || before.gid() != 0 || before.mode() & 0o777 != 0o600 {
        return Err("SyntheticMetadataRefused".to_owned());
    }
    let mut before_label = [0_u8; 256];
    let before_label_len = rustix::fs::getxattr(path, "security.selinux", &mut before_label)
        .map_err(|e| e.to_string())?;
    let sha256_before = digest(path)?;
    let started = Instant::now();
    let (stdout, _stderr) = execute_configured(
        configured_command_with_backend(
            "/usr/bin/guestfish",
            &[
                "--ro",
                "--format=qcow2",
                "-a",
                SYNTHETIC,
                "run",
                ":",
                "list-devices",
            ],
            false,
            "direct",
        ),
        Duration::from_secs(120),
    )
    .and_then(|(status, stdout, stderr)| {
        if status.success() {
            Ok((stdout, stderr))
        } else {
            Err(format!(
                "SyntheticDirectFailure({:?}): {}",
                status.code(),
                String::from_utf8_lossy(&stderr)
            ))
        }
    })?;
    if String::from_utf8_lossy(&stdout).trim() != "/dev/sda" {
        return Err("SyntheticDeviceRefused".to_owned());
    }
    let after = fs::metadata(path).map_err(|e| e.to_string())?;
    let mut after_label = [0_u8; 256];
    let after_label_len = rustix::fs::getxattr(path, "security.selinux", &mut after_label)
        .map_err(|e| e.to_string())?;
    let sha256_after = digest(path)?;
    let metadata_unchanged = before.ino() == after.ino()
        && before.uid() == after.uid()
        && before.gid() == after.gid()
        && before.mode() == after.mode()
        && before_label[..before_label_len] == after_label[..after_label_len]
        && sha256_before == sha256_after;
    if !metadata_unchanged {
        return Err("SyntheticImmutabilityRefused".to_owned());
    }
    let version = fixed_output("/usr/bin/guestfish", &["--version"], Duration::from_secs(5))?;
    Ok(forge_images::PreparationBrokerSyntheticDirectResult {
        protocol_version: request.protocol_version,
        operation: request.operation,
        operation_id: request.operation_id.clone(),
        nonce: request.nonce.clone(),
        broker_version: BROKER_VERSION.to_owned(),
        libguestfs_version: String::from_utf8_lossy(&version.0).trim().to_owned(),
        backend: "direct".to_owned(),
        elapsed_millis: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
        disk_count: 1,
        metadata_unchanged,
        sha256_before,
        sha256_after,
    })
}

#[allow(clippy::too_many_lines)]
fn inspect(
    request: &forge_images::PreparationBrokerRequest,
) -> Result<forge_images::PreparationBrokerResult, BrokerFailure> {
    validate_request(request)?;
    fs::create_dir_all(LEDGER_DIR).map_err(|e| e.to_string())?;
    let mut ledger = OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .mode(0o600)
        .open(LEDGER)
        .map_err(|e| e.to_string())?;
    rustix::fs::flock(&ledger, rustix::fs::FlockOperation::LockExclusive)
        .map_err(|e| e.to_string())?;
    let mut seen = String::new();
    File::open(LEDGER)
        .and_then(|mut file| file.read_to_string(&mut seen))
        .map_err(|e| e.to_string())?;
    if seen.lines().any(|line| line == request.nonce) {
        return Err("ReplayRefused".into());
    }

    let preparation = forge_images::read_fedora_workstation_preparation(Path::new(STATE))
        .map_err(|e| e.to_string())?
        .ok_or("PreparationAbsent")?;
    validate_preparation(&preparation, request)?;
    let mut backend =
        forge_libvirt::LibvirtDefineBackend::connect_local().map_err(|e| e.to_string())?;
    if backend.canonical_base_exists("default", &preparation.canonical.volume_name)? {
        return Err("CanonicalBasePresent".into());
    }
    let domain = backend
        .inspect_installer_domain(DOMAIN)?
        .ok_or("DomainAbsent")?;
    if !domain.shutoff
        || domain.running
        || domain.autostart
        || domain.uuid != UUID
        || domain.xml.contains("<channel")
        || domain.xml.contains("device='cdrom'")
    {
        return Err("DomainTopologyRefused".into());
    }
    forge_images::prove_fedora_workstation_disk_only_topology(&preparation, &domain)
        .map_err(|e| e.to_string())?;
    let volume = FedoraWorkstationPreparationBackend::inspect_volume(
        &mut backend,
        "default",
        &preparation.staging.volume_name,
    )?
    .ok_or("VolumeAbsent")?;
    if volume.name != preparation.staging.volume_name
        || volume.key
            != preparation
                .execution
                .staging_volume_key
                .clone()
                .unwrap_or_default()
        || volume.path != preparation.staging.path
        || volume.format != "qcow2"
        || volume.capacity_bytes != 80 * 1024 * 1024 * 1024
        || volume.backing_path.is_some()
    {
        return Err("StorageIdentityRefused".into());
    }
    let host_identity_before = capture_host_storage_identity(Path::new(STAGING))?;
    validate_storage(&host_identity_before)?;
    let competing_qemu = competing_qemu_exists()?;
    validate_privileged_observation(&PrivilegedObservation {
        shutoff: domain.shutoff && !domain.running,
        autostart: domain.autostart,
        uuid: domain.uuid.clone(),
        disk_count: domain.xml.matches("device='disk'").count(),
        disk_path: volume.path.display().to_string(),
        installer_cdrom: domain.xml.contains("device='cdrom'"),
        channel: domain.xml.contains("<channel"),
        canonical_base: false,
        competing_qemu,
        volume_key_matches: volume.key
            == preparation
                .execution
                .staging_volume_key
                .clone()
                .unwrap_or_default(),
        qcow2: volume.format == "qcow2",
        capacity: volume.capacity_bytes,
        backing: volume.backing_path.is_some(),
        owner: host_identity_before.owner,
        group: host_identity_before.group,
        mode: host_identity_before.mode,
        selinux_label: String::from_utf8_lossy(&host_identity_before.selinux_label).to_string(),
        kernel_selinux_enforcing: fs::read_to_string("/sys/fs/selinux/enforce")
            .map_err(|e| e.to_string())?
            .trim()
            == "1",
    })?;

    let started = Instant::now();
    let roots = match discover_roots(Path::new(STAGING)) {
        Ok(roots) => roots,
        Err(failure) => {
            return Err(BrokerFailure::Identity(Box::new(root_diagnostics(
                &failure,
            ))));
        }
    };
    if roots.len() != 1 {
        return Err(BrokerFailure::Identity(Box::new(identity_diagnostics(
            &roots, "", "", false, "", "",
        ))));
    }
    let root = &roots[0];
    let Ok((stdout, stderr)) = fixed_output_with_backend(
        "/usr/bin/guestfish",
        &[
            "--ro",
            "--format=qcow2",
            "-a",
            STAGING,
            "run",
            ":",
            "echo",
            ROOT_BEGIN,
            ":",
            "inspect-os",
            ":",
            "echo",
            ROOT_END,
            ":",
            "echo",
            "FORGE_DISTRO_BEGIN",
            ":",
            "inspect-get-distro",
            root,
            ":",
            "echo",
            "FORGE_DISTRO_END",
            ":",
            "echo",
            "FORGE_VERSION_BEGIN",
            ":",
            "inspect-get-major-version",
            root,
            ":",
            "echo",
            "FORGE_VERSION_END",
            ":",
            "echo",
            "FORGE_ARCH_BEGIN",
            ":",
            "inspect-get-arch",
            root,
            ":",
            "echo",
            "FORGE_ARCH_END",
            ":",
            "mount-ro",
            root,
            "/",
            ":",
            "echo",
            "FORGE_OS_BEGIN",
            ":",
            "cat",
            "/etc/os-release",
            ":",
            "echo",
            "FORGE_OS_END",
            ":",
            "echo",
            "FORGE_FILESYSTEMS_BEGIN",
            ":",
            "list-filesystems",
            ":",
            "echo",
            "FORGE_FILESYSTEMS_END",
            ":",
            "echo",
            "FORGE_SELINUX_BEGIN",
            ":",
            "cat",
            "/etc/selinux/config",
            ":",
            "echo",
            "FORGE_SELINUX_END",
            ":",
            "echo",
            "FORGE_LAYOUT_BEGIN",
            ":",
            "echo",
            "usr_dir",
            ":",
            "is-dir",
            "/usr",
            ":",
            "echo",
            "usr_libexec_dir",
            ":",
            "is-dir",
            "/usr/libexec",
            ":",
            "echo",
            "systemd_file",
            ":",
            "is-file",
            "/usr/lib/systemd/systemd",
            ":",
            "echo",
            "selinux_config_file",
            ":",
            "is-file",
            "/etc/selinux/config",
            ":",
            "echo",
            "machine_id_file",
            ":",
            "is-file",
            "/etc/machine-id",
            ":",
            "echo",
            "dbus_machine_id_file",
            ":",
            "is-file",
            "/var/lib/dbus/machine-id",
            ":",
            "echo",
            "hostname_file",
            ":",
            "is-file",
            "/etc/hostname",
            ":",
            "echo",
            "gnome_initial_setup_done_file",
            ":",
            "is-file",
            "/var/lib/gnome-initial-setup-done",
            ":",
            "echo",
            "FORGE_LAYOUT_END",
        ],
        Duration::from_secs(120),
        "direct",
    ) else {
        return Err(BrokerFailure::Identity(Box::new(root_diagnostics(
            &RootDiscoveryFailure::InspectCommandFailed,
        ))));
    };
    let output = String::from_utf8(stdout).map_err(|_| {
        BrokerFailure::Identity(Box::new(root_diagnostics(
            &RootDiscoveryFailure::ParserFailed,
        )))
    })?;
    let rebound_roots = parse_root_frame(&output)
        .map_err(|failure| BrokerFailure::Identity(Box::new(root_diagnostics(&failure))))?;
    if rebound_roots != roots {
        return Err(BrokerFailure::Identity(Box::new(root_diagnostics(
            &RootDiscoveryFailure::ParserFailed,
        ))));
    }
    let os = strict_frame(&output, "FORGE_OS_BEGIN", "FORGE_OS_END").map_err(|_| {
        BrokerFailure::Identity(Box::new(root_diagnostics(
            &RootDiscoveryFailure::ParserFailed,
        )))
    })?;
    let distro =
        strict_scalar_frame(&output, "FORGE_DISTRO_BEGIN", "FORGE_DISTRO_END").map_err(|_| {
            BrokerFailure::Identity(Box::new(root_diagnostics(
                &RootDiscoveryFailure::ParserFailed,
            )))
        })?;
    let version = strict_scalar_frame(&output, "FORGE_VERSION_BEGIN", "FORGE_VERSION_END")
        .map_err(|_| {
            BrokerFailure::Identity(Box::new(root_diagnostics(
                &RootDiscoveryFailure::ParserFailed,
            )))
        })?;
    let architecture =
        strict_scalar_frame(&output, "FORGE_ARCH_BEGIN", "FORGE_ARCH_END").map_err(|_| {
            BrokerFailure::Identity(Box::new(root_diagnostics(
                &RootDiscoveryFailure::ParserFailed,
            )))
        })?;
    let selinux =
        strict_frame(&output, "FORGE_SELINUX_BEGIN", "FORGE_SELINUX_END").map_err(|_| {
            BrokerFailure::Identity(Box::new(root_diagnostics(
                &RootDiscoveryFailure::ParserFailed,
            )))
        })?;
    let identity = identity_diagnostics(
        &roots,
        distro,
        version,
        os.to_ascii_lowercase().contains("workstation"),
        architecture,
        selinux,
    );
    if !identity.failed_predicates.is_empty() {
        return Err(BrokerFailure::Identity(Box::new(identity)));
    }
    let filesystems = strict_frame(&output, "FORGE_FILESYSTEMS_BEGIN", "FORGE_FILESYSTEMS_END")?
        .lines()
        .filter(|line| line.starts_with("/dev/") && line.contains(':'))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let layout = parse_named_bools(strict_frame(
        &output,
        "FORGE_LAYOUT_BEGIN",
        "FORGE_LAYOUT_END",
    )?)?;
    let filesystem_layout = layout[..4].to_vec();
    let minimal_observations = layout[4..].to_vec();
    let workstation_evidence = os
        .lines()
        .filter(|line| {
            line.starts_with("NAME=")
                || line.starts_with("VARIANT=")
                || line.starts_with("VARIANT_ID=")
        })
        .collect::<Vec<_>>()
        .join("\n");
    let host_identity_after = capture_host_storage_identity(Path::new(STAGING))?;
    let host_metadata_unchanged = host_identity_before == host_identity_after;
    if !host_metadata_unchanged {
        return Err("HostMetadataDriftRefused".into());
    }
    let version = fixed_output("/usr/bin/guestfish", &["--version"], Duration::from_secs(5))?;
    let broker_sha256 = digest(Path::new("/usr/libexec/forge-preparation-broker"))?;
    ledger
        .write_all(request.nonce.as_bytes())
        .and_then(|()| ledger.write_all(b"\n"))
        .and_then(|()| ledger.sync_all())
        .map_err(|e| e.to_string())?;
    let _diagnostics = String::from_utf8_lossy(&stderr);
    Ok(forge_images::PreparationBrokerResult {
        protocol_version: 1,
        operation: request.operation,
        operation_id: request.operation_id.clone(),
        nonce: request.nonce.clone(),
        preparation_id: preparation.preparation_id,
        domain_uuid: domain.uuid,
        staging_volume_name: volume.name,
        staging_volume_key: volume.key,
        staging_path: volume.path,
        broker_version: BROKER_VERSION.to_owned(),
        broker_sha256,
        libguestfs_version: String::from_utf8_lossy(&version.0).trim().to_owned(),
        backend: "direct".to_owned(),
        os_root: root.to_owned(),
        fedora_product: "Fedora Workstation".to_owned(),
        fedora_release: "44".to_owned(),
        architecture: "x86_64".to_owned(),
        filesystems,
        guest_selinux_config: selinux
            .lines()
            .filter(|line| line.starts_with("SELINUX=") || line.starts_with("SELINUXTYPE="))
            .collect::<Vec<_>>()
            .join("\n"),
        workstation_evidence,
        filesystem_layout,
        minimal_observations,
        clean_close: true,
        host_metadata_unchanged,
        elapsed_millis: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
        completion: forge_images::PreparationBrokerCompletion::Completed,
        error_code: None,
    })
}

fn validate_request(request: &forge_images::PreparationBrokerRequest) -> Result<(), String> {
    if request.protocol_version != 1
        || request.operation
            != forge_images::PreparationBrokerOperation::InspectFedoraWorkstationPreparation
        || request.preparation_id.as_str() != PREPARATION
        || request.expected_domain_name != DOMAIN
        || request.expected_domain_uuid != UUID
        || request.operation_id.len() < 16
        || request.nonce.len() < 32
        || request.operation_id.len() > 128
        || request.nonce.len() > 128
    {
        return Err("RequestRefused".to_owned());
    }
    Ok(())
}

fn validate_preparation(
    p: &forge_images::FedoraWorkstationPreparation,
    request: &forge_images::PreparationBrokerRequest,
) -> Result<(), String> {
    if p.preparation_id != request.preparation_id
        || p.status != forge_images::FedoraWorkstationPreparationStatus::InstalledSystemProven
        || p.installer.name != DOMAIN
        || p.installer.uuid != UUID
        || p.staging.path != Path::new(STAGING)
        || p.installer.disk_path != p.staging.path
        || p.execution.privileged_offline_discovery.is_some()
    {
        return Err("DurableStateRefused".to_owned());
    }
    Ok(())
}

fn validate_storage(identity: &HostStorageIdentity) -> Result<(), String> {
    if identity.inode != 445_745
        || identity.owner != 0
        || identity.group != 0
        || identity.mode != 0o600
        || !owner_only_acl(&identity.acl)
        || identity.qcow2_capacity != 80 * 1024 * 1024 * 1024
        || identity.qcow2_backing.is_some()
        || identity.qcow2_dirty
        || identity.qcow2_corrupt
    {
        return Err("StorageDacRefused".to_owned());
    }
    if !String::from_utf8_lossy(&identity.selinux_label)
        .starts_with("system_u:object_r:virt_image_t:s0")
    {
        return Err("StorageLabelRefused".to_owned());
    }
    Ok(())
}

fn capture_host_storage_identity(path: &Path) -> Result<HostStorageIdentity, String> {
    let metadata = fs::metadata(path).map_err(|e| e.to_string())?;
    let mut label = [0_u8; 256];
    let label_count =
        rustix::fs::getxattr(path, "security.selinux", &mut label).map_err(|e| e.to_string())?;
    let path = path.to_str().ok_or("non-UTF8 storage path")?;
    let (acl, _) = fixed_output("/usr/bin/getfacl", &["-cp", path], Duration::from_secs(5))?;
    let (info, _) = fixed_output(
        "/usr/bin/qemu-img",
        &["info", "--output=json", path],
        Duration::from_secs(10),
    )?;
    let info: serde_json::Value = serde_json::from_slice(&info).map_err(|e| e.to_string())?;
    if info.get("format").and_then(serde_json::Value::as_str) != Some("qcow2") {
        return Err("StorageFormatRefused".to_owned());
    }
    Ok(HostStorageIdentity {
        inode: metadata.ino(),
        owner: metadata.uid(),
        group: metadata.gid(),
        mode: metadata.mode() & 0o777,
        size: metadata.size(),
        mtime: metadata.mtime(),
        mtime_nsec: metadata.mtime_nsec(),
        ctime: metadata.ctime(),
        ctime_nsec: metadata.ctime_nsec(),
        acl: String::from_utf8(acl).map_err(|e| e.to_string())?,
        selinux_label: label[..label_count].to_vec(),
        qcow2_capacity: info
            .get("virtual-size")
            .and_then(serde_json::Value::as_u64)
            .ok_or("StorageCapacityAbsent")?,
        qcow2_backing: info
            .get("backing-filename")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        qcow2_dirty: info
            .get("dirty-flag")
            .and_then(serde_json::Value::as_bool)
            .ok_or("StorageDirtyStateAbsent")?,
        qcow2_corrupt: info
            .pointer("/format-specific/data/corrupt")
            .and_then(serde_json::Value::as_bool)
            .ok_or("StorageCorruptStateAbsent")?,
    })
}

fn owner_only_acl(acl: &str) -> bool {
    let entries = acl
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect::<Vec<_>>();
    entries == ["user::rw-", "group::---", "other::---"]
}

fn fixed_output(
    program: &str,
    arguments: &[&str],
    timeout: Duration,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let (status, stdout, stderr) = fixed_output_status(program, arguments, timeout)?;
    if !status.success() {
        return Err(format!(
            "SubprocessFailure({:?}): {}",
            status.code(),
            String::from_utf8_lossy(&stderr)
        ));
    }
    Ok((stdout, stderr))
}

fn fixed_output_with_backend(
    program: &str,
    arguments: &[&str],
    timeout: Duration,
    backend: &str,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let (status, stdout, stderr) = execute_configured(
        configured_command_with_backend(program, arguments, false, backend),
        timeout,
    )?;
    if !status.success() {
        return Err(format!(
            "SubprocessFailure({:?}): {}",
            status.code(),
            String::from_utf8_lossy(&stderr)
        ));
    }
    Ok((stdout, stderr))
}

fn fixed_output_status(
    program: &str,
    arguments: &[&str],
    timeout: Duration,
) -> Result<(ExitStatus, Vec<u8>, Vec<u8>), String> {
    execute_configured(configured_command(program, arguments, false), timeout)
}

fn diagnostic_output(
    program: &str,
    arguments: &[&str],
    timeout: Duration,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let (status, stdout, stderr) =
        execute_configured(configured_command(program, arguments, true), timeout)?;
    if !status.success() {
        return Err(format!(
            "DiagnosticSubprocessFailure({:?}): {}",
            status.code(),
            String::from_utf8_lossy(&stderr)
        ));
    }
    Ok((stdout, stderr))
}

fn execute_configured(
    mut command: Command,
    timeout: Duration,
) -> Result<(ExitStatus, Vec<u8>, Vec<u8>), String> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let stdout = child.stdout.take().ok_or("stdout unavailable")?;
    let stderr = child.stderr.take().ok_or("stderr unavailable")?;
    let out = thread::spawn(move || read_bounded(stdout));
    let err = thread::spawn(move || read_bounded(stderr));
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().map_err(|e| e.to_string())?;
            return Err("SubprocessTimeout".to_owned());
        }
        thread::sleep(Duration::from_millis(25));
    };
    let stdout = out.join().map_err(|_| "stdout reader failed")??;
    let stderr = err.join().map_err(|_| "stderr reader failed")??;
    Ok((status, stdout, stderr))
}

fn configured_command(program: &str, arguments: &[&str], diagnostic: bool) -> Command {
    configured_command_with_backend(program, arguments, diagnostic, "libvirt:qemu:///system")
}

fn configured_command_with_backend(
    program: &str,
    arguments: &[&str],
    diagnostic: bool,
    backend: &str,
) -> Command {
    let mut command = Command::new(program);
    command
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin")
        .env("HOME", SERVICE_STATE_DIR)
        .env("XDG_CACHE_HOME", LIBGUESTFS_CACHE_DIR)
        .env("LIBGUESTFS_CACHEDIR", LIBGUESTFS_CACHE_DIR)
        .env("TMPDIR", LIBGUESTFS_TMP_DIR)
        .env("LIBGUESTFS_TMPDIR", LIBGUESTFS_TMP_DIR)
        .env("LANG", "C.UTF-8")
        .env("LIBGUESTFS_BACKEND", backend);
    if diagnostic {
        command
            .env("LIBGUESTFS_DEBUG", "1")
            .env("LIBGUESTFS_TRACE", "1");
    }
    command
}

fn discover_roots(path: &Path) -> Result<Vec<String>, RootDiscoveryFailure> {
    let path = path.to_str().ok_or(RootDiscoveryFailure::ParserFailed)?;
    let (status, stdout, _stderr) = execute_configured(
        configured_command_with_backend(
            "/usr/bin/guestfish",
            &[
                "--ro",
                "--format=qcow2",
                "-a",
                path,
                "run",
                ":",
                "echo",
                ROOT_BEGIN,
                ":",
                "inspect-os",
                ":",
                "echo",
                ROOT_END,
            ],
            false,
            "direct",
        ),
        Duration::from_secs(120),
    )
    .map_err(|_| RootDiscoveryFailure::InspectCommandFailed)?;
    if !status.success() {
        return Err(RootDiscoveryFailure::InspectCommandFailed);
    }
    let output = String::from_utf8(stdout).map_err(|_| RootDiscoveryFailure::ParserFailed)?;
    parse_root_frame(&output)
}

fn strict_frame<'a>(value: &'a str, start: &str, end: &str) -> Result<&'a str, String> {
    let lines = value.split('\n').collect::<Vec<_>>();
    let starts = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| **line == start)
        .collect::<Vec<_>>();
    let ends = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| **line == end)
        .collect::<Vec<_>>();
    if starts.len() != 1 || ends.len() != 1 || starts[0].0 >= ends[0].0 {
        return Err("OutputFrameRefused".to_owned());
    }
    let begin = value
        .match_indices(&format!("{start}\n"))
        .next()
        .ok_or("OutputFrameRefused")?
        .0
        + start.len()
        + 1;
    let end_at = value
        .match_indices(&format!("\n{end}"))
        .next()
        .ok_or("OutputFrameRefused")?
        .0;
    if begin > end_at {
        return Err("OutputFrameRefused".to_owned());
    }
    Ok(&value[begin..end_at])
}

fn strict_scalar_frame<'a>(value: &'a str, start: &str, end: &str) -> Result<&'a str, String> {
    let framed = strict_frame(value, start, end)?;
    if framed.is_empty() || framed.contains('\n') || framed.contains('\r') {
        return Err("OutputScalarRefused".to_owned());
    }
    Ok(framed)
}

fn parse_root_frame(value: &str) -> Result<Vec<String>, RootDiscoveryFailure> {
    let framed = strict_frame(value, ROOT_BEGIN, ROOT_END)
        .map_err(|_| RootDiscoveryFailure::ParserFailed)?;
    if framed.is_empty() {
        return Ok(Vec::new());
    }
    let roots = framed.lines().map(str::to_owned).collect::<Vec<_>>();
    if roots.iter().any(|root| {
        root.is_empty()
            || !(root.starts_with("/dev/") || root.starts_with("btrfsvol:/dev/"))
            || root.trim() != root
            || root.contains('\r')
            || root.chars().any(char::is_control)
            || root.chars().any(char::is_whitespace)
            || !root.chars().all(|character| {
                character.is_ascii_alphanumeric()
                    || matches!(character, '/' | '.' | '_' | ':' | '+' | '-' | '@')
            })
            || root.len() > 4096
    }) {
        return Err(RootDiscoveryFailure::ParserFailed);
    }
    Ok(roots)
}

fn parse_named_bools(value: &str) -> Result<Vec<String>, String> {
    let lines = value
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    if lines.len() != 16 {
        return Err("LayoutEvidenceRefused".to_owned());
    }
    lines
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            if pair[1] != "true" && pair[1] != "false" {
                return Err("LayoutEvidenceRefused".to_owned());
            }
            Ok(format!("{}={}", pair[0], pair[1]))
        })
        .collect()
}

fn identity_diagnostics(
    roots: &[String],
    distro_id: &str,
    version_id: &str,
    workstation: bool,
    architecture: &str,
    selinux_config: &str,
) -> forge_images::PreparationGuestIdentityDiagnostics {
    if roots.len() != 1 {
        return forge_images::PreparationGuestIdentityDiagnostics {
            inspect_command_failed: false,
            parser_failed: false,
            root_count: roots.len().try_into().unwrap_or(u32::MAX),
            observed_roots: roots.iter().take(2).cloned().collect(),
            distro_id: String::new(),
            version_id: String::new(),
            workstation: false,
            architecture: String::new(),
            selinux: String::new(),
            failed_predicates: vec!["root_count".to_owned()],
        };
    }
    let selinux = selinux_config
        .lines()
        .find(|line| line.starts_with("SELINUX="))
        .map_or_else(String::new, str::to_owned);
    let checks = [
        (roots.len() == 1, "root_count"),
        (distro_id == "fedora", "distro_id"),
        (version_id == "44", "version_id"),
        (workstation, "workstation"),
        (architecture == "x86_64", "architecture"),
        (selinux == "SELINUX=enforcing", "selinux"),
    ];
    forge_images::PreparationGuestIdentityDiagnostics {
        inspect_command_failed: false,
        parser_failed: false,
        root_count: roots.len().try_into().unwrap_or(u32::MAX),
        observed_roots: roots.iter().take(2).cloned().collect(),
        distro_id: distro_id.to_owned(),
        version_id: version_id.to_owned(),
        workstation,
        architecture: architecture.to_owned(),
        selinux,
        failed_predicates: checks
            .into_iter()
            .filter(|(passed, _)| !passed)
            .map(|(_, name)| name.to_owned())
            .collect(),
    }
}

fn root_diagnostics(
    failure: &RootDiscoveryFailure,
) -> forge_images::PreparationGuestIdentityDiagnostics {
    forge_images::PreparationGuestIdentityDiagnostics {
        inspect_command_failed: *failure == RootDiscoveryFailure::InspectCommandFailed,
        parser_failed: *failure == RootDiscoveryFailure::ParserFailed,
        root_count: 0,
        observed_roots: Vec::new(),
        distro_id: String::new(),
        version_id: String::new(),
        workstation: false,
        architecture: String::new(),
        selinux: String::new(),
        failed_predicates: vec![
            match failure {
                RootDiscoveryFailure::InspectCommandFailed => "inspect_command_failed",
                RootDiscoveryFailure::ParserFailed => "parser_failed",
            }
            .to_owned(),
        ],
    }
}

fn classify_pgrep_exit(code: Option<i32>, output: &[u8]) -> Result<bool, String> {
    match code {
        Some(0) => Ok(String::from_utf8_lossy(output).contains(STAGING)),
        Some(1) => Ok(false),
        _ => Err(format!("PgrepExclusivityFailure({code:?})")),
    }
}

fn competing_qemu_exists() -> Result<bool, String> {
    let (status, stdout, _stderr) = fixed_output_status(
        "/usr/bin/pgrep",
        &["-af", "qemu-system"],
        Duration::from_secs(5),
    )?;
    classify_pgrep_exit(status.code(), &stdout)
}

fn read_bounded(mut input: impl Read) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let count = input.read(&mut buffer).map_err(|e| e.to_string())?;
        if count == 0 {
            break;
        }
        if output.len() + count > MAX_OUTPUT {
            return Err("SubprocessOutputLimit".to_owned());
        }
        output.extend_from_slice(&buffer[..count]);
    }
    Ok(output)
}
fn digest(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let n = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> forge_images::PreparationBrokerRequest {
        forge_images::PreparationBrokerRequest {
            protocol_version: 1,
            operation:
                forge_images::PreparationBrokerOperation::InspectFedoraWorkstationPreparation,
            preparation_id: forge_images::FedoraWorkstationPreparationId::new(
                PREPARATION.to_owned(),
            )
            .unwrap(),
            expected_domain_name: DOMAIN.to_owned(),
            expected_domain_uuid: UUID.to_owned(),
            operation_id: "operation-00000001".to_owned(),
            nonce: "n".repeat(32),
        }
    }
    fn observation() -> PrivilegedObservation {
        PrivilegedObservation {
            shutoff: true,
            autostart: false,
            uuid: UUID.to_owned(),
            disk_count: 1,
            disk_path: STAGING.to_owned(),
            installer_cdrom: false,
            channel: false,
            canonical_base: false,
            competing_qemu: false,
            volume_key_matches: true,
            qcow2: true,
            capacity: 80 * 1024 * 1024 * 1024,
            backing: false,
            owner: 0,
            group: 0,
            mode: 0o600,
            selinux_label: "system_u:object_r:virt_image_t:s0".to_owned(),
            kernel_selinux_enforcing: true,
        }
    }
    #[test]
    fn only_fixed_request_is_accepted() {
        assert!(validate_request(&request()).is_ok());
    }
    #[test]
    fn wrong_identity_and_malformed_nonce_refuse() {
        let mut r = request();
        r.expected_domain_name = "fedora-lab".to_owned();
        assert!(validate_request(&r).is_err());
        let mut r = request();
        r.nonce = "short".to_owned();
        assert!(validate_request(&r).is_err());
    }
    #[test]
    fn markers_are_structured() {
        assert_eq!(
            strict_frame("noise\nA\nroot\nB\n", "A", "B").unwrap(),
            "root"
        );
        assert!(strict_frame("A\nroot\nB\nA\nother\nB\n", "A", "B").is_err());
        assert!(strict_frame("root", "A", "B").is_err());
    }
    #[test]
    fn root_parser_proves_zero_one_two_malformed_and_duplicate_frames() {
        assert_eq!(
            parse_root_frame("FORGE_ROOT_BEGIN\n\nFORGE_ROOT_END\n").unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(
            parse_root_frame(
                "FORGE_ROOT_BEGIN\nbtrfsvol:/dev/mapper/os-root/root\nFORGE_ROOT_END\n"
            )
            .unwrap(),
            ["btrfsvol:/dev/mapper/os-root/root"]
        );
        assert_eq!(
            parse_root_frame("FORGE_ROOT_BEGIN\n/dev/sda2\n/dev/sdb3\nFORGE_ROOT_END\n").unwrap(),
            ["/dev/sda2", "/dev/sdb3"]
        );
        for malformed in [
            "FORGE_ROOT_BEGIN\nrelative\nFORGE_ROOT_END\n",
            "FORGE_ROOT_BEGIN\n /dev/sda2\nFORGE_ROOT_END\n",
            "FORGE_ROOT_BEGIN\n/dev/sda2\r\nFORGE_ROOT_END\n",
            "FORGE_ROOT_BEGIN\n/dev/sda2\n",
            "FORGE_ROOT_BEGIN\n/dev/sda2\nFORGE_ROOT_END\nFORGE_ROOT_BEGIN\n/dev/sda2\nFORGE_ROOT_END\n",
        ] {
            assert_eq!(
                parse_root_frame(malformed),
                Err(RootDiscoveryFailure::ParserFailed)
            );
        }
    }
    #[test]
    fn stderr_noise_is_never_a_root_value() {
        let stdout = "FORGE_ROOT_BEGIN\n/dev/sda2\nFORGE_ROOT_END\n";
        let stderr = "libguestfs: trace: /dev/evil\nFORGE_ROOT_BEGIN\n/dev/sdb1\n";
        assert_eq!(parse_root_frame(stdout).unwrap(), ["/dev/sda2"]);
        assert!(stderr.contains("/dev/evil"));
    }
    #[test]
    fn root_failures_are_distinct_and_bounded() {
        let command = root_diagnostics(&RootDiscoveryFailure::InspectCommandFailed);
        assert!(command.inspect_command_failed);
        assert!(!command.parser_failed);
        assert_eq!(command.failed_predicates, ["inspect_command_failed"]);
        let parser = root_diagnostics(&RootDiscoveryFailure::ParserFailed);
        assert!(!parser.inspect_command_failed);
        assert!(parser.parser_failed);
        assert_eq!(parser.failed_predicates, ["parser_failed"]);
        assert!(parser.observed_roots.is_empty());
    }
    #[test]
    fn arbitrary_surfaces_and_unknown_operations_are_unrepresentable() {
        let base = serde_json::to_value(request()).unwrap();
        for field in [
            "host_path",
            "guest_path",
            "executable",
            "argv",
            "shell",
            "command",
            "mount",
            "module",
            "module_path",
            "modprobe",
            "TMPDIR",
            "LIBGUESTFS_TMPDIR",
            "XDG_CACHE_HOME",
            "LIBGUESTFS_CACHEDIR",
            "cache_path",
            "backend",
            "synthetic_path",
            "temp_path",
        ] {
            let mut value = base.clone();
            value
                .as_object_mut()
                .unwrap()
                .insert(field.to_owned(), serde_json::json!("evil"));
            assert!(
                serde_json::from_value::<forge_images::PreparationBrokerRequest>(value).is_err()
            );
        }
        let mut value = base;
        value["operation"] = serde_json::json!("InjectHelper");
        assert!(serde_json::from_value::<forge_images::PreparationBrokerRequest>(value).is_err());
    }
    #[test]
    fn every_privileged_drift_refuses() {
        let mut values = Vec::new();
        let mut v = observation();
        v.shutoff = false;
        values.push(v);
        let mut v = observation();
        v.autostart = true;
        values.push(v);
        let mut v = observation();
        v.uuid = "wrong".to_owned();
        values.push(v);
        let mut v = observation();
        v.disk_count = 2;
        values.push(v);
        let mut v = observation();
        v.disk_path = "/wrong".to_owned();
        values.push(v);
        let mut v = observation();
        v.installer_cdrom = true;
        values.push(v);
        let mut v = observation();
        v.channel = true;
        values.push(v);
        let mut v = observation();
        v.canonical_base = true;
        values.push(v);
        let mut v = observation();
        v.competing_qemu = true;
        values.push(v);
        let mut v = observation();
        v.volume_key_matches = false;
        values.push(v);
        let mut v = observation();
        v.qcow2 = false;
        values.push(v);
        let mut v = observation();
        v.capacity = 1;
        values.push(v);
        let mut v = observation();
        v.backing = true;
        values.push(v);
        let mut v = observation();
        v.owner = 1000;
        values.push(v);
        let mut v = observation();
        v.mode = 0o640;
        values.push(v);
        let mut v = observation();
        v.selinux_label = "unlabeled_t".to_owned();
        values.push(v);
        let mut v = observation();
        v.kernel_selinux_enforcing = false;
        values.push(v);
        for value in values {
            assert!(validate_privileged_observation(&value).is_err());
        }
    }
    #[test]
    fn pgrep_exclusivity_has_typed_scoped_exit_semantics() {
        assert!(!classify_pgrep_exit(Some(1), b"").unwrap());
        assert!(classify_pgrep_exit(Some(0), STAGING.as_bytes()).unwrap());
        assert!(!classify_pgrep_exit(Some(0), b"unrelated qemu").unwrap());
        assert!(classify_pgrep_exit(Some(2), b"").is_err());
        assert!(classify_pgrep_exit(None, b"").is_err());
    }
    #[test]
    fn subprocess_environment_is_fixed_to_systemd_state_and_private_tmp() {
        let command = configured_command("/usr/bin/guestfish", &["--version"], false);
        let environment = command
            .get_envs()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().into_owned(),
                    value.unwrap().to_string_lossy().into_owned(),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(environment.get("HOME").unwrap(), SERVICE_STATE_DIR);
        assert_eq!(
            environment.get("XDG_CACHE_HOME").unwrap(),
            LIBGUESTFS_CACHE_DIR
        );
        assert_eq!(
            environment.get("LIBGUESTFS_CACHEDIR").unwrap(),
            LIBGUESTFS_CACHE_DIR
        );
        assert_eq!(environment.get("TMPDIR").unwrap(), LIBGUESTFS_TMP_DIR);
        assert_eq!(environment.len(), 8);
        assert!(command.get_envs().all(|(_, value)| value.is_some()));
    }
    #[test]
    fn diagnostic_debug_is_fixed_and_absent_from_inspection_environment() {
        let normal = configured_command("/usr/bin/guestfish", &["--version"], false);
        assert!(
            normal
                .get_envs()
                .all(|(key, _)| key != "LIBGUESTFS_DEBUG" && key != "LIBGUESTFS_TRACE")
        );
        let diagnostic = configured_command("/usr/bin/guestfish", &["run"], true);
        let environment = diagnostic
            .get_envs()
            .map(|(key, value)| (key.to_string_lossy(), value.unwrap().to_string_lossy()))
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(environment.get("LIBGUESTFS_DEBUG").unwrap(), "1");
        assert_eq!(environment.get("LIBGUESTFS_TRACE").unwrap(), "1");
    }
    #[test]
    fn disk_free_request_schema_refuses_every_authority_field() {
        let request = forge_images::PreparationBrokerDiagnosticRequest {
            protocol_version: 1,
            operation:
                forge_images::PreparationBrokerDiagnosticOperation::SelfTestLibguestfsAppliance,
            operation_id: "diagnostic-000001".to_owned(),
            nonce: "n".repeat(32),
        };
        let base = serde_json::to_value(request).unwrap();
        for field in [
            "path",
            "disk",
            "domain",
            "preparation_id",
            "argv",
            "chown",
            "owner",
            "module",
            "module_path",
            "modprobe",
            "TMPDIR",
            "LIBGUESTFS_TMPDIR",
            "XDG_CACHE_HOME",
            "LIBGUESTFS_CACHEDIR",
            "cache_path",
            "backend",
            "synthetic_path",
            "temp_path",
        ] {
            let mut value = base.clone();
            value[field] = serde_json::json!("forbidden");
            assert!(
                serde_json::from_value::<forge_images::PreparationBrokerDiagnosticRequest>(value)
                    .is_err()
            );
        }
    }
    #[test]
    fn reviewed_unit_allows_exactly_the_three_required_capabilities() {
        let unit = include_str!("../deploy/forge-preparation-broker.service");
        let expected = "CAP_CHOWN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH";
        let capability_lines = unit
            .lines()
            .filter(|line| {
                line.starts_with("CapabilityBoundingSet=")
                    || line.starts_with("AmbientCapabilities=")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            capability_lines,
            vec![
                format!("CapabilityBoundingSet={expected}"),
                format!("AmbientCapabilities={expected}"),
            ]
        );
        for required in [
            "NoNewPrivileges=yes",
            "PrivateTmp=no",
            "ProtectSystem=strict",
            "ProtectHome=read-only",
            "RestrictAddressFamilies=AF_UNIX",
            "ProtectKernelModules=no",
        ] {
            assert!(unit.lines().any(|line| line == required));
        }
        assert!(!unit.contains("CAP_SYS_MODULE"));
        assert!(!unit.contains("BindPaths="));
        assert!(!unit.contains("BindReadOnlyPaths="));
        assert_eq!(
            unit.lines()
                .filter(|line| line.starts_with("ReadWritePaths="))
                .collect::<Vec<_>>(),
            vec!["ReadWritePaths=/tmp /var/tmp"]
        );
        assert_eq!(
            unit.lines()
                .filter(|line| line.starts_with("StateDirectory"))
                .collect::<Vec<_>>(),
            vec![
                "StateDirectory=forge-preparation-broker",
                "StateDirectoryMode=0700",
            ]
        );
        assert_eq!(
            unit.lines()
                .filter(|line| line.starts_with("CacheDirectory"))
                .collect::<Vec<_>>(),
            vec![
                "CacheDirectory=forge-preparation-broker",
                "CacheDirectoryMode=0755",
            ]
        );
    }

    #[test]
    fn direct_synthetic_operation_is_fixed_read_only_and_not_staging() {
        assert_ne!(SYNTHETIC, STAGING);
        assert!(SYNTHETIC.starts_with(SERVICE_STATE_DIR));
        let command = configured_command_with_backend(
            "/usr/bin/guestfish",
            &["--ro", "--format=qcow2", "-a", SYNTHETIC, "run"],
            false,
            "direct",
        );
        assert_eq!(command.get_program(), "/usr/bin/guestfish");
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(args.contains(&"--ro".to_owned()));
        assert!(args.contains(&SYNTHETIC.to_owned()));
        assert!(!args.contains(&STAGING.to_owned()));
        assert_eq!(
            command
                .get_envs()
                .find(|(key, _)| *key == "LIBGUESTFS_BACKEND")
                .unwrap()
                .1
                .unwrap(),
            "direct"
        );
    }

    #[test]
    fn identity_refusal_reports_each_bounded_predicate() {
        let roots = ["/dev/sda2".to_owned()];
        let diagnostics =
            identity_diagnostics(&roots, "other", "43", false, "i386", "SELINUX=permissive\n");
        assert_eq!(
            diagnostics.failed_predicates,
            [
                "distro_id",
                "version_id",
                "workstation",
                "architecture",
                "selinux",
            ]
        );
        let encoded =
            serde_json::to_string(&forge_images::PreparationBrokerResponse::IdentityRefusal {
                error_code: "GuestIdentityPredicateRefused".to_owned(),
                diagnostics,
            })
            .unwrap();
        assert!(encoded.len() < 1024);
        assert!(!encoded.contains("guest_path"));
    }

    #[test]
    fn r15_identity_without_an_established_root_is_impossible() {
        let diagnostics =
            identity_diagnostics(&[], "fedora", "44", true, "x86_64", "SELINUX=enforcing\n");
        assert_eq!(diagnostics.failed_predicates, ["root_count"]);
        assert_eq!(diagnostics.root_count, 0);
        assert!(diagnostics.observed_roots.is_empty());
        assert!(diagnostics.distro_id.is_empty());
        assert!(diagnostics.version_id.is_empty());
        assert!(!diagnostics.workstation);
        assert!(diagnostics.architecture.is_empty());
        assert!(diagnostics.selinux.is_empty());
    }

    #[test]
    fn inspection_commands_use_explicit_launch_and_root_binding() {
        let source = include_str!("broker.rs");
        let inspection = &source[source.find("let roots = match discover_roots").unwrap()
            ..source
                .find("let output = String::from_utf8(stdout)")
                .unwrap()];
        assert!(inspection.contains("\"run\""));
        assert!(inspection.contains("\"inspect-os\""));
        assert!(inspection.contains("\"inspect-get-distro\""));
        assert!(inspection.contains("\"inspect-get-major-version\""));
        assert!(inspection.contains("\"inspect-get-arch\""));
        assert!(inspection.contains("root,"));
        assert!(!inspection.contains("\"-i\""));
        assert!(!inspection.contains("inspect-get-roots"));
    }

    #[test]
    fn layout_evidence_is_fixed_bounded_and_named() {
        let input = "usr_dir\ntrue\nusr_libexec_dir\ntrue\nsystemd_file\ntrue\nselinux_config_file\ntrue\nmachine_id_file\ntrue\ndbus_machine_id_file\nfalse\nhostname_file\ntrue\ngnome_initial_setup_done_file\nfalse\n";
        let parsed = parse_named_bools(input).unwrap();
        assert_eq!(parsed.len(), 8);
        assert_eq!(parsed[0], "usr_dir=true");
        assert_eq!(parsed[7], "gnome_initial_setup_done_file=false");
        assert!(parse_named_bools("guest-content").is_err());
    }

    #[test]
    fn owner_only_acl_rejects_named_mask_default_and_permissive_entries() {
        assert!(owner_only_acl("user::rw-\ngroup::---\nother::---\n"));
        assert!(!owner_only_acl(
            "user::rw-\nuser:forge:r--\ngroup::---\nmask::r--\nother::---\n"
        ));
        assert!(!owner_only_acl("user::rw-\ngroup::r--\nother::---\n"));
        assert!(!owner_only_acl(
            "user::rw-\ngroup::---\nother::---\ndefault:user::rw-\n"
        ));
    }

    #[test]
    fn recovery_authority_is_exact_and_has_no_broker_operation() {
        assert_eq!(
            STAGING,
            "/var/lib/libvirt/images/forge-stage-fedora-workstation-44-1.7-5d87db39.qcow2"
        );
        assert_eq!(PREPARATION, "5d87db391be74e86bd0c7dca042295c3");
        assert_eq!(UUID, "ae82467d-10dd-4d33-b6ab-52f67e11e795");
        let operations = serde_json::to_string(
            &forge_images::PreparationBrokerDiagnosticOperation::SelfTestDirectBackendSynthetic,
        )
        .unwrap();
        assert!(!operations.contains("Recover"));
        assert!(!operations.contains("Chown"));
    }
}
