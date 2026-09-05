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

mod helper_replacement;

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
const BOOTSTRAP_SYNTHETIC: &str =
    "/var/lib/forge-preparation-broker/helper-bootstrap-synthetic.qcow2";
const BOOTSTRAP_BINDING: &str = "/var/lib/forge-preparation-broker/bootstrap-binding.json";
const BOOTSTRAP_LEDGER: &str = "/var/lib/forge-preparation-broker/bootstrap-ledger";
const BOOTSTRAP_JOURNAL: &str = "/var/lib/forge-preparation-broker/bootstrap-journal";
const REAL_BOOTSTRAP_BINDING: &str =
    "/var/lib/forge-preparation-broker/real-bootstrap-binding.json";
const REAL_BOOTSTRAP_LEDGER: &str = "/var/lib/forge-preparation-broker/real-bootstrap-ledger";
const REAL_BOOTSTRAP_JOURNAL: &str = "/var/lib/forge-preparation-broker/real-bootstrap-journal";
const REAL_BOOTSTRAP_DIAGNOSTIC: &str =
    "/var/lib/forge-preparation-broker/real-bootstrap-diagnostic";
const REAL_BOOTSTRAP_EVIDENCE: &str =
    "/var/lib/forge-preparation-broker/real-bootstrap-evidence.json";
const HELPER_ARTIFACT: &str =
    "/home/majorforge/forge-virt/target/release/forge-preparation-control";
const HELPER_SHA256: &str = "bb546fa9bf6efc11bde7687cba792421afc46616287a4fa468eadf3a7d0ad4a2";
const HELPER_BYTES: u64 = 784_624;
const SOURCE_CHECKPOINT: &str = "6c4838512e468a1d3c7bb7e21376928dfc7f6b4e";
const R16_BROKER_SHA256: &str = "9c64892cb0697c0b89cb53625b5fc1b273acb62ce040e56c9d3ca96e4ae6838e";
const HELPER: &str = "/usr/libexec/forge-preparation-control";
const GENERATOR: &str = "/usr/lib/systemd/system-generators/forge-preparation-control-generator";
const BINDING: &str = "/usr/lib/forge-preparation-control/binding.json";
const BROKER_VERSION: &str = "forge-preparation-broker/1";
const MAX_MESSAGE: usize = 64 * 1024;
const MAX_OUTPUT: usize = 1024 * 1024;
const ROOT_BEGIN: &str = "FORGE_ROOT_BEGIN";
const ROOT_END: &str = "FORGE_ROOT_END";

enum BrokerSuccess {
    Inspection(Box<forge_images::PreparationBrokerResult>),
    ApplianceSelfTest(forge_images::PreparationBrokerApplianceSelfTestResult),
    SyntheticDirectSelfTest(forge_images::PreparationBrokerSyntheticDirectResult),
    Bootstrap(Box<forge_images::PreparationBrokerBootstrapResult>),
    Recovery(forge_images::PreparationBrokerRecoveryResult),
}

enum BrokerFailure {
    Code(String),
    Identity(Box<forge_images::PreparationGuestIdentityDiagnostics>),
}

/// Private capability for one validated preparation disk; no protocol caller can construct it.
#[allow(dead_code)]
struct ResolvedPreparationDiskCapability {
    qcow2_path: std::path::PathBuf,
    replacement: helper_replacement::ReplacementTransaction,
}

impl ResolvedPreparationDiskCapability {
    #[allow(dead_code)]
    fn guestfish_replace(&self, new_helper: &Path) -> Result<(), String> {
        if self.qcow2_path == Path::new(STAGING) {
            return Err("RealReplacementRequiresR3Authorization".to_owned());
        }
        let artifact = fs::read(new_helper).map_err(|e| e.to_string())?;
        let digest = format!("{:x}", Sha256::digest(&artifact));
        if digest != self.replacement.new_helper_sha256
            || artifact.len() as u64 != self.replacement.new_helper_bytes
        {
            return Err("NewHelperIdentityRefused".to_owned());
        }
        let args = [
            "--rw",
            "--format=qcow2",
            "-a",
            self.qcow2_path.to_str().ok_or("TargetPathRefused")?,
            "run",
            ":",
            "mount",
            "/dev/sda1",
            "/",
            ":",
            "upload",
            new_helper.to_str().ok_or("ArtifactPathRefused")?,
            HELPER,
            ":",
            "chmod",
            "0755",
            HELPER,
            ":",
            "chown",
            "0",
            "0",
            HELPER,
        ];
        fixed_output_with_backend(
            "/usr/bin/guestfish",
            &args,
            Duration::from_secs(120),
            "direct",
        )?;
        Ok(())
    }
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

#[derive(Debug, PartialEq, Eq)]
enum BootstrapResume {
    Fresh,
    Resume,
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
            Ok(BrokerSuccess::Bootstrap(result)) => {
                forge_images::PreparationBrokerResponse::BootstrapSuccess { result }
            }
            Ok(BrokerSuccess::Recovery(result)) => {
                forge_images::PreparationBrokerResponse::RecoveryClassificationSuccess { result }
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
    match request.operation {
        forge_images::PreparationBrokerOperation::InspectFedoraWorkstationPreparation => {
            inspect(&request).map(|result| BrokerSuccess::Inspection(Box::new(result)))
        }
        forge_images::PreparationBrokerOperation::BootstrapPreparationHelperOffline => {
            bootstrap_helper(&request).map(|result| BrokerSuccess::Bootstrap(Box::new(result)))
        }
        forge_images::PreparationBrokerOperation::ReplacePreparationHelper => {
            resolve_replacement_target(&request)
                .map(|result| BrokerSuccess::Bootstrap(Box::new(result)))
                .map_err(BrokerFailure::Code)
        }
        forge_images::PreparationBrokerOperation::ClassifyBootstrapRecoveryReadOnly => {
            classify_real_recovery(&request).map(BrokerSuccess::Recovery)
        }
        forge_images::PreparationBrokerOperation::CompleteBootstrapRecoveryHostOnly => {
            complete_real_recovery(&request)
                .map(|result| BrokerSuccess::Bootstrap(Box::new(result)))
        }
    }
}

fn resolve_replacement_target(
    request: &forge_images::PreparationBrokerRequest,
) -> Result<forge_images::PreparationBrokerBootstrapResult, String> {
    if request.protocol_version != forge_images::FORGE_PREPARATION_BROKER_PROTOCOL_VERSION
        || request.operation != forge_images::PreparationBrokerOperation::ReplacePreparationHelper
        || request.preparation_id.as_str() != PREPARATION
        || request.expected_domain_name != DOMAIN
        || request.expected_domain_uuid != UUID
        || request.bootstrap_target
            != Some(forge_images::PreparationBootstrapTarget::SyntheticProof)
    {
        return Err("ReplacementRequestRefused".to_owned());
    }
    let transaction = stable_identity("replace-helper", &[PREPARATION, DOMAIN, UUID, STAGING]);
    if request.operation_id != transaction
        || request.nonce != stable_identity("replace-helper-nonce", &[&transaction])
    {
        return Err("ReplacementTransactionRefused".to_owned());
    }
    let preparation = forge_images::read_fedora_workstation_preparation(Path::new(STATE))
        .map_err(|e| e.to_string())?
        .ok_or("PreparationAbsent")?;
    if preparation.status != forge_images::FedoraWorkstationPreparationStatus::InstalledSystemProven
        || preparation.preparation_id.as_str() != PREPARATION
        || preparation.installer.name != DOMAIN
        || preparation.installer.uuid != UUID
        || preparation.staging.path != Path::new(STAGING)
        || preparation.execution.preparation_channel.is_some()
        || preparation.execution.read_only_guest_inventory.is_some()
    {
        return Err("ReplacementPreparationIdentityRefused".to_owned());
    }
    // Target paths and artifact identities are fixed constants, not request fields.
    let replacement = helper_replacement::ReplacementTransaction {
        preparation_id: PREPARATION.to_owned(),
        domain_name: DOMAIN.to_owned(),
        domain_uuid: UUID.to_owned(),
        staging_identity: STAGING.to_owned(),
        remediation_transaction_id: transaction.clone(),
        protocol_version: forge_images::FORGE_GUEST_CONTROL_PROTOCOL_VERSION,
        normalization_recipe: "V1".to_owned(),
        canonical_binding_sha256: preparation
            .execution
            .helper_bootstrap
            .as_ref()
            .map(|e| e.binding_sha256.clone())
            .ok_or("ReplacementBindingEvidenceRefused")?,
        generator_sha256: HELPER_SHA256.to_owned(),
        old_helper_sha256: HELPER_SHA256.to_owned(),
        old_helper_bytes: HELPER_BYTES,
        new_helper_sha256: "cfc6ee47afa64767e6eb93594235f203e89fd76ca4ce851548ce02d3545b16a5"
            .to_owned(),
        new_helper_bytes: 802_896,
    };
    let _trusted_target = ResolvedPreparationDiskCapability {
        qcow2_path: Path::new(STAGING).to_owned(),
        replacement,
    };
    Err("ReplacementDryRunTargetResolved".to_owned())
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

use forge_images::{
    BootstrapArtifactClassification as ArtifactClass,
    BootstrapRecoveryClassification as RecoveryClass, BootstrapResumePlan as ResumePlan,
};

fn recovery_outcome(
    helper: ArtifactClass,
    generator: ArtifactClass,
    binding: ArtifactClass,
) -> (RecoveryClass, ResumePlan) {
    use ArtifactClass::{Absent, Exact, PartialOrMismatched, UnreadableOrIndeterminate};
    if [helper, generator, binding].contains(&UnreadableOrIndeterminate) {
        return (
            RecoveryClass::Indeterminate,
            ResumePlan::RecoveryBlockedIndeterminate,
        );
    }
    if [helper, generator, binding].contains(&PartialOrMismatched) {
        return (
            RecoveryClass::PartialOrMismatched,
            ResumePlan::RecoveryBlockedMismatch,
        );
    }
    match (helper, generator, binding) {
        (Absent, Absent, Absent) => (
            RecoveryClass::NothingWritten,
            ResumePlan::ResumeWritingHelper,
        ),
        (Exact, Absent, Absent) => (
            RecoveryClass::HelperExactOnly,
            ResumePlan::ResumeWritingGenerator,
        ),
        (Exact, Exact, Absent) => (RecoveryClass::ExactPrefix, ResumePlan::ResumeWritingBinding),
        (Exact, Exact, Exact) => (
            RecoveryClass::ExactComplete,
            ResumePlan::VerifyExistingArtifacts,
        ),
        _ => (
            RecoveryClass::InconsistentSet,
            ResumePlan::RecoveryBlockedInconsistent,
        ),
    }
}

fn validate_recovery_request(
    request: &forge_images::PreparationBrokerRequest,
    transaction: &str,
) -> Result<(), String> {
    if request.protocol_version != forge_images::FORGE_PREPARATION_BROKER_PROTOCOL_VERSION
        || !matches!(
            request.operation,
            forge_images::PreparationBrokerOperation::ClassifyBootstrapRecoveryReadOnly
                | forge_images::PreparationBrokerOperation::CompleteBootstrapRecoveryHostOnly
        )
        || request.preparation_id.as_str() != PREPARATION
        || request.expected_domain_name != DOMAIN
        || request.expected_domain_uuid != UUID
        || request.bootstrap_target
            != Some(forge_images::PreparationBootstrapTarget::RealPreparation)
        || request.operation_id != transaction
        || request.nonce != real_bootstrap_nonce(transaction)
    {
        return Err("RecoveryRequestRefused".to_owned());
    }
    Ok(())
}

fn read_only_presence() -> Result<[bool; 3], String> {
    let output = real_guest_output(
        &[
            "is-file", HELPER, ":", "is-file", GENERATOR, ":", "is-file", BINDING,
        ],
        false,
    )?;
    let values = output
        .lines()
        .filter(|line| *line == "true" || *line == "false")
        .map(|line| line == "true")
        .collect::<Vec<_>>();
    values
        .try_into()
        .map_err(|_| "RecoveryPresenceIndeterminate".to_owned())
}

fn classify_fixed_artifact(path: &'static str, expected_label: &str) -> ArtifactClass {
    match real_guest_output(
        &[
            "checksum",
            "sha256",
            path,
            ":",
            "statns",
            path,
            ":",
            "getxattr",
            path,
            "security.selinux",
        ],
        false,
    ) {
        Ok(output) => {
            let digest_exact = output.lines().any(|line| line == HELPER_SHA256);
            let size_exact = output
                .lines()
                .any(|line| line == format!("st_size: {HELPER_BYTES}"));
            let owner_exact = output.lines().any(|line| line == "st_uid: 0")
                && output.lines().any(|line| line == "st_gid: 0");
            let mode_exact = output.lines().any(|line| line == "st_mode: 33261");
            let label_exact = output.lines().any(|line| line == expected_label);
            if digest_exact && size_exact && owner_exact && mode_exact && label_exact {
                ArtifactClass::Exact
            } else {
                ArtifactClass::PartialOrMismatched
            }
        }
        Err(_) => ArtifactClass::UnreadableOrIndeterminate,
    }
}

fn classify_fixed_binding(expected: &[u8]) -> ArtifactClass {
    let bytes = real_guest_output(&["base64-out", BINDING, "/dev/stdout"], false);
    let metadata = real_guest_output(
        &[
            "statns",
            BINDING,
            ":",
            "getxattr",
            BINDING,
            "security.selinux",
        ],
        false,
    );
    match (bytes, metadata) {
        (Ok(output), Ok(metadata)) => {
            let content_exact =
                decode_binding_base64(output.trim()).is_ok_and(|bytes| bytes == expected);
            let metadata_exact = metadata
                .lines()
                .any(|line| line == format!("st_size: {}", expected.len()))
                && metadata.lines().any(|line| line == "st_uid: 0")
                && metadata.lines().any(|line| line == "st_gid: 0")
                && metadata.lines().any(|line| line == "st_mode: 33152")
                && metadata
                    .lines()
                    .any(|line| line == "system_u:object_r:lib_t:s0");
            if content_exact && metadata_exact {
                ArtifactClass::Exact
            } else {
                ArtifactClass::PartialOrMismatched
            }
        }
        _ => ArtifactClass::UnreadableOrIndeterminate,
    }
}

#[allow(clippy::too_many_lines)]
fn classify_real_recovery(
    request: &forge_images::PreparationBrokerRequest,
) -> Result<forge_images::PreparationBrokerRecoveryResult, BrokerFailure> {
    let preparation = forge_images::read_fedora_workstation_preparation(Path::new(STATE))
        .map_err(|e| e.to_string())?
        .ok_or("PreparationAbsent")?;
    validate_bootstrap_preparation(&preparation, request)?;
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
    if volume.path != Path::new(STAGING)
        || volume.format != "qcow2"
        || volume.capacity_bytes != 80 * 1024 * 1024 * 1024
        || volume.backing_path.is_some()
        || competing_qemu_exists()?
    {
        return Err("RecoveryStorageIdentityRefused".into());
    }
    let before = capture_host_storage_identity(Path::new(STAGING))?;
    validate_storage(&before)?;
    let transaction = real_bootstrap_transaction_id(&preparation, before.inode)?;
    validate_recovery_request(request, &transaction)?;
    let journal = fs::read_to_string(REAL_BOOTSTRAP_JOURNAL).unwrap_or_default();
    let writing = format!("WritingHelper {transaction}\n");
    let verifying = format!("Verifying {transaction}\n");
    if (journal != writing && journal != verifying)
        || fs::read_to_string(REAL_BOOTSTRAP_LEDGER)
            .unwrap_or_default()
            .lines()
            .any(|line| line == transaction)
    {
        return Err("RecoveryBoundaryRefused".into());
    }
    let (presence, presence_indeterminate) = match read_only_presence() {
        Ok(value) => (value, false),
        Err(_) => ([false; 3], true),
    };
    let expected_binding = expected_real_binding_bytes(&transaction, &preparation, before.inode)?;
    let classify = |present: bool, path| {
        if presence_indeterminate {
            ArtifactClass::UnreadableOrIndeterminate
        } else if !present {
            ArtifactClass::Absent
        } else {
            let label = if path == HELPER {
                "system_u:object_r:bin_t:s0"
            } else {
                "system_u:object_r:systemd_generic_generator_exec_t:s0"
            };
            classify_fixed_artifact(path, label)
        }
    };
    let helper = classify(presence[0], HELPER);
    let generator = classify(presence[1], GENERATOR);
    let binding = if presence_indeterminate {
        ArtifactClass::UnreadableOrIndeterminate
    } else if !presence[2] {
        ArtifactClass::Absent
    } else {
        classify_fixed_binding(&expected_binding)
    };
    let (classification, resume_plan) = recovery_outcome(helper, generator, binding);
    if journal == verifying {
        if classification != RecoveryClass::ExactComplete
            || resume_plan != ResumePlan::VerifyExistingArtifacts
        {
            return Err("RealFinalVerificationArtifactSetRefused".into());
        }
        let output = real_guest_output(&real_verification_arguments(), false)?;
        validate_real_verification(&output, &transaction, &preparation, before.inode)?;
    }
    let after = capture_host_storage_identity(Path::new(STAGING))?;
    let unchanged = before == after;
    if !unchanged {
        return Err("RecoveryHostIdentityDriftRefused".into());
    }
    Ok(forge_images::PreparationBrokerRecoveryResult {
        protocol_version: request.protocol_version,
        operation: request.operation,
        operation_id: request.operation_id.clone(),
        preparation_id: preparation.preparation_id,
        domain_uuid: UUID.to_owned(),
        staging_path: STAGING.into(),
        bootstrap_transaction_id: transaction,
        helper,
        generator,
        binding,
        classification,
        resume_plan,
        backend: "direct".to_owned(),
        read_only: true,
        clean_close: true,
        host_metadata_unchanged: true,
    })
}

fn atomic_publish(path: &str, bytes: &[u8]) -> Result<(), String> {
    let temporary = format!("{path}.tmp");
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|_| "AtomicPublicationCollisionRefused")?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| e.to_string())?;
    fs::rename(&temporary, path).map_err(|e| e.to_string())?;
    File::open(SERVICE_STATE_DIR)
        .and_then(|directory| directory.sync_all())
        .map_err(|e| e.to_string())
}

fn complete_real_recovery(
    request: &forge_images::PreparationBrokerRequest,
) -> Result<forge_images::PreparationBrokerBootstrapResult, BrokerFailure> {
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open("/var/lib/forge-preparation-broker/operation.lock")
        .map_err(|e| e.to_string())?;
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive)
        .map_err(|_| "OperationLockUnavailable")?;
    if Path::new(REAL_BOOTSTRAP_LEDGER).exists() || Path::new(REAL_BOOTSTRAP_EVIDENCE).exists() {
        return Err("ReplayRefused".into());
    }
    let verification = classify_real_recovery(request)?;
    if verification.classification != RecoveryClass::ExactComplete
        || verification.resume_plan != ResumePlan::VerifyExistingArtifacts
        || !verification.read_only
        || !verification.clean_close
        || !verification.host_metadata_unchanged
    {
        return Err("CompletionVerificationRefused".into());
    }
    let host_identity = capture_host_storage_identity(Path::new(STAGING))?;
    validate_storage(&host_identity)?;
    let preparation = forge_images::read_fedora_workstation_preparation(Path::new(STATE))
        .map_err(|e| e.to_string())?
        .ok_or("PreparationAbsent")?;
    let binding = expected_real_binding_bytes(
        &verification.bootstrap_transaction_id,
        &preparation,
        host_identity.inode,
    )?;
    let evidence = serde_json::json!({
        "schema_version": 1,
        "completion": "RealOfflineHelperInjectionCompleted",
        "transaction_id": verification.bootstrap_transaction_id,
        "preparation_id": PREPARATION,
        "domain_uuid": UUID,
        "staging_path": STAGING,
        "staging_inode": host_identity.inode,
        "helper": {"path": HELPER, "sha256": HELPER_SHA256, "bytes": HELPER_BYTES, "owner": "0:0", "mode": "0755", "selinux_type": "bin_t"},
        "generator": {"path": GENERATOR, "sha256": HELPER_SHA256, "bytes": HELPER_BYTES, "owner": "0:0", "mode": "0755", "selinux_type": "systemd_generic_generator_exec_t"},
        "binding": {"path": BINDING, "sha256": format!("{:x}", Sha256::digest(&binding)), "bytes": binding.len(), "owner": "0:0", "mode": "0600", "selinux_type": "lib_t"},
        "protocol_version": forge_images::FORGE_GUEST_CONTROL_PROTOCOL_VERSION,
        "recipe": "V1",
        "channel": forge_images::FORGE_PREPARATION_CHANNEL,
        "structured_verification": "Passed",
        "path_set": "Exact",
        "r6_guest_write": false
    });
    let evidence_bytes = serde_json::to_vec_pretty(&evidence).map_err(|e| e.to_string())?;
    atomic_publish(REAL_BOOTSTRAP_EVIDENCE, &evidence_bytes)?;
    atomic_publish(
        REAL_BOOTSTRAP_LEDGER,
        format!("{}\n", verification.bootstrap_transaction_id).as_bytes(),
    )?;
    atomic_publish(
        REAL_BOOTSTRAP_JOURNAL,
        format!("Completed {}\n", verification.bootstrap_transaction_id).as_bytes(),
    )?;
    Ok(forge_images::PreparationBrokerBootstrapResult {
        protocol_version: request.protocol_version,
        operation: request.operation,
        operation_id: request.operation_id.clone(),
        nonce: request.nonce.clone(),
        preparation_id: preparation.preparation_id,
        domain_uuid: UUID.to_owned(),
        target: forge_images::PreparationBootstrapTarget::RealPreparation,
        source_checkpoint: SOURCE_CHECKPOINT.to_owned(),
        helper_sha256: HELPER_SHA256.to_owned(),
        helper_bytes: HELPER_BYTES,
        generator_sha256: HELPER_SHA256.to_owned(),
        generator_bytes: HELPER_BYTES,
        binding_sha256: format!("{:x}", Sha256::digest(&binding)),
        binding_bytes: binding.len() as u64,
        helper_protocol_version: forge_images::FORGE_GUEST_CONTROL_PROTOCOL_VERSION,
        supported_operations: vec!["ReadOnlyGuestInventoryProbe".to_owned()],
        bootstrap_transaction_id: request.operation_id.clone(),
        guest_paths: vec![HELPER.to_owned(), GENERATOR.to_owned(), BINDING.to_owned()],
        guest_modes: vec![
            "0:0:0755".to_owned(),
            "0:0:0755".to_owned(),
            "0:0:0600".to_owned(),
        ],
        guest_selinux_labels: vec![
            "bin_t".to_owned(),
            "systemd_generic_generator_exec_t".to_owned(),
            "lib_t".to_owned(),
        ],
        unexpected_paths_modified: false,
        clean_close: true,
        backend: "direct".to_owned(),
        target_sha256_before: String::new(),
        target_sha256_after: String::new(),
    })
}

#[allow(clippy::too_many_lines)]
fn bootstrap_helper(
    request: &forge_images::PreparationBrokerRequest,
) -> Result<forge_images::PreparationBrokerBootstrapResult, BrokerFailure> {
    match request.bootstrap_target {
        Some(forge_images::PreparationBootstrapTarget::SyntheticProof) => {
            bootstrap_synthetic(request)
        }
        Some(forge_images::PreparationBootstrapTarget::RealPreparation) => bootstrap_real(request),
        None => Err("BootstrapRequestRefused".into()),
    }
}

#[allow(clippy::too_many_lines)]
fn bootstrap_synthetic(
    request: &forge_images::PreparationBrokerRequest,
) -> Result<forge_images::PreparationBrokerBootstrapResult, BrokerFailure> {
    validate_bootstrap_request(request)?;
    let preparation = forge_images::read_fedora_workstation_preparation(Path::new(STATE))
        .map_err(|e| e.to_string())?
        .ok_or("PreparationAbsent")?;
    validate_bootstrap_preparation(&preparation, request)?;
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
    if volume.key
        != preparation
            .execution
            .staging_volume_key
            .clone()
            .unwrap_or_default()
        || volume.path != Path::new(STAGING)
        || volume.format != "qcow2"
        || volume.capacity_bytes != 80 * 1024 * 1024 * 1024
        || volume.backing_path.is_some()
    {
        return Err("StorageIdentityRefused".into());
    }
    validate_storage(&capture_host_storage_identity(Path::new(STAGING))?)?;
    if competing_qemu_exists()? {
        return Err("CompetingQemuRefused".into());
    }
    if fs::read_to_string("/sys/fs/selinux/enforce")
        .map_err(|e| e.to_string())?
        .trim()
        != "1"
    {
        return Err("SelinuxEnforcementRefused".into());
    }
    let artifact = fs::metadata(HELPER_ARTIFACT).map_err(|_| "HelperArtifactRefused")?;
    if !helper_artifact_matches(artifact.len(), &digest(Path::new(HELPER_ARTIFACT))?)
        || request.bootstrap_target
            != Some(forge_images::PreparationBootstrapTarget::SyntheticProof)
    {
        return Err("HelperArtifactRefused".into());
    }
    let target_before = capture_host_storage_identity(Path::new(BOOTSTRAP_SYNTHETIC))?;
    if target_before.owner != 0
        || target_before.group != 0
        || target_before.mode != 0o600
        || !owner_only_acl(&target_before.acl)
        || target_before.qcow2_capacity != 256 * 1024 * 1024
        || target_before.qcow2_backing.is_some()
        || target_before.qcow2_dirty
        || target_before.qcow2_corrupt
        || !String::from_utf8_lossy(&target_before.selinux_label).contains("virt_image_t:s0")
    {
        return Err("SyntheticTargetRefused".into());
    }
    let target_sha256_before = digest(Path::new(BOOTSTRAP_SYNTHETIC))?;
    let transaction = bootstrap_transaction_id();
    let nonce = bootstrap_nonce(&transaction);
    let ledger_seen = fs::read_to_string(BOOTSTRAP_LEDGER).unwrap_or_default();
    if ledger_seen.lines().any(|line| line == transaction) {
        return Err("ReplayRefused".into());
    }
    let journal = fs::read_to_string(BOOTSTRAP_JOURNAL).ok();
    if journal.as_deref() == Some("Completed\n") {
        return Err("ReplayRefused".into());
    }
    let before = synthetic_guest_output(
        &[
            "run",
            ":",
            "mount-ro",
            "/dev/sda1",
            "/",
            ":",
            "echo",
            "FORGE_PATHS_BEGIN",
            ":",
            "find",
            "/",
            ":",
            "echo",
            "FORGE_PATHS_END",
            ":",
            "is-file",
            HELPER,
            ":",
            "is-file",
            GENERATOR,
            ":",
            "is-file",
            BINDING,
        ],
        false,
    )?;
    let artifact_states = before
        .lines()
        .filter(|line| *line == "true" || *line == "false")
        .collect::<Vec<_>>();
    if artifact_states.len() != 3 {
        return Err("SyntheticPreconditionRefused".into());
    }
    let resume = classify_bootstrap_resume(journal.as_deref(), artifact_states.contains(&"true"))?;
    match resume {
        BootstrapResume::Fresh => {
            let binding = expected_binding_bytes(&transaction)?;
            let mut binding_file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(BOOTSTRAP_BINDING)
                .map_err(|_| "BootstrapBindingRefused")?;
            binding_file
                .write_all(&binding)
                .and_then(|()| binding_file.sync_all())
                .map_err(|e| e.to_string())?;
            write_bootstrap_state("Writing\n")?;
            synthetic_guest_output(
                &[
                    "run",
                    ":",
                    "mount",
                    "/dev/sda1",
                    "/",
                    ":",
                    "mkdir-p",
                    "/usr/lib/forge-preparation-control",
                    ":",
                    "upload",
                    HELPER_ARTIFACT,
                    HELPER,
                    ":",
                    "upload",
                    HELPER_ARTIFACT,
                    GENERATOR,
                    ":",
                    "upload",
                    BOOTSTRAP_BINDING,
                    BINDING,
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
                    "chown",
                    "0",
                    "0",
                    HELPER,
                    ":",
                    "chown",
                    "0",
                    "0",
                    GENERATOR,
                    ":",
                    "chown",
                    "0",
                    "0",
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
                ],
                true,
            )?;
            write_bootstrap_state("Verifying\n")?;
        }
        BootstrapResume::Resume
            if matches!(journal.as_deref(), Some("Verifying\n" | "Verified\n")) => {}
        BootstrapResume::Resume => return Err("WriteStageRecoveryRequired".into()),
    }
    let after = synthetic_guest_output(&synthetic_verification_arguments(), false)?;
    let after_paths = framed_paths(&after)?;
    let expected_after = expected_synthetic_paths();
    let unexpected_paths_modified = after_paths != expected_after;
    if unexpected_paths_modified {
        return Err("SyntheticPathSetRefused".into());
    }
    validate_synthetic_verification(&after, &transaction)?;
    let target_after = capture_host_storage_identity(Path::new(BOOTSTRAP_SYNTHETIC))?;
    if target_before.inode != target_after.inode
        || target_before.owner != target_after.owner
        || target_before.group != target_after.group
        || target_before.mode != target_after.mode
        || target_before.acl != target_after.acl
        || target_before.selinux_label != target_after.selinux_label
        || target_before.qcow2_capacity != target_after.qcow2_capacity
        || target_before.qcow2_backing != target_after.qcow2_backing
        || target_after.qcow2_dirty
        || target_after.qcow2_corrupt
    {
        return Err("SyntheticHostIdentityDriftRefused".into());
    }
    write_bootstrap_state("Verified\n")?;
    let mut ledger = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(BOOTSTRAP_LEDGER)
        .map_err(|_| "BootstrapLedgerRefused")?;
    ledger
        .write_all(format!("{transaction}\n").as_bytes())
        .and_then(|()| ledger.sync_all())
        .map_err(|e| e.to_string())?;
    write_bootstrap_state("Completed\n")?;
    let target_sha256_after = digest(Path::new(BOOTSTRAP_SYNTHETIC))?;
    Ok(forge_images::PreparationBrokerBootstrapResult {
        protocol_version: forge_images::FORGE_PREPARATION_BROKER_PROTOCOL_VERSION,
        operation: request.operation,
        operation_id: request.operation_id.clone(),
        nonce,
        preparation_id: preparation.preparation_id,
        domain_uuid: domain.uuid,
        target: forge_images::PreparationBootstrapTarget::SyntheticProof,
        source_checkpoint: SOURCE_CHECKPOINT.to_owned(),
        helper_sha256: HELPER_SHA256.to_owned(),
        helper_bytes: HELPER_BYTES,
        generator_sha256: HELPER_SHA256.to_owned(),
        generator_bytes: HELPER_BYTES,
        binding_sha256: format!(
            "{:x}",
            Sha256::digest(expected_binding_bytes(&transaction)?)
        ),
        binding_bytes: expected_binding_bytes(&transaction)?.len() as u64,
        helper_protocol_version: forge_images::FORGE_GUEST_CONTROL_PROTOCOL_VERSION,
        supported_operations: vec!["ReadOnlyGuestInventoryProbe".to_owned()],
        bootstrap_transaction_id: transaction,
        guest_paths: vec![HELPER.to_owned(), GENERATOR.to_owned(), BINDING.to_owned()],
        guest_modes: vec![
            "0:0:0755".to_owned(),
            "0:0:0755".to_owned(),
            "0:0:0600".to_owned(),
        ],
        guest_selinux_labels: vec![
            "bin_t".to_owned(),
            "systemd_generic_generator_exec_t".to_owned(),
            "lib_t".to_owned(),
        ],
        unexpected_paths_modified,
        clean_close: true,
        backend: "direct".to_owned(),
        target_sha256_before,
        target_sha256_after,
    })
}

#[allow(clippy::too_many_lines)]
fn bootstrap_real(
    request: &forge_images::PreparationBrokerRequest,
) -> Result<forge_images::PreparationBrokerBootstrapResult, BrokerFailure> {
    validate_real_bootstrap_request(request)?;
    let preparation = forge_images::read_fedora_workstation_preparation(Path::new(STATE))
        .map_err(|e| e.to_string())?
        .ok_or("PreparationAbsent")?;
    validate_bootstrap_preparation(&preparation, request)?;
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
    if volume.key
        != preparation
            .execution
            .staging_volume_key
            .clone()
            .unwrap_or_default()
        || volume.path != Path::new(STAGING)
        || volume.format != "qcow2"
        || volume.capacity_bytes != 80 * 1024 * 1024 * 1024
        || volume.backing_path.is_some()
    {
        return Err("StorageIdentityRefused".into());
    }
    let target_before = capture_host_storage_identity(Path::new(STAGING))?;
    validate_storage(&target_before)?;
    if competing_qemu_exists()? {
        return Err("CompetingQemuRefused".into());
    }
    if fs::read_to_string("/sys/fs/selinux/enforce")
        .map_err(|e| e.to_string())?
        .trim()
        != "1"
    {
        return Err("SelinuxEnforcementRefused".into());
    }
    let artifact = fs::metadata(HELPER_ARTIFACT).map_err(|_| "HelperArtifactRefused")?;
    if !helper_artifact_matches(artifact.len(), &digest(Path::new(HELPER_ARTIFACT))?) {
        return Err("HelperArtifactRefused".into());
    }
    let transaction = real_bootstrap_transaction_id(&preparation, target_before.inode)?;
    if request.operation_id != transaction || request.nonce != real_bootstrap_nonce(&transaction) {
        return Err("BootstrapRequestRefused".into());
    }
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open("/var/lib/forge-preparation-broker/operation.lock")
        .map_err(|e| e.to_string())?;
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive)
        .map_err(|_| "OperationLockUnavailable")?;
    if fs::read_to_string(REAL_BOOTSTRAP_LEDGER)
        .unwrap_or_default()
        .lines()
        .any(|v| v == transaction)
    {
        return Err("ReplayRefused".into());
    }
    let binding = expected_real_binding_bytes(&transaction, &preparation, target_before.inode)?;
    let binding_sha256 = format!("{:x}", Sha256::digest(&binding));
    let journal = fs::read_to_string(REAL_BOOTSTRAP_JOURNAL).ok();
    if journal.as_deref() != Some(&format!("WritingHelper {transaction}\n")) {
        return Err("ReplayRefused".into());
    }
    let presence = read_only_presence()?;
    let (classification, plan) = recovery_outcome(
        if presence[0] {
            classify_fixed_artifact(HELPER, "system_u:object_r:bin_t:s0")
        } else {
            ArtifactClass::Absent
        },
        if presence[1] {
            classify_fixed_artifact(
                GENERATOR,
                "system_u:object_r:systemd_generic_generator_exec_t:s0",
            )
        } else {
            ArtifactClass::Absent
        },
        if presence[2] {
            classify_fixed_binding(&binding)
        } else {
            ArtifactClass::Absent
        },
    );
    if classification != RecoveryClass::NothingWritten || plan != ResumePlan::ResumeWritingHelper {
        return Err("RecoveryClassificationRefused".into());
    }
    if fs::read(REAL_BOOTSTRAP_BINDING).map_err(|_| "BootstrapBindingRefused")? != binding {
        return Err("BootstrapBindingRefused".into());
    }

    real_guest_output(
        &[
            "upload",
            HELPER_ARTIFACT,
            HELPER,
            ":",
            "chmod",
            "0755",
            HELPER,
            ":",
            "chown",
            "0",
            "0",
            HELPER,
            ":",
            "setxattr",
            "security.selinux",
            "system_u:object_r:bin_t:s0",
            "26",
            HELPER,
        ],
        true,
    )?;
    if classify_fixed_artifact(HELPER, "system_u:object_r:bin_t:s0") != ArtifactClass::Exact {
        return Err("HelperVerificationRefused".into());
    }
    write_real_bootstrap_state(&format!("WritingGenerator {transaction}\n"))?;
    real_guest_output(
        &[
            "upload",
            HELPER_ARTIFACT,
            GENERATOR,
            ":",
            "chmod",
            "0755",
            GENERATOR,
            ":",
            "chown",
            "0",
            "0",
            GENERATOR,
            ":",
            "setxattr",
            "security.selinux",
            "system_u:object_r:systemd_generic_generator_exec_t:s0",
            "53",
            GENERATOR,
        ],
        true,
    )?;
    if classify_fixed_artifact(
        GENERATOR,
        "system_u:object_r:systemd_generic_generator_exec_t:s0",
    ) != ArtifactClass::Exact
    {
        return Err("GeneratorVerificationRefused".into());
    }
    write_real_bootstrap_state(&format!("WritingBinding {transaction}\n"))?;
    real_guest_output(
        &[
            "mkdir-p",
            "/usr/lib/forge-preparation-control",
            ":",
            "upload",
            REAL_BOOTSTRAP_BINDING,
            BINDING,
            ":",
            "chmod",
            "0600",
            BINDING,
            ":",
            "chown",
            "0",
            "0",
            BINDING,
            ":",
            "setxattr",
            "security.selinux",
            "system_u:object_r:lib_t:s0",
            "26",
            BINDING,
        ],
        true,
    )?;
    if classify_fixed_binding(&binding) != ArtifactClass::Exact {
        return Err("BindingVerificationRefused".into());
    }
    write_real_bootstrap_state(&format!("Verifying {transaction}\n"))?;

    let after = real_guest_output(&real_verification_arguments(), false)?;
    validate_real_verification(&after, &transaction, &preparation, target_before.inode)?;
    write_real_bootstrap_state(&format!("Verified {transaction}\n"))?;
    let target_after = capture_host_storage_identity(Path::new(STAGING))?;
    if target_before.inode != target_after.inode
        || target_before.owner != target_after.owner
        || target_before.group != target_after.group
        || target_before.mode != target_after.mode
        || target_before.acl != target_after.acl
        || target_before.selinux_label != target_after.selinux_label
        || target_before.qcow2_capacity != target_after.qcow2_capacity
        || target_before.qcow2_backing != target_after.qcow2_backing
        || target_after.qcow2_dirty
        || target_after.qcow2_corrupt
    {
        return Err("RealHostIdentityDriftRefused".into());
    }
    let mut ledger = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(REAL_BOOTSTRAP_LEDGER)
        .map_err(|_| "BootstrapLedgerRefused")?;
    ledger
        .write_all(format!("{transaction}\n").as_bytes())
        .and_then(|()| ledger.sync_all())
        .map_err(|e| e.to_string())?;
    write_real_bootstrap_state(&format!("Completed {transaction}\n"))?;
    Ok(forge_images::PreparationBrokerBootstrapResult {
        protocol_version: forge_images::FORGE_PREPARATION_BROKER_PROTOCOL_VERSION,
        operation: request.operation,
        operation_id: request.operation_id.clone(),
        nonce: request.nonce.clone(),
        preparation_id: preparation.preparation_id,
        domain_uuid: domain.uuid,
        target: forge_images::PreparationBootstrapTarget::RealPreparation,
        source_checkpoint: SOURCE_CHECKPOINT.to_owned(),
        helper_sha256: HELPER_SHA256.to_owned(),
        helper_bytes: HELPER_BYTES,
        generator_sha256: HELPER_SHA256.to_owned(),
        generator_bytes: HELPER_BYTES,
        binding_sha256,
        binding_bytes: binding.len() as u64,
        helper_protocol_version: forge_images::FORGE_GUEST_CONTROL_PROTOCOL_VERSION,
        supported_operations: vec!["ReadOnlyGuestInventoryProbe".to_owned()],
        bootstrap_transaction_id: transaction,
        guest_paths: vec![HELPER.to_owned(), GENERATOR.to_owned(), BINDING.to_owned()],
        guest_modes: vec![
            "0:0:0755".to_owned(),
            "0:0:0755".to_owned(),
            "0:0:0600".to_owned(),
        ],
        guest_selinux_labels: vec![
            "bin_t".to_owned(),
            "systemd_generic_generator_exec_t".to_owned(),
            "lib_t".to_owned(),
        ],
        unexpected_paths_modified: false,
        clean_close: true,
        backend: "direct".to_owned(),
        target_sha256_before: String::new(),
        target_sha256_after: String::new(),
    })
}

fn validate_real_bootstrap_request(
    request: &forge_images::PreparationBrokerRequest,
) -> Result<(), String> {
    if request.protocol_version != forge_images::FORGE_PREPARATION_BROKER_PROTOCOL_VERSION
        || request.operation
            != forge_images::PreparationBrokerOperation::BootstrapPreparationHelperOffline
        || request.preparation_id.as_str() != PREPARATION
        || request.expected_domain_name != DOMAIN
        || request.expected_domain_uuid != UUID
        || request.bootstrap_target
            != Some(forge_images::PreparationBootstrapTarget::RealPreparation)
    {
        return Err("BootstrapRequestRefused".to_owned());
    }
    Ok(())
}

fn real_bootstrap_transaction_id(
    p: &forge_images::FedoraWorkstationPreparation,
    inode: u64,
) -> Result<String, String> {
    let discovery = p
        .execution
        .privileged_offline_discovery
        .as_ref()
        .ok_or("MissingR16EvidenceRefused")?;
    Ok(stable_identity(
        "real-bootstrap",
        &[
            SOURCE_CHECKPOINT,
            PREPARATION,
            UUID,
            STAGING,
            &inode.to_string(),
            &discovery.operation_id,
            &discovery.broker_sha256,
            HELPER_SHA256,
            "generator=same-fixed-artifact",
            "canonical-json-pretty-v1",
            "protocol=1",
            "recipe=V1",
            BROKER_VERSION,
        ],
    ))
}

fn real_bootstrap_nonce(transaction: &str) -> String {
    stable_identity("bootstrap-nonce", &[transaction, "RealPreparation", "1"])
}

fn expected_real_binding(
    transaction: &str,
    p: &forge_images::FedoraWorkstationPreparation,
    inode: u64,
) -> serde_json::Value {
    serde_json::json!({"protocol_version": forge_images::FORGE_GUEST_CONTROL_PROTOCOL_VERSION,
        "preparation_id": PREPARATION, "domain_name": DOMAIN, "domain_uuid": UUID,
        "staging_identity": {"path": STAGING, "volume_name": p.staging.volume_name, "volume_key": p.execution.staging_volume_key, "inode": inode, "capacity_bytes": p.staging.capacity_bytes},
        "normalization_recipe": "V1", "expected_state": "InstalledSystemProven",
        "bootstrap_transaction_id": transaction, "helper_sha256": HELPER_SHA256,
        "generator_sha256": HELPER_SHA256, "channel_name": forge_images::FORGE_PREPARATION_CHANNEL})
}
fn expected_real_binding_bytes(
    transaction: &str,
    p: &forge_images::FedoraWorkstationPreparation,
    inode: u64,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec_pretty(&expected_real_binding(transaction, p, inode))
        .map_err(|_| "BindingEncodingRefused".to_owned())
}
fn write_real_bootstrap_state(state: &str) -> Result<(), String> {
    atomic_publish(REAL_BOOTSTRAP_JOURNAL, state.as_bytes())
}
fn real_guest_output(arguments: &[&str], writable: bool) -> Result<String, String> {
    let access = if writable { "--rw" } else { "--ro" };
    let mut fixed = vec![access, "--format=qcow2", "-a", STAGING, "-i"];
    fixed.extend_from_slice(arguments);
    let result = fixed_output_with_backend(
        "/usr/bin/guestfish",
        &fixed,
        Duration::from_secs(120),
        "direct",
    );
    let (stdout, _) = match result {
        Ok(output) => output,
        Err(error) if writable => {
            retain_real_failure_diagnostic(&error)?;
            return Err(error);
        }
        Err(error) => return Err(error),
    };
    String::from_utf8(stdout).map_err(|e| e.to_string())
}

fn retain_real_failure_diagnostic(error: &str) -> Result<(), String> {
    let transaction = fs::read_to_string(REAL_BOOTSTRAP_JOURNAL)
        .unwrap_or_else(|_| "journal-unavailable".to_owned());
    let bounded = error
        .lines()
        .take(8)
        .collect::<Vec<_>>()
        .join("\n")
        .chars()
        .take(4096)
        .collect::<String>();
    let record = format!(
        "transaction_stage={transaction}backend=direct\nmode=rw\ncache=writeback\nstaging={STAGING}\nenvironment=LIBGUESTFS_BACKEND:direct,LIBGUESTFS_CACHEDIR:{LIBGUESTFS_CACHE_DIR},TMPDIR:{LIBGUESTFS_TMP_DIR}\nerror={bounded}\n"
    );
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(REAL_BOOTSTRAP_DIAGNOSTIC)
        .map_err(|e| e.to_string())?;
    file.write_all(record.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|e| e.to_string())
}
fn real_verification_arguments() -> Vec<&'static str> {
    let mut v = synthetic_verification_arguments();
    v.drain(0..6);
    let start = v.iter().position(|x| *x == "find").expect("fixed verifier");
    v.splice(start..=start + 1, ["echo", "usr/lib/forge-preparation-control/binding.json\nusr/lib/systemd/system-generators/forge-preparation-control-generator\nusr/libexec/forge-preparation-control"]);
    let sentinel = v
        .iter()
        .rposition(|x| *x == "checksum")
        .expect("fixed verifier");
    v.splice(
        sentinel..=sentinel + 2,
        [
            "echo",
            "9f2235c7754a56a9f0bc89dc2eb821ba0e52189db6dba93ee03d22337ae9739c",
        ],
    );
    v
}
fn validate_real_verification(
    output: &str,
    transaction: &str,
    p: &forge_images::FedoraWorkstationPreparation,
    inode: u64,
) -> Result<(), String> {
    let evidence = parse_synthetic_verification(output)?;
    if evidence.helper_digest != HELPER_SHA256
        || evidence.generator_digest != HELPER_SHA256
        || evidence.helper_stat
            != (GuestStat {
                mode: 33_261,
                uid: 0,
                gid: 0,
                size: HELPER_BYTES,
            })
        || evidence.generator_stat
            != (GuestStat {
                mode: 33_261,
                uid: 0,
                gid: 0,
                size: HELPER_BYTES,
            })
        || evidence.helper_label != "system_u:object_r:bin_t:s0"
        || evidence.generator_label != "system_u:object_r:systemd_generic_generator_exec_t:s0"
        || evidence.binding_label != "system_u:object_r:lib_t:s0"
    {
        return Err("RealArtifactVerificationRefused".to_owned());
    }
    let expected = expected_real_binding_bytes(transaction, p, inode)?;
    let expected_stat = GuestStat {
        mode: 33_152,
        uid: 0,
        gid: 0,
        size: expected.len() as u64,
    };
    if evidence.binding_stat != expected_stat {
        return Err(format!(
            "RealBindingStatMismatch(expected={expected_stat:?},observed={:?})",
            evidence.binding_stat
        ));
    }
    if evidence.binding_bytes != expected {
        return Err(format!(
            "RealBindingBytesMismatch(expected_sha256={:x},observed_sha256={:x})",
            Sha256::digest(&expected),
            Sha256::digest(&evidence.binding_bytes)
        ));
    }
    let observed_json = serde_json::from_slice::<serde_json::Value>(&evidence.binding_bytes)
        .map_err(|_| "RealBindingJsonMalformed")?;
    if observed_json != expected_real_binding(transaction, p, inode) {
        return Err("RealBindingSemanticIdentityMismatch".to_owned());
    }
    let expected_paths = [HELPER.to_owned(), GENERATOR.to_owned(), BINDING.to_owned()]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    let observed_paths = framed_paths(output)?;
    if observed_paths != expected_paths {
        return Err(format!(
            "RealPathSetMismatch(expected={expected_paths:?},observed={observed_paths:?})"
        ));
    }
    Ok(())
}

fn validate_bootstrap_request(
    request: &forge_images::PreparationBrokerRequest,
) -> Result<(), String> {
    let transaction = bootstrap_transaction_id();
    if request.protocol_version != forge_images::FORGE_PREPARATION_BROKER_PROTOCOL_VERSION
        || request.operation
            != forge_images::PreparationBrokerOperation::BootstrapPreparationHelperOffline
        || request.preparation_id.as_str() != PREPARATION
        || request.expected_domain_name != DOMAIN
        || request.expected_domain_uuid != UUID
        || request.bootstrap_target
            != Some(forge_images::PreparationBootstrapTarget::SyntheticProof)
        || request.operation_id != transaction
        || request.nonce != bootstrap_nonce(&transaction)
    {
        return Err("BootstrapRequestRefused".to_owned());
    }
    Ok(())
}

fn validate_bootstrap_preparation(
    p: &forge_images::FedoraWorkstationPreparation,
    request: &forge_images::PreparationBrokerRequest,
) -> Result<(), String> {
    let evidence = p
        .execution
        .privileged_offline_discovery
        .as_ref()
        .ok_or("MissingR16EvidenceRefused")?;
    if p.status != forge_images::FedoraWorkstationPreparationStatus::InstalledSystemProven
        || p.preparation_id != request.preparation_id
        || p.installer.uuid != UUID
        || p.staging.path != Path::new(STAGING)
        || p.execution.helper_bootstrap.is_some()
        || p.execution.preparation_channel.is_some()
        || evidence.preparation_id != p.preparation_id
        || evidence.domain_uuid != UUID
        || evidence.staging_volume_key != p.execution.staging_volume_key.clone().unwrap_or_default()
        || evidence.broker_sha256 != R16_BROKER_SHA256
        || evidence.backend != "direct"
        || evidence.os_root != "btrfsvol:/dev/sda3/root"
        || evidence.fedora_product != "Fedora Workstation"
        || evidence.fedora_release != "44"
        || evidence.architecture != "x86_64"
        || !evidence.guest_selinux_enforcing_configured
        || !evidence.clean_close
        || !evidence.host_metadata_unchanged
    {
        return Err("ForgedR16EvidenceRefused".to_owned());
    }
    Ok(())
}

fn bootstrap_transaction_id() -> String {
    stable_identity(
        "bootstrap",
        &[SOURCE_CHECKPOINT, PREPARATION, UUID, STAGING, HELPER_SHA256],
    )
}

fn bootstrap_nonce(transaction: &str) -> String {
    stable_identity("bootstrap-nonce", &[transaction, "SyntheticProof", "1"])
}

fn stable_identity(kind: &str, values: &[&str]) -> String {
    let mut hash = Sha256::new();
    hash.update(kind);
    for value in values {
        hash.update([0]);
        hash.update(value);
    }
    format!("{kind}-{:x}", hash.finalize())
}

fn helper_artifact_matches(bytes: u64, sha256: &str) -> bool {
    bytes == HELPER_BYTES && sha256 == HELPER_SHA256
}

fn classify_bootstrap_resume(
    journal: Option<&str>,
    artifacts_present: bool,
) -> Result<BootstrapResume, String> {
    match (journal, artifacts_present) {
        (None, false) => Ok(BootstrapResume::Fresh),
        (Some("Writing\n" | "Verifying\n" | "Verified\n"), _) => Ok(BootstrapResume::Resume),
        (Some("Completed\n"), _) => Err("ReplayRefused".to_owned()),
        (None, true) => Err("UnexpectedBootstrapArtifactRefused".to_owned()),
        (Some(_), _) => Err("BootstrapJournalRefused".to_owned()),
    }
}

fn write_bootstrap_state(state: &str) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(BOOTSTRAP_JOURNAL)
        .map_err(|e| e.to_string())?;
    file.write_all(state.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|e| e.to_string())
}

fn synthetic_guest_output(arguments: &[&str], writable: bool) -> Result<String, String> {
    let access = if writable { "--rw" } else { "--ro" };
    let mut fixed = vec![access, "--format=qcow2", "-a", BOOTSTRAP_SYNTHETIC];
    fixed.extend_from_slice(arguments);
    let (stdout, _) = fixed_output_with_backend(
        "/usr/bin/guestfish",
        &fixed,
        Duration::from_secs(120),
        "direct",
    )?;
    String::from_utf8(stdout).map_err(|e| e.to_string())
}

#[allow(clippy::too_many_lines)]
fn synthetic_verification_arguments() -> Vec<&'static str> {
    vec![
        "run",
        ":",
        "mount-ro",
        "/dev/sda1",
        "/",
        ":",
        "echo",
        "FORGE_PATHS_BEGIN",
        ":",
        "find",
        "/",
        ":",
        "echo",
        "",
        ":",
        "echo",
        "FORGE_PATHS_END",
        ":",
        "echo",
        "FORGE_HELPER_DIGEST_BEGIN",
        ":",
        "checksum",
        "sha256",
        HELPER,
        ":",
        "echo",
        "",
        ":",
        "echo",
        "FORGE_HELPER_DIGEST_END",
        ":",
        "echo",
        "FORGE_GENERATOR_DIGEST_BEGIN",
        ":",
        "checksum",
        "sha256",
        GENERATOR,
        ":",
        "echo",
        "",
        ":",
        "echo",
        "FORGE_GENERATOR_DIGEST_END",
        ":",
        "echo",
        "FORGE_BINDING_BASE64_BEGIN",
        ":",
        "base64-out",
        BINDING,
        "/dev/stdout",
        ":",
        "echo",
        "FORGE_BINDING_BASE64_END",
        ":",
        "echo",
        "FORGE_HELPER_LABEL_BEGIN",
        ":",
        "getxattr",
        HELPER,
        "security.selinux",
        ":",
        "echo",
        "",
        ":",
        "echo",
        "FORGE_HELPER_LABEL_END",
        ":",
        "echo",
        "FORGE_GENERATOR_LABEL_BEGIN",
        ":",
        "getxattr",
        GENERATOR,
        "security.selinux",
        ":",
        "echo",
        "",
        ":",
        "echo",
        "FORGE_GENERATOR_LABEL_END",
        ":",
        "echo",
        "FORGE_BINDING_LABEL_BEGIN",
        ":",
        "getxattr",
        BINDING,
        "security.selinux",
        ":",
        "echo",
        "",
        ":",
        "echo",
        "FORGE_BINDING_LABEL_END",
        ":",
        "echo",
        "FORGE_HELPER_STAT_BEGIN",
        ":",
        "statns",
        HELPER,
        ":",
        "echo",
        "",
        ":",
        "echo",
        "FORGE_HELPER_STAT_END",
        ":",
        "echo",
        "FORGE_GENERATOR_STAT_BEGIN",
        ":",
        "statns",
        GENERATOR,
        ":",
        "echo",
        "",
        ":",
        "echo",
        "FORGE_GENERATOR_STAT_END",
        ":",
        "echo",
        "FORGE_BINDING_STAT_BEGIN",
        ":",
        "statns",
        BINDING,
        ":",
        "echo",
        "",
        ":",
        "echo",
        "FORGE_BINDING_STAT_END",
        ":",
        "echo",
        "FORGE_SENTINEL_DIGEST_BEGIN",
        ":",
        "checksum",
        "sha256",
        "/etc/forge-synthetic-sentinel",
        ":",
        "echo",
        "",
        ":",
        "echo",
        "FORGE_SENTINEL_DIGEST_END",
    ]
}

fn expected_synthetic_paths() -> std::collections::BTreeSet<String> {
    [
        "/etc",
        "/etc/forge-synthetic-sentinel",
        "/lost+found",
        "/usr",
        "/usr/lib",
        "/usr/lib/systemd",
        "/usr/lib/systemd/system-generators",
        GENERATOR,
        "/usr/lib/forge-preparation-control",
        BINDING,
        "/usr/libexec",
        HELPER,
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

#[derive(Debug, PartialEq, Eq)]
struct GuestStat {
    mode: u64,
    uid: u64,
    gid: u64,
    size: u64,
}

#[derive(Debug, PartialEq, Eq)]
struct SyntheticVerification {
    helper_digest: String,
    generator_digest: String,
    binding_bytes: Vec<u8>,
    helper_label: String,
    generator_label: String,
    binding_label: String,
    helper_stat: GuestStat,
    generator_stat: GuestStat,
    binding_stat: GuestStat,
    sentinel_digest: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SyntheticFrame {
    PathInventory,
    HelperDigest,
    GeneratorDigest,
    BindingBase64,
    HelperXattr,
    GeneratorXattr,
    BindingXattr,
    HelperStat,
    GeneratorStat,
    BindingStat,
    Sentinel,
}

impl SyntheticFrame {
    fn name(self) -> &'static str {
        match self {
            Self::PathInventory => "PathInventory",
            Self::HelperDigest => "HelperDigest",
            Self::GeneratorDigest => "GeneratorDigest",
            Self::BindingBase64 => "BindingBase64",
            Self::HelperXattr => "HelperXattr",
            Self::GeneratorXattr => "GeneratorXattr",
            Self::BindingXattr => "BindingXattr",
            Self::HelperStat => "HelperStat",
            Self::GeneratorStat => "GeneratorStat",
            Self::BindingStat => "BindingStat",
            Self::Sentinel => "Sentinel",
        }
    }
}

fn structured_frame<'a>(
    value: &'a str,
    kind: SyntheticFrame,
    start: &str,
    end: &str,
) -> Result<&'a str, String> {
    const MAX_FRAME_PAYLOAD: usize = 64 * 1024;
    let lines = value.split('\n').collect::<Vec<_>>();
    let starts = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| **line == start)
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    let ends = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| **line == end)
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    let failure = |category: &str| format!("{}{category}", kind.name());
    if starts.is_empty() {
        return Err(failure("MissingBegin"));
    }
    if starts.len() != 1 {
        return Err(failure("DuplicateBegin"));
    }
    if ends.is_empty() {
        return Err(failure("MissingEnd"));
    }
    if ends.len() != 1 {
        return Err(failure("DuplicateEnd"));
    }
    if starts[0] >= ends[0] {
        return Err(failure("MalformedBoundary"));
    }
    let begin = value
        .match_indices(&format!("{start}\n"))
        .next()
        .ok_or_else(|| failure("MalformedBoundary"))?
        .0
        + start.len()
        + 1;
    let end_at = value
        .match_indices(&format!("\n{end}"))
        .next()
        .ok_or_else(|| failure("MalformedBoundary"))?
        .0;
    if begin > end_at {
        return Err(failure("MalformedBoundary"));
    }
    let payload = &value[begin..end_at];
    if payload.len() > MAX_FRAME_PAYLOAD {
        return Err(failure("Oversized"));
    }
    if payload.chars().any(|character| {
        character.is_control()
            && !matches!(character, '\n' | '\r' | '\t')
            && !(character == '\0'
                && matches!(
                    kind,
                    SyntheticFrame::HelperXattr
                        | SyntheticFrame::GeneratorXattr
                        | SyntheticFrame::BindingXattr
                ))
    }) {
        return Err(failure("ControlCharacter"));
    }
    Ok(payload)
}

fn parse_guest_stat(value: &str) -> Result<GuestStat, String> {
    fn field(value: &str, name: &str) -> Result<u64, String> {
        let matches = value
            .lines()
            .filter_map(|line| line.strip_prefix(name))
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err("ArtifactStatRefused".to_owned());
        }
        matches[0]
            .trim()
            .parse()
            .map_err(|_| "ArtifactStatRefused".to_owned())
    }
    Ok(GuestStat {
        mode: field(value, "st_mode:")?,
        uid: field(value, "st_uid:")?,
        gid: field(value, "st_gid:")?,
        size: field(value, "st_size:")?,
    })
}

fn expected_binding(transaction: &str) -> serde_json::Value {
    serde_json::json!({
        "protocol_version": forge_images::FORGE_GUEST_CONTROL_PROTOCOL_VERSION,
        "preparation_id": PREPARATION,
        "domain_name": DOMAIN,
        "domain_uuid": UUID,
        "staging_path": STAGING,
        "expected_state": "InstalledSystemProven",
        "bootstrap_transaction_id": transaction,
        "helper_sha256": HELPER_SHA256,
    })
}

fn expected_binding_bytes(transaction: &str) -> Result<Vec<u8>, String> {
    serde_json::to_vec_pretty(&expected_binding(transaction))
        .map_err(|_| "BindingEncodingRefused".to_owned())
}

fn decode_binding_base64(encoded: &str) -> Result<Vec<u8>, String> {
    const MAX_BINDING_BYTES: usize = 4096;
    let compact = encoded
        .bytes()
        .filter(|byte| !matches!(byte, b'\r' | b'\n'))
        .collect::<Vec<_>>();
    if compact.len() > 4 * MAX_BINDING_BYTES / 3 + 4 {
        return Err("BindingBase64Oversized".to_owned());
    }
    if compact.is_empty() || compact.len() % 4 != 0 {
        return Err("BindingBase64Malformed".to_owned());
    }
    let mut decoded = Vec::with_capacity(compact.len() / 4 * 3);
    let (quartets, remainder) = compact.as_chunks::<4>();
    if !remainder.is_empty() {
        return Err("BindingBase64Malformed".to_owned());
    }
    for (index, quartet) in quartets.iter().enumerate() {
        let last = index + 1 == quartets.len();
        let value = |byte: u8| -> Option<u8> {
            match byte {
                b'A'..=b'Z' => Some(byte - b'A'),
                b'a'..=b'z' => Some(byte - b'a' + 26),
                b'0'..=b'9' => Some(byte - b'0' + 52),
                b'+' => Some(62),
                b'/' => Some(63),
                _ => None,
            }
        };
        let a = value(quartet[0]).ok_or_else(|| "BindingBase64Malformed".to_owned())?;
        let b = value(quartet[1]).ok_or_else(|| "BindingBase64Malformed".to_owned())?;
        let padding = match (quartet[2], quartet[3]) {
            (b'=', b'=') if last => 2,
            (_, b'=') if last => 1,
            (b'=', _) => return Err("BindingBase64Malformed".to_owned()),
            _ => 0,
        };
        let c = if padding == 2 {
            0
        } else {
            value(quartet[2]).ok_or_else(|| "BindingBase64Malformed".to_owned())?
        };
        let d = if padding > 0 {
            0
        } else {
            value(quartet[3]).ok_or_else(|| "BindingBase64Malformed".to_owned())?
        };
        if (padding == 2 && b & 0x0f != 0) || (padding == 1 && c & 0x03 != 0) {
            return Err("BindingBase64Malformed".to_owned());
        }
        decoded.push((a << 2) | (b >> 4));
        if padding < 2 {
            decoded.push((b << 4) | (c >> 2));
        }
        if padding == 0 {
            decoded.push((c << 6) | d);
        }
        if decoded.len() > MAX_BINDING_BYTES {
            return Err("BindingBase64Oversized".to_owned());
        }
    }
    Ok(decoded)
}

fn parse_synthetic_verification(output: &str) -> Result<SyntheticVerification, String> {
    let binding_base64 = structured_frame(
        output,
        SyntheticFrame::BindingBase64,
        "FORGE_BINDING_BASE64_BEGIN",
        "FORGE_BINDING_BASE64_END",
    )?;
    Ok(SyntheticVerification {
        helper_digest: structured_frame(
            output,
            SyntheticFrame::HelperDigest,
            "FORGE_HELPER_DIGEST_BEGIN",
            "FORGE_HELPER_DIGEST_END",
        )?
        .trim()
        .to_owned(),
        generator_digest: structured_frame(
            output,
            SyntheticFrame::GeneratorDigest,
            "FORGE_GENERATOR_DIGEST_BEGIN",
            "FORGE_GENERATOR_DIGEST_END",
        )?
        .trim()
        .to_owned(),
        binding_bytes: decode_binding_base64(binding_base64)?,
        helper_label: structured_frame(
            output,
            SyntheticFrame::HelperXattr,
            "FORGE_HELPER_LABEL_BEGIN",
            "FORGE_HELPER_LABEL_END",
        )?
        .trim_end_matches('\0')
        .trim()
        .to_owned(),
        generator_label: structured_frame(
            output,
            SyntheticFrame::GeneratorXattr,
            "FORGE_GENERATOR_LABEL_BEGIN",
            "FORGE_GENERATOR_LABEL_END",
        )?
        .trim_end_matches('\0')
        .trim()
        .to_owned(),
        binding_label: structured_frame(
            output,
            SyntheticFrame::BindingXattr,
            "FORGE_BINDING_LABEL_BEGIN",
            "FORGE_BINDING_LABEL_END",
        )?
        .trim_end_matches('\0')
        .trim()
        .to_owned(),
        helper_stat: parse_guest_stat(structured_frame(
            output,
            SyntheticFrame::HelperStat,
            "FORGE_HELPER_STAT_BEGIN",
            "FORGE_HELPER_STAT_END",
        )?)
        .map_err(|_| "HelperStatMalformed".to_owned())?,
        generator_stat: parse_guest_stat(structured_frame(
            output,
            SyntheticFrame::GeneratorStat,
            "FORGE_GENERATOR_STAT_BEGIN",
            "FORGE_GENERATOR_STAT_END",
        )?)
        .map_err(|_| "GeneratorStatMalformed".to_owned())?,
        binding_stat: parse_guest_stat(structured_frame(
            output,
            SyntheticFrame::BindingStat,
            "FORGE_BINDING_STAT_BEGIN",
            "FORGE_BINDING_STAT_END",
        )?)
        .map_err(|_| "BindingStatMalformed".to_owned())?,
        sentinel_digest: structured_frame(
            output,
            SyntheticFrame::Sentinel,
            "FORGE_SENTINEL_DIGEST_BEGIN",
            "FORGE_SENTINEL_DIGEST_END",
        )?
        .trim()
        .to_owned(),
    })
}

#[cfg(test)]
fn synthetic_verification_valid(output: &str, transaction: &str) -> bool {
    validate_synthetic_verification(output, transaction).is_ok()
}

fn validate_synthetic_verification(output: &str, transaction: &str) -> Result<(), String> {
    let evidence = parse_synthetic_verification(output)?;
    let expected_binding = expected_binding(transaction);
    let expected_binding_bytes = expected_binding_bytes(transaction)?;
    if evidence.helper_digest != HELPER_SHA256
        || evidence.helper_stat
            != (GuestStat {
                mode: 33_261,
                uid: 0,
                gid: 0,
                size: HELPER_BYTES,
            })
        || evidence.helper_label != "system_u:object_r:bin_t:s0"
    {
        return Err("SyntheticHelperRefused".to_owned());
    }
    if evidence.generator_digest != HELPER_SHA256
        || evidence.generator_stat
            != (GuestStat {
                mode: 33_261,
                uid: 0,
                gid: 0,
                size: HELPER_BYTES,
            })
        || evidence.generator_label != "system_u:object_r:systemd_generic_generator_exec_t:s0"
    {
        return Err("SyntheticGeneratorRefused".to_owned());
    }
    let mut binding_failures = Vec::new();
    if evidence.binding_stat.size != expected_binding_bytes.len() as u64
        || evidence.binding_stat.size != evidence.binding_bytes.len() as u64
    {
        binding_failures.push("BindingSizeMismatch".to_owned());
    }
    if evidence.binding_stat.uid != 0 {
        binding_failures.push("BindingUidMismatch".to_owned());
    }
    if evidence.binding_stat.gid != 0 {
        binding_failures.push("BindingGidMismatch".to_owned());
    }
    if evidence.binding_stat.mode != 33_152 {
        binding_failures.push("BindingModeMismatch".to_owned());
    }
    if evidence.binding_label != "system_u:object_r:lib_t:s0" {
        binding_failures.push("BindingSelinuxLabelMismatch".to_owned());
    }
    match serde_json::from_slice::<serde_json::Value>(&evidence.binding_bytes) {
        Err(_) => binding_failures.push("BindingJsonMalformed".to_owned()),
        Ok(binding) if binding != expected_binding => {
            binding_failures.push("BindingJsonSemanticMismatch".to_owned());
        }
        Ok(_) => {}
    }
    if evidence.binding_bytes != expected_binding_bytes {
        let expected_digest = format!("{:x}", Sha256::digest(&expected_binding_bytes));
        let observed_digest = format!("{:x}", Sha256::digest(&evidence.binding_bytes));
        binding_failures.push(format!(
            "BindingContentMismatch(expected_length={},observed_length={},expected_sha256={expected_digest},observed_sha256={observed_digest})",
            expected_binding_bytes.len(), evidence.binding_bytes.len()
        ));
    }
    if !binding_failures.is_empty() {
        return Err(format!(
            "SyntheticBindingRefused[{}]",
            binding_failures.join(",")
        ));
    }
    if evidence.sentinel_digest
        != "9f2235c7754a56a9f0bc89dc2eb821ba0e52189db6dba93ee03d22337ae9739c"
    {
        return Err("SyntheticSentinelRefused".to_owned());
    }
    Ok(())
}

fn framed_paths(output: &str) -> Result<std::collections::BTreeSet<String>, String> {
    let mut paths = std::collections::BTreeSet::new();
    for path in structured_frame(
        output,
        SyntheticFrame::PathInventory,
        "FORGE_PATHS_BEGIN",
        "FORGE_PATHS_END",
    )?
    .lines()
    {
        if path.is_empty() || path.starts_with('/') || !paths.insert(format!("/{path}")) {
            return Err("PathInventoryRefused".to_owned());
        }
    }
    Ok(paths)
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
        || request.bootstrap_target.is_some()
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
            bootstrap_target: None,
            operation_id: "operation-00000001".to_owned(),
            nonce: "n".repeat(32),
        }
    }
    fn bootstrap_request() -> forge_images::PreparationBrokerRequest {
        let transaction = bootstrap_transaction_id();
        forge_images::PreparationBrokerRequest {
            protocol_version: 1,
            operation: forge_images::PreparationBrokerOperation::BootstrapPreparationHelperOffline,
            preparation_id: forge_images::FedoraWorkstationPreparationId::new(
                PREPARATION.to_owned(),
            )
            .unwrap(),
            expected_domain_name: DOMAIN.to_owned(),
            expected_domain_uuid: UUID.to_owned(),
            bootstrap_target: Some(forge_images::PreparationBootstrapTarget::SyntheticProof),
            operation_id: transaction.clone(),
            nonce: bootstrap_nonce(&transaction),
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
    fn synthetic_bootstrap_validator_remains_target_exact() {
        assert!(validate_bootstrap_request(&bootstrap_request()).is_ok());
        let mut request = bootstrap_request();
        request.bootstrap_target = Some(forge_images::PreparationBootstrapTarget::RealPreparation);
        assert!(validate_bootstrap_request(&request).is_err());
        let mut request = bootstrap_request();
        request.expected_domain_uuid = "wrong".to_owned();
        assert!(validate_bootstrap_request(&request).is_err());
        let mut request = bootstrap_request();
        request.protocol_version += 1;
        assert!(validate_bootstrap_request(&request).is_err());
        let mut request = bootstrap_request();
        request.operation_id = "forged-transaction".to_owned();
        assert!(validate_bootstrap_request(&request).is_err());
        let mut request = bootstrap_request();
        request.nonce = "forged-nonce".to_owned();
        assert!(validate_bootstrap_request(&request).is_err());
    }
    #[test]
    fn bootstrap_schema_exposes_no_generic_authority() {
        let base = serde_json::to_value(bootstrap_request()).unwrap();
        for field in [
            "host_path",
            "guest_path",
            "bytes",
            "executable",
            "argv",
            "shell",
            "command",
            "backend",
            "disk",
            "disk_path",
            "domain_path",
            "mount_point",
            "chmod_target",
            "chown_target",
            "selinux_label",
            "copy_source",
            "copy_destination",
        ] {
            let mut value = base.clone();
            value[field] = serde_json::json!("forbidden");
            assert!(
                serde_json::from_value::<forge_images::PreparationBrokerRequest>(value).is_err()
            );
        }
        let mut unsupported = base;
        unsupported["operation"] = serde_json::json!("GenericGuestfish");
        assert!(
            serde_json::from_value::<forge_images::PreparationBrokerRequest>(unsupported).is_err()
        );
    }
    #[test]
    fn helper_identity_is_independently_fixed() {
        assert!(helper_artifact_matches(HELPER_BYTES, HELPER_SHA256));
        assert!(!helper_artifact_matches(HELPER_BYTES + 1, HELPER_SHA256));
        assert!(!helper_artifact_matches(HELPER_BYTES, &"0".repeat(64)));
    }
    #[test]
    fn synthetic_recovery_matrix_and_resume_plans_are_fail_closed() {
        use ArtifactClass::{Absent, Exact, PartialOrMismatched, UnreadableOrIndeterminate};
        use RecoveryClass::{
            ExactComplete, ExactPrefix, HelperExactOnly, InconsistentSet, Indeterminate,
            NothingWritten, PartialOrMismatched as Mismatch,
        };
        use ResumePlan::{
            RecoveryBlockedInconsistent, RecoveryBlockedIndeterminate, RecoveryBlockedMismatch,
            ResumeWritingBinding, ResumeWritingGenerator, ResumeWritingHelper,
            VerifyExistingArtifacts,
        };
        let cases = [
            (
                (Absent, Absent, Absent),
                (NothingWritten, ResumeWritingHelper),
            ),
            (
                (Exact, Absent, Absent),
                (HelperExactOnly, ResumeWritingGenerator),
            ),
            ((Exact, Exact, Absent), (ExactPrefix, ResumeWritingBinding)),
            (
                (Exact, Exact, Exact),
                (ExactComplete, VerifyExistingArtifacts),
            ),
            (
                (PartialOrMismatched, Absent, Absent),
                (Mismatch, RecoveryBlockedMismatch),
            ),
            (
                (PartialOrMismatched, Absent, Absent),
                (Mismatch, RecoveryBlockedMismatch),
            ),
            (
                (Exact, PartialOrMismatched, Absent),
                (Mismatch, RecoveryBlockedMismatch),
            ),
            (
                (Exact, Exact, PartialOrMismatched),
                (Mismatch, RecoveryBlockedMismatch),
            ),
            (
                (Exact, Exact, PartialOrMismatched),
                (Mismatch, RecoveryBlockedMismatch),
            ),
            (
                (Absent, Absent, Exact),
                (InconsistentSet, RecoveryBlockedInconsistent),
            ),
            (
                (UnreadableOrIndeterminate, Absent, Absent),
                (Indeterminate, RecoveryBlockedIndeterminate),
            ),
        ];
        for ((helper, generator, binding), expected) in cases {
            assert_eq!(recovery_outcome(helper, generator, binding), expected);
        }
    }

    #[test]
    fn recovery_request_binds_exact_transaction_and_exposes_no_generic_authority() {
        let transaction = "real-bootstrap-exact";
        let mut request = bootstrap_request();
        request.operation =
            forge_images::PreparationBrokerOperation::ClassifyBootstrapRecoveryReadOnly;
        request.bootstrap_target = Some(forge_images::PreparationBootstrapTarget::RealPreparation);
        request.operation_id = transaction.to_owned();
        request.nonce = real_bootstrap_nonce(transaction);
        assert!(validate_recovery_request(&request, transaction).is_ok());
        request.operation_id = "real-bootstrap-other".to_owned();
        assert!(validate_recovery_request(&request, transaction).is_err());
        let value = serde_json::to_value(request).unwrap();
        for field in [
            "path", "disk", "backend", "command", "argv", "shell", "decoder", "bytes",
        ] {
            assert!(value.get(field).is_none());
        }
    }

    #[test]
    fn recovery_classifier_source_is_read_only_and_journal_preserving() {
        let source = include_str!("broker.rs");
        let recovery = &source[source.find("fn classify_real_recovery(").unwrap()
            ..source.find("fn atomic_publish(").unwrap()];
        assert!(recovery.contains("read_only_presence"));
        assert!(!recovery.contains("write_real_bootstrap_state"));
        assert!(!recovery.contains("\"--rw\""));
        assert!(!recovery.contains("upload"));
        assert!(!recovery.contains("create_new"));
    }

    #[test]
    fn completion_only_path_has_no_writable_guest_operation() {
        let source = include_str!("broker.rs");
        let completion = &source[source.find("fn complete_real_recovery(").unwrap()
            ..source.find("fn bootstrap_helper(").unwrap()];
        assert!(completion.contains("classify_real_recovery(request)"));
        assert!(completion.contains("RecoveryClass::ExactComplete"));
        assert!(completion.contains("ResumePlan::VerifyExistingArtifacts"));
        assert!(completion.contains("atomic_publish(REAL_BOOTSTRAP_EVIDENCE"));
        assert!(completion.contains("atomic_publish(\n        REAL_BOOTSTRAP_LEDGER"));
        assert!(completion.contains("atomic_publish(\n        REAL_BOOTSTRAP_JOURNAL"));
        assert!(!completion.contains("real_guest_output"));
        assert!(!completion.contains("\"--rw\""));
        assert!(!completion.contains("upload"));
        assert!(!completion.contains("write_real_bootstrap_state"));
    }
    #[test]
    fn crash_boundaries_are_detectable_resumable_or_replay_refused() {
        assert_eq!(
            classify_bootstrap_resume(None, false).unwrap(),
            BootstrapResume::Fresh
        );
        assert_eq!(
            classify_bootstrap_resume(Some("Writing\n"), true).unwrap(),
            BootstrapResume::Resume
        );
        assert_eq!(
            classify_bootstrap_resume(Some("Verifying\n"), true).unwrap(),
            BootstrapResume::Resume
        );
        assert_eq!(
            classify_bootstrap_resume(Some("Verified\n"), true).unwrap(),
            BootstrapResume::Resume
        );
        assert_eq!(
            classify_bootstrap_resume(Some("Writing\n"), false).unwrap(),
            BootstrapResume::Resume
        );
        assert!(classify_bootstrap_resume(None, true).is_err());
        assert!(classify_bootstrap_resume(Some("Completed\n"), true).is_err());
        assert!(classify_bootstrap_resume(Some("malformed\n"), false).is_err());
    }
    #[test]
    fn getxattr_uses_path_then_name_and_reversed_order_regresses() {
        let arguments = synthetic_verification_arguments();
        for path in [HELPER, GENERATOR, BINDING] {
            assert!(
                arguments
                    .windows(3)
                    .any(|window| { window == ["getxattr", path, "security.selinux"] })
            );
            assert!(
                !arguments
                    .windows(3)
                    .any(|window| { window == ["getxattr", "security.selinux", path] })
            );
        }
        for end in [
            "FORGE_PATHS_END",
            "FORGE_HELPER_DIGEST_END",
            "FORGE_GENERATOR_DIGEST_END",
            "FORGE_HELPER_LABEL_END",
            "FORGE_GENERATOR_LABEL_END",
            "FORGE_BINDING_LABEL_END",
            "FORGE_HELPER_STAT_END",
            "FORGE_GENERATOR_STAT_END",
            "FORGE_BINDING_STAT_END",
            "FORGE_SENTINEL_DIGEST_END",
        ] {
            assert!(
                arguments
                    .windows(5)
                    .any(|window| window == ["echo", "", ":", "echo", end])
            );
        }
        assert!(
            arguments
                .windows(5)
                .any(|window| { window == ["base64-out", BINDING, "/dev/stdout", ":", "echo",] })
        );
        assert!(arguments.contains(&"FORGE_BINDING_BASE64_END"));
        assert!(!arguments.contains(&"cat"));
    }

    #[test]
    fn structured_frames_are_newline_independent_and_diagnostic() {
        let start = "FORGE_BINDING_BASE64_BEGIN";
        let end = "FORGE_BINDING_BASE64_END";
        for payload in ["e30=", "e30=\n", "e30=\n\n"] {
            let framed = format!("{start}\n{payload}\n{end}\n");
            assert_eq!(
                structured_frame(&framed, SyntheticFrame::BindingBase64, start, end).unwrap(),
                payload
            );
        }
        let concatenated = format!("{start}\ne30={end}\n");
        assert_eq!(
            structured_frame(&concatenated, SyntheticFrame::BindingBase64, start, end),
            Err("BindingBase64MissingEnd".to_owned())
        );
        let duplicate_begin = format!("{start}\n{start}\ne30=\n{end}\n");
        assert_eq!(
            structured_frame(&duplicate_begin, SyntheticFrame::BindingBase64, start, end),
            Err("BindingBase64DuplicateBegin".to_owned())
        );
        let duplicate_end = format!("{start}\ne30=\n{end}\n{end}\n");
        assert_eq!(
            structured_frame(&duplicate_end, SyntheticFrame::BindingBase64, start, end),
            Err("BindingBase64DuplicateEnd".to_owned())
        );
        assert_eq!(
            structured_frame(
                &format!("{start}\ne30=\n"),
                SyntheticFrame::BindingBase64,
                start,
                end
            ),
            Err("BindingBase64MissingEnd".to_owned())
        );
        let empty = format!("{start}\n\n{end}\n");
        assert_eq!(
            structured_frame(&empty, SyntheticFrame::BindingBase64, start, end).unwrap(),
            ""
        );
        let oversized = format!("{start}\n{}\n{end}\n", "x".repeat(64 * 1024 + 1));
        assert_eq!(
            structured_frame(&oversized, SyntheticFrame::BindingBase64, start, end),
            Err("BindingBase64Oversized".to_owned())
        );
    }

    #[test]
    fn every_synthetic_frame_preserves_payload_boundaries_independently() {
        for (kind, start, end) in [
            (SyntheticFrame::HelperDigest, "H_BEGIN", "H_END"),
            (SyntheticFrame::GeneratorDigest, "G_BEGIN", "G_END"),
            (SyntheticFrame::HelperXattr, "X_BEGIN", "X_END"),
            (SyntheticFrame::HelperStat, "S_BEGIN", "S_END"),
            (SyntheticFrame::PathInventory, "P_BEGIN", "P_END"),
            (SyntheticFrame::Sentinel, "D_BEGIN", "D_END"),
        ] {
            for payload in ["value", "value\n", "value\n\n"] {
                let framed = format!("{start}\n{payload}\n{end}\n");
                assert_eq!(
                    structured_frame(&framed, kind, start, end).unwrap(),
                    payload
                );
            }
        }
        assert_eq!(
            structured_frame(
                "G_BEGIN\nvalue\n",
                SyntheticFrame::GeneratorDigest,
                "G_BEGIN",
                "G_END"
            ),
            Err("GeneratorDigestMissingEnd".to_owned())
        );
    }
    fn encode_base64(bytes: &[u8]) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
        for chunk in bytes.chunks(3) {
            let a = chunk[0];
            let b = *chunk.get(1).unwrap_or(&0);
            let c = *chunk.get(2).unwrap_or(&0);
            encoded.push(TABLE[(a >> 2) as usize] as char);
            encoded.push(TABLE[(((a & 3) << 4) | (b >> 4)) as usize] as char);
            encoded.push(if chunk.len() > 1 {
                TABLE[(((b & 15) << 2) | (c >> 6)) as usize] as char
            } else {
                '='
            });
            encoded.push(if chunk.len() > 2 {
                TABLE[(c & 63) as usize] as char
            } else {
                '='
            });
        }
        encoded
    }

    fn exact_verification_output() -> String {
        let transaction = bootstrap_transaction_id();
        let binding = expected_binding_bytes(&transaction).unwrap();
        let binding_size = binding.len();
        let binding_base64 = encode_base64(&binding);
        format!(
            "FORGE_HELPER_DIGEST_BEGIN\n{HELPER_SHA256}\nFORGE_HELPER_DIGEST_END\n\
FORGE_GENERATOR_DIGEST_BEGIN\n{HELPER_SHA256}\nFORGE_GENERATOR_DIGEST_END\n\
FORGE_BINDING_BASE64_BEGIN\n{binding_base64}\nFORGE_BINDING_BASE64_END\n\
FORGE_HELPER_LABEL_BEGIN\nsystem_u:object_r:bin_t:s0\nFORGE_HELPER_LABEL_END\n\
FORGE_GENERATOR_LABEL_BEGIN\nsystem_u:object_r:systemd_generic_generator_exec_t:s0\nFORGE_GENERATOR_LABEL_END\n\
FORGE_BINDING_LABEL_BEGIN\nsystem_u:object_r:lib_t:s0\nFORGE_BINDING_LABEL_END\n\
FORGE_HELPER_STAT_BEGIN\nst_mode: 33261\nst_uid: 0\nst_gid: 0\nst_size: {HELPER_BYTES}\nFORGE_HELPER_STAT_END\n\
FORGE_GENERATOR_STAT_BEGIN\nst_mode: 33261\nst_uid: 0\nst_gid: 0\nst_size: {HELPER_BYTES}\nFORGE_GENERATOR_STAT_END\n\
FORGE_BINDING_STAT_BEGIN\nst_mode: 33152\nst_uid: 0\nst_gid: 0\nst_size: {binding_size}\nFORGE_BINDING_STAT_END\n\
FORGE_SENTINEL_DIGEST_BEGIN\n9f2235c7754a56a9f0bc89dc2eb821ba0e52189db6dba93ee03d22337ae9739c\nFORGE_SENTINEL_DIGEST_END\n"
        )
    }

    fn verification_with_binding(bytes: &[u8]) -> String {
        let mut output = exact_verification_output();
        let canonical = expected_binding_bytes(&bootstrap_transaction_id()).unwrap();
        output = output.replace(&encode_base64(&canonical), &encode_base64(bytes));
        output.replace(
            &format!("st_size: {}", canonical.len()),
            &format!("st_size: {}", bytes.len()),
        )
    }

    fn binding_failure(output: &str) -> String {
        validate_synthetic_verification(output, &bootstrap_transaction_id()).unwrap_err()
    }

    fn replace_binding_evidence(output: &str, original: &str, changed: &str) -> String {
        let marker = if original.contains("lib_t") {
            "FORGE_BINDING_LABEL_BEGIN"
        } else {
            "FORGE_BINDING_STAT_BEGIN"
        };
        let binding_start = output.find(marker).unwrap();
        let at = binding_start + output[binding_start..].find(original).unwrap();
        format!(
            "{}{}{}",
            &output[..at],
            changed,
            &output[at + original.len()..]
        )
    }

    #[test]
    fn binding_binary_transport_and_exact_byte_contract_regressions() {
        let canonical = expected_binding_bytes(&bootstrap_transaction_id()).unwrap();
        assert_eq!(
            decode_binding_base64(&encode_base64(&canonical)).unwrap(),
            canonical
        );
        assert!(synthetic_verification_valid(
            &verification_with_binding(&canonical),
            &bootstrap_transaction_id()
        ));

        let mut newline = canonical.clone();
        newline.push(b'\n');
        let newline_failure = binding_failure(&verification_with_binding(&newline));
        assert!(newline_failure.contains("BindingContentMismatch"));
        assert!(!newline_failure.contains("BindingJsonSemanticMismatch"));

        let compact = serde_json::to_vec(&expected_binding(&bootstrap_transaction_id())).unwrap();
        let whitespace_failure = binding_failure(&verification_with_binding(&compact));
        assert!(whitespace_failure.contains("BindingContentMismatch"));
        assert!(!whitespace_failure.contains("BindingJsonSemanticMismatch"));

        assert_eq!(
            decode_binding_base64("!!!!"),
            Err("BindingBase64Malformed".to_owned())
        );
        assert_eq!(
            decode_binding_base64("e30"),
            Err("BindingBase64Malformed".to_owned())
        );
        assert_eq!(
            decode_binding_base64(&"A".repeat(4 * 4096 / 3 + 8)),
            Err("BindingBase64Oversized".to_owned())
        );
    }

    #[test]
    fn binding_subpredicate_diagnostics_are_typed_and_bounded() {
        let canonical = expected_binding_bytes(&bootstrap_transaction_id()).unwrap();
        for (changed, diagnostic) in [
            ("st_size: 999", "BindingSizeMismatch"),
            ("st_uid: 1000", "BindingUidMismatch"),
            ("st_gid: 1000", "BindingGidMismatch"),
            ("st_mode: 33188", "BindingModeMismatch"),
            (
                "system_u:object_r:unlabeled_t:s0",
                "BindingSelinuxLabelMismatch",
            ),
        ] {
            let original = match diagnostic {
                "BindingSizeMismatch" => format!("st_size: {}", canonical.len()),
                "BindingUidMismatch" => "st_uid: 0".to_owned(),
                "BindingGidMismatch" => "st_gid: 0".to_owned(),
                "BindingModeMismatch" => "st_mode: 33152".to_owned(),
                _ => "system_u:object_r:lib_t:s0".to_owned(),
            };
            assert!(
                binding_failure(&replace_binding_evidence(
                    &exact_verification_output(),
                    &original,
                    changed
                ))
                .contains(diagnostic)
            );
        }

        let malformed = binding_failure(&verification_with_binding(b"not-json"));
        assert!(malformed.contains("BindingJsonMalformed"));
        let mut semantic = expected_binding(&bootstrap_transaction_id());
        semantic["protocol_version"] = serde_json::json!(2);
        let semantic = serde_json::to_vec_pretty(&semantic).unwrap();
        assert!(
            binding_failure(&verification_with_binding(&semantic))
                .contains("BindingJsonSemanticMismatch")
        );

        let mismatch = binding_failure(&verification_with_binding(b"{}"));
        assert!(mismatch.contains("expected_length="));
        assert!(mismatch.contains("observed_length=2"));
        assert!(mismatch.contains("expected_sha256="));
        assert!(mismatch.contains("observed_sha256="));
        assert!(!mismatch.contains(std::str::from_utf8(&canonical).unwrap()));
    }

    #[test]
    fn exact_verifying_resume_requires_every_artifact_property() {
        let transaction = bootstrap_transaction_id();
        let exact = exact_verification_output();
        assert!(synthetic_verification_valid(&exact, &transaction));
        assert_eq!(exact.matches(HELPER_SHA256).count(), 2);
        assert!(synthetic_verification_valid(
            &format!("untrusted-text={HELPER_SHA256}\n{exact}"),
            &transaction
        ));
        for broken in [
            exact.replacen(HELPER_SHA256, &"0".repeat(64), 1),
            exact.replacen(HELPER_SHA256, &"1".repeat(64), 2),
            exact.replace("system_u:object_r:bin_t:s0", "unlabeled_t"),
            exact.replace("systemd_generic_generator_exec_t", "bin_t"),
            exact.replace("system_u:object_r:lib_t:s0", "unlabeled_t"),
            exact.replacen("st_mode: 33261", "st_mode: 33188", 1),
            exact.replacen("st_uid: 0", "st_uid: 1000", 1),
        ] {
            assert!(!synthetic_verification_valid(&broken, &transaction));
        }
        let duplicate = exact.replace(
            "FORGE_HELPER_DIGEST_END",
            &format!(
                "FORGE_HELPER_DIGEST_END\nFORGE_HELPER_DIGEST_BEGIN\n{HELPER_SHA256}\nFORGE_HELPER_DIGEST_END"
            ),
        );
        assert!(parse_synthetic_verification(&duplicate).is_err());
        assert!(parse_synthetic_verification("parser failure").is_err());
    }
    #[test]
    fn real_aggregate_path_inventory_removes_find_operand_and_is_exact() {
        let arguments = real_verification_arguments();
        let marker = arguments
            .iter()
            .position(|value| *value == "FORGE_PATHS_BEGIN")
            .unwrap();
        assert_eq!(arguments[marker + 2], "echo");
        assert_eq!(
            arguments[marker + 3],
            "usr/lib/forge-preparation-control/binding.json\nusr/lib/systemd/system-generators/forge-preparation-control-generator\nusr/libexec/forge-preparation-control"
        );
        assert_eq!(arguments[marker + 4], ":");
        let expected = [HELPER.to_owned(), GENERATOR.to_owned(), BINDING.to_owned()]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        let exact = "FORGE_PATHS_BEGIN\nusr/lib/forge-preparation-control/binding.json\nusr/lib/systemd/system-generators/forge-preparation-control-generator\nusr/libexec/forge-preparation-control\nFORGE_PATHS_END\n";
        assert_eq!(framed_paths(exact).unwrap(), expected);
        let prior_bug = "FORGE_PATHS_BEGIN\nusr/lib/forge-preparation-control/binding.json\nusr/lib/systemd/system-generators/forge-preparation-control-generator\nusr/libexec/forge-preparation-control /\nFORGE_PATHS_END\n";
        assert_ne!(framed_paths(prior_bug).unwrap(), expected);
    }
    #[test]
    fn missing_or_unexpected_resume_paths_refuse() {
        let expected = expected_synthetic_paths();
        for required in [HELPER, GENERATOR, BINDING] {
            let mut missing = expected.clone();
            missing.remove(required);
            assert_ne!(missing, expected);
        }
        let mut unexpected = expected.clone();
        unexpected.insert("/root/unexpected".to_owned());
        assert_ne!(unexpected, expected);
        assert!(framed_paths("FORGE_PATHS_BEGIN\nusr\nusr\nFORGE_PATHS_END\n").is_err());
        assert!(framed_paths("FORGE_PATHS_BEGIN\n/usr\nFORGE_PATHS_END\n").is_err());
    }
    #[test]
    fn recovery_and_rollback_authority_selects_only_synthetic_owned_paths() {
        let targets = [
            HELPER,
            GENERATOR,
            BINDING,
            "/usr/lib/forge-preparation-control",
        ];
        assert!(targets.iter().all(|path| path.starts_with('/')));
        assert!(!targets.contains(&STAGING));
        assert_ne!(BOOTSTRAP_SYNTHETIC, STAGING);
        assert!(BOOTSTRAP_SYNTHETIC.starts_with(SERVICE_STATE_DIR));
    }
    #[test]
    fn verification_failure_never_reaches_success_publication() {
        let source = include_str!("broker.rs");
        let verification = source
            .find("validate_synthetic_verification(&after, &transaction)?")
            .unwrap();
        let ledger = source.find(".open(BOOTSTRAP_LEDGER)").unwrap();
        assert!(verification < ledger);
        assert_eq!(
            classify_bootstrap_resume(Some("Completed\n"), true),
            Err("ReplayRefused".to_owned())
        );
    }
    #[test]
    fn write_mode_is_confined_to_fixed_typed_bootstrap_targets() {
        let source = include_str!("broker.rs");
        let bootstrap = &source[source.find("fn bootstrap_helper(").unwrap()
            ..source.find("fn validate_bootstrap_request(").unwrap()];
        assert!(bootstrap.contains("BOOTSTRAP_SYNTHETIC"));
        assert!(bootstrap.contains("SyntheticProof"));
        assert!(bootstrap.contains("HELPER_ARTIFACT"));
        assert!(bootstrap.contains("RealPreparation"));
        assert!(bootstrap.contains("REAL_BOOTSTRAP_JOURNAL"));
        assert!(bootstrap.contains("validate_real_verification"));
        for forbidden in [
            "caller_guest_path",
            "caller_host_path",
            "caller_bytes",
            "caller_argv",
        ] {
            assert!(!bootstrap.contains(forbidden));
        }
        let read_only = &source
            [source.find("fn inspect(").unwrap()..source.find("fn validate_request(").unwrap()];
        assert!(!read_only.contains("\"--rw\""));
        assert!(!read_only.contains("BOOTSTRAP_SYNTHETIC"));
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
            vec![
                "ReadWritePaths=/tmp /var/tmp /var/lib/libvirt/images/forge-stage-fedora-workstation-44-1.7-5d87db39.qcow2"
            ]
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
