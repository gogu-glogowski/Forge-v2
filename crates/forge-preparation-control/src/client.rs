use sha2::{Digest, Sha256};
use std::env;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

const SOCKET: &str = "/run/forge-preparation-broker/broker.sock";
const PREPARATION: &str = "5d87db391be74e86bd0c7dca042295c3";
const DOMAIN: &str = "forge-prepare-fedora-workstation-44-1.7-5d87db39";
const UUID: &str = "ae82467d-10dd-4d33-b6ab-52f67e11e795";
const STAGING: &str =
    "/var/lib/libvirt/images/forge-stage-fedora-workstation-44-1.7-5d87db39.qcow2";
const SOURCE_CHECKPOINT: &str = "6c4838512e468a1d3c7bb7e21376928dfc7f6b4e";
const HELPER_SHA256: &str = "bb546fa9bf6efc11bde7687cba792421afc46616287a4fa468eadf3a7d0ad4a2";
const BINDING_SHA256: &str = "64f3a73901f9770661263bae1bdd3a6b1d100d165e6545345d8c45cf07720115";

fn main() -> ExitCode {
    let arguments = env::args().collect::<Vec<_>>();
    let result = match arguments.as_slice().get(1).map(String::as_str) {
        Some("self-test") => self_test(),
        Some("appliance-self-test") => appliance_self_test(),
        Some("direct-self-test") => direct_self_test(),
        Some("inspect") => inspect(),
        Some("bootstrap-synthetic") => bootstrap_synthetic(),
        Some("bootstrap-real") => bootstrap_real(
            forge_images::PreparationBrokerOperation::BootstrapPreparationHelperOffline,
        ),
        Some("complete-real") => bootstrap_real(
            forge_images::PreparationBrokerOperation::CompleteBootstrapRecoveryHostOnly,
        ),
        Some("probe-real-replay") => probe_real_replay(),
        Some("classify-real-recovery") => classify_real_recovery(),
        _ => Err(
            "usage: forge-broker-client self-test|appliance-self-test|direct-self-test|inspect|bootstrap-synthetic|bootstrap-real|classify-real-recovery|complete-real|probe-real-replay"
                .to_owned(),
        ),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("forge-broker-client: {error}");
            ExitCode::from(1)
        }
    }
}

fn classify_real_recovery() -> Result<(), String> {
    let home = env::var_os("HOME").ok_or("HOME unavailable")?;
    let state_path = forge_images::fedora_workstation_preparation_state_path(Path::new(&home));
    let preparation = forge_images::read_fedora_workstation_preparation(&state_path)
        .map_err(|e| e.to_string())?
        .ok_or("preparation absent")?;
    let discovery = preparation
        .execution
        .privileged_offline_discovery
        .as_ref()
        .ok_or("R16 evidence absent")?;
    if preparation.status != forge_images::FedoraWorkstationPreparationStatus::InstalledSystemProven
        || preparation.preparation_id.as_str() != PREPARATION
        || preparation.installer.uuid != UUID
        || preparation.staging.path != Path::new(STAGING)
        || preparation.execution.helper_bootstrap.is_some()
        || preparation.execution.preparation_channel.is_some()
        || discovery.backend != "direct"
    {
        return Err("client-side recovery binding refused".to_owned());
    }
    let transaction = identity(
        "real-bootstrap",
        &[
            SOURCE_CHECKPOINT,
            PREPARATION,
            UUID,
            STAGING,
            "445745",
            &discovery.operation_id,
            &discovery.broker_sha256,
            HELPER_SHA256,
            "generator=same-fixed-artifact",
            "canonical-json-pretty-v1",
            "protocol=1",
            "recipe=V1",
            "forge-preparation-broker/1",
        ],
    );
    let request = forge_images::PreparationBrokerRequest {
        protocol_version: forge_images::FORGE_PREPARATION_BROKER_PROTOCOL_VERSION,
        operation: forge_images::PreparationBrokerOperation::ClassifyBootstrapRecoveryReadOnly,
        preparation_id: preparation.preparation_id,
        expected_domain_name: DOMAIN.to_owned(),
        expected_domain_uuid: UUID.to_owned(),
        bootstrap_target: Some(forge_images::PreparationBootstrapTarget::RealPreparation),
        operation_id: transaction.clone(),
        nonce: identity("bootstrap-nonce", &[&transaction, "RealPreparation", "1"]),
    };
    let mut payload = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
    payload.push(b'\n');
    match parse_response(&exchange(&payload)?)? {
        forge_images::PreparationBrokerResponse::RecoveryClassificationSuccess { result }
            if result.bootstrap_transaction_id == transaction
                && result.operation_id == transaction
                && result.read_only
                && result.clean_close
                && result.host_metadata_unchanged =>
        {
            println!(
                "BROKER_REAL_RECOVERY_CLASSIFICATION={}",
                serde_json::to_string(&result).map_err(|e| e.to_string())?
            );
            Ok(())
        }
        forge_images::PreparationBrokerResponse::Refusal { error_code }
        | forge_images::PreparationBrokerResponse::InternalError { error_code } => Err(format!(
            "broker recovery classification failure: {error_code}"
        )),
        _ => Err("unexpected recovery classification response".to_owned()),
    }
}

fn probe_real_replay() -> Result<(), String> {
    let home = env::var_os("HOME").ok_or("HOME unavailable")?;
    let state_path = forge_images::fedora_workstation_preparation_state_path(Path::new(&home));
    let preparation = forge_images::read_fedora_workstation_preparation(&state_path)
        .map_err(|e| e.to_string())?
        .ok_or("preparation absent")?;
    let discovery = preparation
        .execution
        .privileged_offline_discovery
        .as_ref()
        .ok_or("R16 evidence absent")?;
    if preparation.preparation_id.as_str() != PREPARATION
        || preparation.installer.uuid != UUID
        || preparation.staging.path != Path::new(STAGING)
        || preparation.execution.helper_bootstrap.is_none()
        || preparation.execution.preparation_channel.is_some()
        || discovery.backend != "direct"
    {
        return Err("client-side replay binding refused".to_owned());
    }
    let transaction = identity(
        "real-bootstrap",
        &[
            SOURCE_CHECKPOINT,
            PREPARATION,
            UUID,
            STAGING,
            "445745",
            &discovery.operation_id,
            &discovery.broker_sha256,
            HELPER_SHA256,
            "generator=same-fixed-artifact",
            "canonical-json-pretty-v1",
            "protocol=1",
            "recipe=V1",
            "forge-preparation-broker/1",
        ],
    );
    let request = forge_images::PreparationBrokerRequest {
        protocol_version: forge_images::FORGE_PREPARATION_BROKER_PROTOCOL_VERSION,
        operation: forge_images::PreparationBrokerOperation::CompleteBootstrapRecoveryHostOnly,
        preparation_id: preparation.preparation_id,
        expected_domain_name: DOMAIN.to_owned(),
        expected_domain_uuid: UUID.to_owned(),
        bootstrap_target: Some(forge_images::PreparationBootstrapTarget::RealPreparation),
        operation_id: transaction.clone(),
        nonce: identity("bootstrap-nonce", &[&transaction, "RealPreparation", "1"]),
    };
    let mut payload = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
    payload.push(b'\n');
    match parse_response(&exchange(&payload)?)? {
        forge_images::PreparationBrokerResponse::Refusal { error_code }
            if error_code == "ReplayRefused" =>
        {
            println!("BROKER_REAL_COMPLETION_REPLAY=ReplayRefused");
            Ok(())
        }
        forge_images::PreparationBrokerResponse::Refusal { error_code }
        | forge_images::PreparationBrokerResponse::InternalError { error_code } => {
            Err(format!("unexpected replay refusal: {error_code}"))
        }
        _ => Err("completed transaction replay was not refused".to_owned()),
    }
}

#[allow(clippy::too_many_lines)]
fn bootstrap_real(operation: forge_images::PreparationBrokerOperation) -> Result<(), String> {
    let home = env::var_os("HOME").ok_or("HOME unavailable")?;
    let state_path = forge_images::fedora_workstation_preparation_state_path(Path::new(&home));
    let mut preparation = forge_images::read_fedora_workstation_preparation(&state_path)
        .map_err(|e| e.to_string())?
        .ok_or("preparation absent")?;
    let discovery = preparation
        .execution
        .privileged_offline_discovery
        .as_ref()
        .ok_or("R16 evidence absent")?;
    if preparation.status != forge_images::FedoraWorkstationPreparationStatus::InstalledSystemProven
        || preparation.preparation_id.as_str() != PREPARATION
        || preparation.installer.uuid != UUID
        || preparation.staging.path != Path::new(STAGING)
        || preparation.execution.helper_bootstrap.is_some()
        || preparation.execution.preparation_channel.is_some()
        || discovery.backend != "direct"
    {
        return Err("client-side real bootstrap binding refused".to_owned());
    }
    let transaction = identity(
        "real-bootstrap",
        &[
            SOURCE_CHECKPOINT,
            PREPARATION,
            UUID,
            STAGING,
            "445745",
            &discovery.operation_id,
            &discovery.broker_sha256,
            HELPER_SHA256,
            "generator=same-fixed-artifact",
            "canonical-json-pretty-v1",
            "protocol=1",
            "recipe=V1",
            "forge-preparation-broker/1",
        ],
    );
    let nonce = identity("bootstrap-nonce", &[&transaction, "RealPreparation", "1"]);
    let request = forge_images::PreparationBrokerRequest {
        protocol_version: forge_images::FORGE_PREPARATION_BROKER_PROTOCOL_VERSION,
        operation,
        preparation_id: preparation.preparation_id.clone(),
        expected_domain_name: DOMAIN.to_owned(),
        expected_domain_uuid: UUID.to_owned(),
        bootstrap_target: Some(forge_images::PreparationBootstrapTarget::RealPreparation),
        operation_id: transaction.clone(),
        nonce,
    };
    let mut payload = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
    payload.push(b'\n');
    let result = match parse_response(&exchange(&payload)?)? {
        forge_images::PreparationBrokerResponse::BootstrapSuccess { result } => *result,
        forge_images::PreparationBrokerResponse::Refusal { error_code }
        | forge_images::PreparationBrokerResponse::InternalError { error_code } => {
            return Err(format!("broker bootstrap failure: {error_code}"));
        }
        _ => return Err("unexpected bootstrap response".to_owned()),
    };
    if result.target != forge_images::PreparationBootstrapTarget::RealPreparation
        || result.operation != operation
        || result.bootstrap_transaction_id != transaction
        || result.operation_id != transaction
        || !result.clean_close
        || result.unexpected_paths_modified
        || result.backend != "direct"
        || result.helper_sha256 != HELPER_SHA256
        || result.generator_sha256 != HELPER_SHA256
        || result.binding_sha256 != BINDING_SHA256
        || result.helper_bytes != 784_624
        || result.generator_bytes != 784_624
        || result.binding_bytes != 975
        || result.guest_paths
            != [
                forge_images::FORGE_PREPARATION_HELPER_PATH,
                forge_images::FORGE_PREPARATION_GENERATOR_PATH,
                forge_images::FORGE_PREPARATION_BINDING_PATH,
            ]
        || result.guest_modes != ["0:0:0755", "0:0:0755", "0:0:0600"]
        || result.guest_selinux_labels != ["bin_t", "systemd_generic_generator_exec_t", "lib_t"]
    {
        return Err("real bootstrap proof refused".to_owned());
    }
    preparation.execution.helper_bootstrap = Some(forge_images::PreparationHelperBootstrap {
        preparation_id: preparation.preparation_id.clone(),
        domain_uuid: UUID.to_owned(),
        staging_path: preparation.staging.path.clone(),
        helper_sha256: result.helper_sha256.clone(),
        helper_bytes: result.helper_bytes,
        generator_sha256: result.generator_sha256.clone(),
        generator_bytes: result.generator_bytes,
        binding_sha256: result.binding_sha256.clone(),
        binding_bytes: result.binding_bytes,
        helper_protocol_version: result.helper_protocol_version,
        bootstrap_transaction_id: transaction,
        guest_installation_path: forge_images::FORGE_PREPARATION_HELPER_PATH.into(),
        persistent_activation_path: forge_images::FORGE_PREPARATION_GENERATOR_PATH.into(),
        temporary_activation_path: "/run/systemd/system/forge-preparation-control.service".into(),
        channel_name: forge_images::FORGE_PREPARATION_CHANNEL.to_owned(),
        expected_state: forge_images::FedoraWorkstationPreparationStatus::InstalledSystemProven,
        cleanup_inventory: forge_images::guest_channel_cleanup_inventory(),
        guest_paths: result.guest_paths.iter().map(Into::into).collect(),
        guest_modes: result.guest_modes.clone(),
        guest_selinux_labels: result.guest_selinux_labels.clone(),
        structured_verification_proven: true,
        clean_close: true,
        unexpected_paths_modified: false,
    });
    forge_images::update_fedora_workstation_preparation(&state_path, &preparation)
        .map_err(|e| e.to_string())?;
    println!(
        "BROKER_BOOTSTRAP_REAL_PROOF={}",
        serde_json::to_string(&result).map_err(|e| e.to_string())?
    );
    Ok(())
}

fn bootstrap_synthetic() -> Result<(), String> {
    let home = env::var_os("HOME").ok_or("HOME unavailable")?;
    let state_path = forge_images::fedora_workstation_preparation_state_path(Path::new(&home));
    let preparation = forge_images::read_fedora_workstation_preparation(&state_path)
        .map_err(|e| e.to_string())?
        .ok_or("preparation absent")?;
    let transaction = identity(
        "bootstrap",
        &[SOURCE_CHECKPOINT, PREPARATION, UUID, STAGING, HELPER_SHA256],
    );
    let nonce = identity("bootstrap-nonce", &[&transaction, "SyntheticProof", "1"]);
    let request = forge_images::PreparationBrokerRequest {
        protocol_version: forge_images::FORGE_PREPARATION_BROKER_PROTOCOL_VERSION,
        operation: forge_images::PreparationBrokerOperation::BootstrapPreparationHelperOffline,
        preparation_id: preparation.preparation_id,
        expected_domain_name: DOMAIN.to_owned(),
        expected_domain_uuid: UUID.to_owned(),
        bootstrap_target: Some(forge_images::PreparationBootstrapTarget::SyntheticProof),
        operation_id: transaction,
        nonce,
    };
    let mut payload = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
    payload.push(b'\n');
    match parse_response(&exchange(&payload)?)? {
        forge_images::PreparationBrokerResponse::BootstrapSuccess { result } => {
            println!(
                "BROKER_BOOTSTRAP_SYNTHETIC_PROOF={}",
                serde_json::to_string(&result).map_err(|e| e.to_string())?
            );
            Ok(())
        }
        forge_images::PreparationBrokerResponse::Refusal { error_code }
        | forge_images::PreparationBrokerResponse::InternalError { error_code } => {
            Err(format!("broker bootstrap failure: {error_code}"))
        }
        _ => Err("unexpected bootstrap response".to_owned()),
    }
}

fn direct_self_test() -> Result<(), String> {
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_nanos()
        .to_string();
    let request = forge_images::PreparationBrokerDiagnosticRequest {
        protocol_version: forge_images::FORGE_PREPARATION_BROKER_PROTOCOL_VERSION,
        operation:
            forge_images::PreparationBrokerDiagnosticOperation::SelfTestDirectBackendSynthetic,
        operation_id: identity("direct-self-test", &[&seed]),
        nonce: identity("direct-test-nonce", &[&seed]),
    };
    let mut payload = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
    payload.push(b'\n');
    match parse_response(&exchange(&payload)?)? {
        forge_images::PreparationBrokerResponse::SyntheticDirectSelfTestSuccess { result }
            if result.protocol_version == request.protocol_version
                && result.operation == request.operation
                && result.operation_id == request.operation_id
                && result.nonce == request.nonce
                && result.backend == "direct"
                && result.disk_count == 1
                && result.metadata_unchanged
                && result.sha256_before == result.sha256_after =>
        {
            println!(
                "BROKER_DIRECT_SYNTHETIC_SELF_TEST={}",
                serde_json::to_string(&result).map_err(|e| e.to_string())?
            );
            Ok(())
        }
        forge_images::PreparationBrokerResponse::Refusal { error_code }
        | forge_images::PreparationBrokerResponse::InternalError { error_code } => {
            Err(format!("broker direct self-test failure: {error_code}"))
        }
        _ => Err("unexpected direct self-test response".to_owned()),
    }
}

fn self_test() -> Result<(), String> {
    let response = exchange(b"not-json\n")?;
    match parse_response(&response)? {
        forge_images::PreparationBrokerResponse::Refusal { error_code }
            if error_code == "MalformedProtocol" => {}
        _ => return Err("malformed protocol was not refused".to_owned()),
    }
    println!("BROKER_SELF_TEST=malformed-request-refused;peer-authorized;unix-ipc");
    Ok(())
}

fn appliance_self_test() -> Result<(), String> {
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_nanos()
        .to_string();
    let request = forge_images::PreparationBrokerDiagnosticRequest {
        protocol_version: forge_images::FORGE_PREPARATION_BROKER_PROTOCOL_VERSION,
        operation: forge_images::PreparationBrokerDiagnosticOperation::SelfTestLibguestfsAppliance,
        operation_id: identity("appliance-self-test", &[&seed]),
        nonce: identity("diagnostic-nonce", &[&seed]),
    };
    let mut payload = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
    payload.push(b'\n');
    match parse_response(&exchange(&payload)?)? {
        forge_images::PreparationBrokerResponse::ApplianceSelfTestSuccess { result }
            if result.protocol_version == request.protocol_version
                && result.operation == request.operation
                && result.operation_id == request.operation_id
                && result.nonce == request.nonce
                && result.appliance_initialized
                && result.disk_count == 0 =>
        {
            println!(
                "BROKER_APPLIANCE_SELF_TEST={}",
                serde_json::to_string(&result).map_err(|e| e.to_string())?
            );
            Ok(())
        }
        forge_images::PreparationBrokerResponse::Refusal { error_code } => {
            Err(format!("broker refusal: {error_code}"))
        }
        forge_images::PreparationBrokerResponse::InternalError { error_code } => {
            Err(format!("broker internal error: {error_code}"))
        }
        _ => Err("unexpected appliance self-test response".to_owned()),
    }
}

fn inspect() -> Result<(), String> {
    let home = env::var_os("HOME").ok_or("HOME unavailable")?;
    let state_path = forge_images::fedora_workstation_preparation_state_path(Path::new(&home));
    let mut preparation = forge_images::read_fedora_workstation_preparation(&state_path)
        .map_err(|e| e.to_string())?
        .ok_or("preparation absent")?;
    if preparation.preparation_id.as_str() != PREPARATION
        || preparation.status
            != forge_images::FedoraWorkstationPreparationStatus::InstalledSystemProven
        || preparation.installer.name != DOMAIN
        || preparation.installer.uuid != UUID
        || preparation.execution.privileged_offline_discovery.is_some()
    {
        return Err("client-side durable binding refused".to_owned());
    }
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_nanos()
        .to_string();
    let operation_id = identity("broker-inspect", &[PREPARATION, UUID, &seed]);
    let nonce = identity("nonce", &[&operation_id, PREPARATION, &seed]);
    let request = forge_images::PreparationBrokerRequest {
        protocol_version: forge_images::FORGE_PREPARATION_BROKER_PROTOCOL_VERSION,
        operation: forge_images::PreparationBrokerOperation::InspectFedoraWorkstationPreparation,
        preparation_id: preparation.preparation_id.clone(),
        expected_domain_name: DOMAIN.to_owned(),
        expected_domain_uuid: UUID.to_owned(),
        bootstrap_target: None,
        operation_id,
        nonce,
    };
    let mut payload = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
    payload.push(b'\n');
    let response = exchange(&payload)?;
    let result = match parse_response(&response)? {
        forge_images::PreparationBrokerResponse::Success { result } => *result,
        forge_images::PreparationBrokerResponse::Refusal { error_code } => {
            return Err(format!("broker refusal: {error_code}"));
        }
        forge_images::PreparationBrokerResponse::InternalError { error_code } => {
            return Err(format!("broker internal error: {error_code}"));
        }
        forge_images::PreparationBrokerResponse::ApplianceSelfTestSuccess { .. } => {
            return Err("unexpected appliance self-test response".to_owned());
        }
        forge_images::PreparationBrokerResponse::SyntheticDirectSelfTestSuccess { .. } => {
            return Err("unexpected synthetic direct response".to_owned());
        }
        forge_images::PreparationBrokerResponse::IdentityRefusal {
            error_code,
            diagnostics,
        } => {
            return Err(format!(
                "broker identity refusal: {error_code}: {}",
                serde_json::to_string(&diagnostics).map_err(|e| e.to_string())?
            ));
        }
        forge_images::PreparationBrokerResponse::BootstrapSuccess { .. } => {
            return Err("unexpected bootstrap response".to_owned());
        }
        forge_images::PreparationBrokerResponse::RecoveryClassificationSuccess { .. } => {
            return Err("unexpected recovery classification response".to_owned());
        }
    };
    let evidence =
        forge_images::prove_privileged_offline_fedora_discovery(&preparation, &request, result)
            .map_err(|e| e.to_string())?;
    println!(
        "BROKER_DISCOVERY_EVIDENCE={}",
        serde_json::to_string(&evidence).map_err(|e| e.to_string())?
    );
    preparation.execution.privileged_offline_discovery = Some(evidence);
    forge_images::update_fedora_workstation_preparation(&state_path, &preparation)
        .map_err(|e| e.to_string())?;
    println!("BROKER_DISCOVERY_PUBLISHED=true");
    Ok(())
}

fn parse_response(response: &[u8]) -> Result<forge_images::PreparationBrokerResponse, String> {
    serde_json::from_slice(response).map_err(|error| format!("malformed broker envelope: {error}"))
}

fn exchange(payload: &[u8]) -> Result<Vec<u8>, String> {
    let mut stream = UnixStream::connect(SOCKET).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(150)))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    stream.write_all(payload).map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;
    let mut response = Vec::new();
    BufReader::new(stream)
        .take(1024 * 1024)
        .read_until(b'\n', &mut response)
        .map_err(|e| e.to_string())?;
    if response.is_empty() || response.len() >= 1024 * 1024 {
        return Err("bounded broker response refused".to_owned());
    }
    Ok(response)
}

fn identity(kind: &str, values: &[&str]) -> String {
    let mut hash = Sha256::new();
    hash.update(kind);
    for value in values {
        hash.update([0]);
        hash.update(value);
    }
    format!("{kind}-{:x}", hash.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn result() -> forge_images::PreparationBrokerResult {
        forge_images::PreparationBrokerResult {
            protocol_version: 1,
            operation:
                forge_images::PreparationBrokerOperation::InspectFedoraWorkstationPreparation,
            operation_id: "operation-00000001".to_owned(),
            nonce: "n".repeat(32),
            preparation_id: forge_images::FedoraWorkstationPreparationId::new(
                PREPARATION.to_owned(),
            )
            .unwrap(),
            domain_uuid: UUID.to_owned(),
            staging_volume_name: "forge-stage-fedora-workstation-44-1.7-5d87db39.qcow2".to_owned(),
            staging_volume_key:
                "/var/lib/libvirt/images/forge-stage-fedora-workstation-44-1.7-5d87db39.qcow2"
                    .to_owned(),
            staging_path: Path::new(
                "/var/lib/libvirt/images/forge-stage-fedora-workstation-44-1.7-5d87db39.qcow2",
            )
            .to_path_buf(),
            broker_version: "forge-preparation-broker/1".to_owned(),
            broker_sha256: "a".repeat(64),
            libguestfs_version: "guestfish 1.60.1".to_owned(),
            backend: "direct".to_owned(),
            os_root: "/dev/mapper/root".to_owned(),
            fedora_product: "Fedora Workstation".to_owned(),
            fedora_release: "44".to_owned(),
            architecture: "x86_64".to_owned(),
            filesystems: vec!["/dev/mapper/root: ext4".to_owned()],
            guest_selinux_config: "SELINUX=enforcing".to_owned(),
            workstation_evidence: "VARIANT_ID=workstation".to_owned(),
            filesystem_layout: vec!["usr_dir=true".to_owned()],
            minimal_observations: vec!["machine_id_file=true".to_owned()],
            clean_close: true,
            host_metadata_unchanged: true,
            elapsed_millis: 1,
            completion: forge_images::PreparationBrokerCompletion::Completed,
            error_code: None,
        }
    }
    #[test]
    fn identities_are_deterministic_and_bound() {
        assert_eq!(identity("x", &["a"]), identity("x", &["a"]));
        assert_ne!(identity("x", &["a"]), identity("x", &["b"]));
    }
    #[test]
    fn typed_response_envelopes_are_distinct_and_malformed_fails_closed() {
        let envelopes = [
            forge_images::PreparationBrokerResponse::Success {
                result: Box::new(result()),
            },
            forge_images::PreparationBrokerResponse::Refusal {
                error_code: "RequestRefused".to_owned(),
            },
            forge_images::PreparationBrokerResponse::InternalError {
                error_code: "io failure".to_owned(),
            },
        ];
        for envelope in envelopes {
            let bytes = serde_json::to_vec(&envelope).unwrap();
            assert_eq!(parse_response(&bytes).unwrap(), envelope);
        }
        assert!(parse_response(br#"{"kind":"unknown"}"#).is_err());
        assert!(parse_response(br#"{"kind":"refusal","result":{}}"#).is_err());
    }
}
