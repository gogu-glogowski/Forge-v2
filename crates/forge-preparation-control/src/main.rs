use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::{Command, ExitCode};

const PROTOCOL_VERSION: u32 = 1;
const CHANNEL: &str = "/dev/virtio-ports/org.majorforge.preparation.0";
const BINDING: &str = "/usr/lib/forge-preparation-control/binding.json";
const RUN_BINDING: &str = "/run/forge-preparation-control/binding.json";
const UNIT: &str = "/run/systemd/system/forge-preparation-control.service";
const GENERATOR_NAME: &str = "forge-preparation-control-generator";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    protocol_version: u32,
    preparation_id: String,
    domain_name: String,
    domain_uuid: String,
    staging_identity: StagingIdentity,
    normalization_recipe: String,
    expected_state: String,
    bootstrap_transaction_id: String,
    helper_sha256: String,
    generator_sha256: String,
    channel_name: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StagingIdentity {
    path: String,
    volume_name: String,
    volume_key: String,
    inode: u64,
    capacity_bytes: u64,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Request {
    protocol_version: u32,
    binding: RequestBinding,
    operation: String,
    operation_id: String,
    nonce: String,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RequestBinding {
    preparation_id: String,
    domain_name: String,
    domain_uuid: String,
    staging_path: String,
    recipe: String,
    expected_state: String,
}

#[derive(Debug, Serialize)]
struct Handshake<'a> {
    kind: &'static str,
    protocol_version: u32,
    preparation_id: &'a str,
    domain_uuid: &'a str,
    bootstrap_transaction_id: &'a str,
    helper_sha256: &'a str,
    recipe: &'a str,
    channel_name: &'a str,
}

#[derive(Debug, Serialize)]
struct ResultEnvelope<'a> {
    protocol_version: u32,
    binding: ResultBinding<'a>,
    operation: &'static str,
    operation_id: &'a str,
    nonce: &'a str,
    completion: &'static str,
    inventory: Option<&'a Inventory>,
    error_code: Option<&'static str>,
    guest_sequence: u64,
}

#[derive(Debug, Serialize, Clone)]
struct ResultBinding<'a> {
    preparation_id: &'a str,
    domain_name: &'a str,
    domain_uuid: &'a str,
    staging_path: &'a str,
    recipe: &'static str,
    expected_state: &'static str,
}

#[derive(Debug, Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct Inventory {
    fedora_product: String,
    fedora_release: String,
    architecture: String,
    kernel: String,
    hostname: String,
    machine_id_present: bool,
    dbus_machine_id_relationship: String,
    normal_users: Vec<String>,
    normal_user_count: usize,
    root_locked: bool,
    accounts_service_entries: Vec<String>,
    gnome_initial_setup_completed: bool,
    network_profile_summaries: Vec<String>,
    preparation_mac_referenced: bool,
    network_static_addresses: Vec<String>,
    dhcp_identity_residue: bool,
    network_secrets_present: bool,
    openssh_server_installed: bool,
    openssh_server_enabled: bool,
    ssh_host_keys_present: bool,
    selinux_enabled: bool,
    selinux_enforcing: bool,
    relabel_pending: bool,
    package_transactions_clean: bool,
    enabled_fedora_repositories: Vec<String>,
    relevant_packages: Vec<String>,
    spice_vdagent_installed: bool,
    spice_vdagent_components: Vec<String>,
    qemu_guest_agent_installed: bool,
    display_stack: Vec<String>,
    anaconda_residue: Vec<String>,
    crash_temp_history_residue: Vec<String>,
    preparation_identity_residue: Vec<String>,
}

fn main() -> ExitCode {
    let executable = env::args_os().next().unwrap_or_default();
    if Path::new(&executable).file_name().and_then(|v| v.to_str()) == Some(GENERATOR_NAME) {
        return generator();
    }
    match serve() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("forge-preparation-control: {error}");
            ExitCode::from(1)
        }
    }
}

fn generator() -> ExitCode {
    let result = (|| -> Result<(), String> {
        let binding = fs::read(BINDING).map_err(|e| e.to_string())?;
        fs::create_dir_all("/run/forge-preparation-control").map_err(|e| e.to_string())?;
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(RUN_BINDING)
            .map_err(|e| e.to_string())?;
        output.write_all(&binding).map_err(|e| e.to_string())?;
        fs::set_permissions(RUN_BINDING, fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
        fs::create_dir_all("/run/systemd/system").map_err(|e| e.to_string())?;
        fs::write(UNIT, "[Unit]\nDescription=Forge preparation-only control\nConditionPathExists=/dev/virtio-ports/org.majorforge.preparation.0\nAfter=systemd-udev-settle.service\n\n[Service]\nType=oneshot\nExecStart=/usr/libexec/forge-preparation-control\nStandardInput=null\nStandardOutput=journal\nStandardError=journal\n\n[Install]\nWantedBy=multi-user.target\n").map_err(|e| e.to_string())?;
        fs::create_dir_all("/run/systemd/generator/multi-user.target.wants")
            .map_err(|e| e.to_string())?;
        std::os::unix::fs::symlink(
            UNIT,
            "/run/systemd/generator/multi-user.target.wants/forge-preparation-control.service",
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    })();
    result.map_or_else(
        |e| {
            eprintln!("{e}");
            ExitCode::from(1)
        },
        |()| ExitCode::SUCCESS,
    )
}

fn serve() -> Result<(), String> {
    let binding = parse_binding_bytes(&fs::read(RUN_BINDING).map_err(|e| e.to_string())?)?;
    validate_binding(&binding)?;
    let actual_digest = executable_digest()?;
    if actual_digest != binding.helper_sha256 {
        return Err("helper digest mismatch".to_owned());
    }
    let mut channel = OpenOptions::new()
        .read(true)
        .write(true)
        .open(CHANNEL)
        .map_err(|e| e.to_string())?;
    write_json(
        &mut channel,
        &Handshake {
            kind: "Handshake",
            protocol_version: PROTOCOL_VERSION,
            preparation_id: &binding.preparation_id,
            domain_uuid: &binding.domain_uuid,
            bootstrap_transaction_id: &binding.bootstrap_transaction_id,
            helper_sha256: &actual_digest,
            recipe: &binding.normalization_recipe,
            channel_name: &binding.channel_name,
        },
    )?;
    let mut reader = BufReader::new(channel.try_clone().map_err(|e| e.to_string())?);
    let line = read_bounded_request(&mut reader)?;
    let request: Request = serde_json::from_str(&line).map_err(|e| e.to_string())?;
    validate_request(&binding, &request)?;
    let inventory = collect_inventory()?;
    write_json(
        &mut channel,
        &ResultEnvelope {
            protocol_version: PROTOCOL_VERSION,
            binding: ResultBinding {
                preparation_id: &binding.preparation_id,
                domain_name: &binding.domain_name,
                domain_uuid: &binding.domain_uuid,
                staging_path: &binding.staging_identity.path,
                recipe: "V1",
                expected_state: "InstalledSystemProven",
            },
            operation: "ReadOnlyGuestInventoryProbe",
            operation_id: &request.operation_id,
            nonce: &request.nonce,
            completion: "Completed",
            inventory: Some(&inventory),
            error_code: None,
            guest_sequence: 1,
        },
    )?;
    let replay_line = read_bounded_request(&mut reader)?;
    let replay: Request = serde_json::from_str(&replay_line).map_err(|e| e.to_string())?;
    if replay != request {
        return Err("second request was not an exact replay".to_owned());
    }
    write_json(
        &mut channel,
        &ResultEnvelope {
            protocol_version: PROTOCOL_VERSION,
            binding: ResultBinding {
                preparation_id: &binding.preparation_id,
                domain_name: &binding.domain_name,
                domain_uuid: &binding.domain_uuid,
                staging_path: &binding.staging_identity.path,
                recipe: "V1",
                expected_state: "InstalledSystemProven",
            },
            operation: "ReadOnlyGuestInventoryProbe",
            operation_id: &request.operation_id,
            nonce: &request.nonce,
            completion: "Failed",
            inventory: None,
            error_code: Some("ReplayRefused"),
            guest_sequence: 1,
        },
    )
}

fn parse_binding_bytes(bytes: &[u8]) -> Result<Binding, String> {
    serde_json::from_slice(bytes).map_err(|e| format!("binding JSON refused: {e}"))
}

fn validate_binding(binding: &Binding) -> Result<(), String> {
    if binding.protocol_version != PROTOCOL_VERSION
        || binding.preparation_id != "5d87db391be74e86bd0c7dca042295c3"
        || binding.domain_name != "forge-prepare-fedora-workstation-44-1.7-5d87db39"
        || binding.domain_uuid != "ae82467d-10dd-4d33-b6ab-52f67e11e795"
        || binding.staging_identity.path
            != "/var/lib/libvirt/images/forge-stage-fedora-workstation-44-1.7-5d87db39.qcow2"
        || binding.staging_identity.volume_name
            != "forge-stage-fedora-workstation-44-1.7-5d87db39.qcow2"
        || binding.staging_identity.volume_key != binding.staging_identity.path
        || binding.staging_identity.inode != 445_745
        || binding.staging_identity.capacity_bytes != 80 * 1024 * 1024 * 1024
        || binding.normalization_recipe != "V1"
        || binding.expected_state != "InstalledSystemProven"
        || binding.generator_sha256 != binding.helper_sha256
        || binding.channel_name != "org.majorforge.preparation.0"
    {
        return Err("binding refused".to_owned());
    }
    Ok(())
}

fn read_bounded_request(reader: &mut BufReader<File>) -> Result<String, String> {
    let mut line = String::new();
    reader
        .take(64 * 1024)
        .read_line(&mut line)
        .map_err(|e| e.to_string())?;
    if line.is_empty() || line.len() >= 64 * 1024 || !line.ends_with('\n') {
        return Err("bounded request frame refused".to_owned());
    }
    Ok(line)
}

fn validate_request(binding: &Binding, request: &Request) -> Result<(), String> {
    if request.protocol_version != PROTOCOL_VERSION
        || request.operation != "ReadOnlyGuestInventoryProbe"
        || request.operation_id.len() < 16
        || request.nonce.len() < 32
        || request.binding.preparation_id != binding.preparation_id
        || request.binding.domain_name != binding.domain_name
        || request.binding.domain_uuid != binding.domain_uuid
        || request.binding.staging_path != binding.staging_identity.path
        || request.binding.recipe != "V1"
        || request.binding.expected_state != "InstalledSystemProven"
    {
        return Err("request refused".to_owned());
    }
    Ok(())
}

fn executable_digest() -> Result<String, String> {
    let bytes = fs::read("/usr/libexec/forge-preparation-control").map_err(|e| e.to_string())?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn write_json<T: Serialize>(output: &mut File, value: &T) -> Result<(), String> {
    serde_json::to_writer(&mut *output, value).map_err(|e| e.to_string())?;
    output.write_all(b"\n").map_err(|e| e.to_string())?;
    output.flush().map_err(|e| e.to_string())
}

fn read(path: &str) -> String {
    fs::read_to_string(path)
        .unwrap_or_default()
        .trim()
        .to_owned()
}
fn exists(path: &str) -> bool {
    Path::new(path).exists()
}
fn entries(path: &str) -> Vec<String> {
    let mut values: Vec<String> = fs::read_dir(path)
        .map(|it| {
            it.filter_map(Result::ok)
                .filter_map(|e| e.file_name().into_string().ok())
                .collect()
        })
        .unwrap_or_default();
    values.sort();
    values
}
fn output(program: &str, arguments: &[&str]) -> String {
    Command::new(program)
        .args(arguments)
        .output()
        .ok()
        .filter(|v| v.status.success())
        .map(|v| String::from_utf8_lossy(&v.stdout).trim().to_owned())
        .unwrap_or_default()
}
fn package(name: &str) -> Option<String> {
    let v = output("/usr/bin/rpm", &["-q", name]);
    (!v.is_empty()).then_some(v)
}

#[allow(clippy::too_many_lines)]
fn collect_inventory() -> Result<Inventory, String> {
    let os = read("/etc/os-release");
    if !os.contains("ID=fedora") || !os.contains("VERSION_ID=44") {
        return Err("Fedora 44 identity refused".to_owned());
    }
    let passwd = read("/etc/passwd");
    let mut users = passwd
        .lines()
        .filter_map(|line| {
            let p: Vec<_> = line.split(':').collect();
            (p.len() > 6
                && p[2]
                    .parse::<u32>()
                    .is_ok_and(|u| (1000..65534).contains(&u)))
            .then(|| p[0].to_owned())
        })
        .collect::<Vec<_>>();
    users.sort();
    let profiles = entries("/etc/NetworkManager/system-connections");
    let profile_text = profiles
        .iter()
        .map(|p| read(&format!("/etc/NetworkManager/system-connections/{p}")))
        .collect::<Vec<_>>()
        .join("\n");
    let mut relevant = ["spice-vdagent", "qemu-guest-agent", "openssh-server"]
        .iter()
        .filter_map(|p| package(p))
        .collect::<Vec<_>>();
    relevant.sort();
    let enforcing = read("/sys/fs/selinux/enforce") == "1";
    Ok(Inventory {
        fedora_product: "Fedora Workstation".to_owned(),
        fedora_release: "44".to_owned(),
        architecture: output("/usr/bin/uname", &["-m"]),
        kernel: output("/usr/bin/uname", &["-r"]),
        hostname: read("/etc/hostname"),
        machine_id_present: !read("/etc/machine-id").is_empty(),
        dbus_machine_id_relationship: fs::read_link("/var/lib/dbus/machine-id").map_or_else(
            |_| {
                if exists("/var/lib/dbus/machine-id") {
                    "regular-file".to_owned()
                } else {
                    "absent".to_owned()
                }
            },
            |p| p.display().to_string(),
        ),
        normal_user_count: users.len(),
        normal_users: users,
        root_locked: read("/etc/shadow")
            .lines()
            .find(|l| l.starts_with("root:"))
            .is_some_and(|l| {
                l.split(':')
                    .nth(1)
                    .is_some_and(|p| p.starts_with('!') || p == "*")
            }),
        accounts_service_entries: entries("/var/lib/AccountsService/users"),
        gnome_initial_setup_completed: exists("/var/lib/gnome-initial-setup-done"),
        preparation_mac_referenced: profile_text
            .to_ascii_lowercase()
            .contains("52:54:00:28:d0:55"),
        network_static_addresses: profile_text
            .lines()
            .filter(|l| l.starts_with("address") || l.starts_with("addresses"))
            .map(str::to_owned)
            .collect(),
        dhcp_identity_residue: profile_text.contains("dhcp-client-id")
            || profile_text.contains("dhcp-duid")
            || !entries("/var/lib/NetworkManager").is_empty(),
        network_secrets_present: profile_text
            .lines()
            .any(|l| l.starts_with("psk=") || l.starts_with("password=")),
        network_profile_summaries: profiles,
        openssh_server_installed: package("openssh-server").is_some(),
        openssh_server_enabled: output("/usr/bin/systemctl", &["is-enabled", "sshd.service"])
            == "enabled",
        ssh_host_keys_present: fs::read_dir("/etc/ssh").is_ok_and(|it| {
            it.filter_map(Result::ok).any(|e| {
                e.file_name().to_string_lossy().starts_with("ssh_host_")
                    && e.file_name().to_string_lossy().ends_with("_key")
            })
        }),
        selinux_enabled: exists("/sys/fs/selinux/enforce"),
        selinux_enforcing: enforcing,
        relabel_pending: exists("/.autorelabel"),
        package_transactions_clean: !exists("/var/lib/rpm/.rpm.lock")
            && !exists("/var/lib/dnf/rpmdb_lock.pid"),
        enabled_fedora_repositories: output("/usr/bin/dnf", &["-q", "repolist", "--enabled"])
            .lines()
            .filter(|l| l.contains("fedora") || l.contains("updates"))
            .map(str::to_owned)
            .collect(),
        relevant_packages: relevant,
        spice_vdagent_installed: package("spice-vdagent").is_some(),
        spice_vdagent_components: ["spice-vdagentd.service", "spice-vdagentd.socket"]
            .into_iter()
            .filter(|u| !output("/usr/bin/systemctl", &["is-enabled", u]).is_empty())
            .map(str::to_owned)
            .collect(),
        qemu_guest_agent_installed: package("qemu-guest-agent").is_some(),
        display_stack: ["gdm.service", "graphical.target"]
            .into_iter()
            .filter(|u| !output("/usr/bin/systemctl", &["is-enabled", u]).is_empty())
            .map(str::to_owned)
            .collect(),
        anaconda_residue: ["/root/anaconda-ks.cfg", "/var/log/anaconda"]
            .into_iter()
            .filter(|p| exists(p))
            .map(str::to_owned)
            .collect(),
        crash_temp_history_residue: ["/var/crash", "/root/.bash_history"]
            .into_iter()
            .filter(|p| exists(p))
            .map(str::to_owned)
            .collect(),
        preparation_identity_residue: vec![
            BINDING.to_owned(),
            RUN_BINDING.to_owned(),
            UNIT.to_owned(),
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> Binding {
        Binding {
            protocol_version: 1,
            preparation_id: "5d87db391be74e86bd0c7dca042295c3".to_owned(),
            domain_name: "forge-prepare-fedora-workstation-44-1.7-5d87db39".to_owned(),
            domain_uuid: "ae82467d-10dd-4d33-b6ab-52f67e11e795".to_owned(),
            staging_identity: StagingIdentity {
                path:
                    "/var/lib/libvirt/images/forge-stage-fedora-workstation-44-1.7-5d87db39.qcow2"
                        .to_owned(),
                volume_name: "forge-stage-fedora-workstation-44-1.7-5d87db39.qcow2".to_owned(),
                volume_key:
                    "/var/lib/libvirt/images/forge-stage-fedora-workstation-44-1.7-5d87db39.qcow2"
                        .to_owned(),
                inode: 445_745,
                capacity_bytes: 80 * 1024 * 1024 * 1024,
            },
            normalization_recipe: "V1".to_owned(),
            expected_state: "InstalledSystemProven".to_owned(),
            bootstrap_transaction_id: "bootstrap-test".to_owned(),
            helper_sha256: "a".repeat(64),
            generator_sha256: "a".repeat(64),
            channel_name: "org.majorforge.preparation.0".to_owned(),
        }
    }

    fn request() -> Request {
        let binding = binding();
        Request {
            protocol_version: 1,
            binding: RequestBinding {
                preparation_id: binding.preparation_id,
                domain_name: binding.domain_name,
                domain_uuid: binding.domain_uuid,
                staging_path: binding.staging_identity.path,
                recipe: "V1".to_owned(),
                expected_state: binding.expected_state,
            },
            operation: "ReadOnlyGuestInventoryProbe".to_owned(),
            operation_id: "operation-00000001".to_owned(),
            nonce: "n".repeat(32),
        }
    }

    #[test]
    fn fixed_read_only_request_is_accepted() {
        assert!(validate_request(&binding(), &request()).is_ok());
    }

    #[test]
    fn unsupported_operation_nonce_and_identity_are_refused() {
        let mut values = Vec::new();
        let mut value = request();
        value.operation = "Normalize".to_owned();
        values.push(value);
        let mut value = request();
        value.nonce = "short".to_owned();
        values.push(value);
        let mut value = request();
        value.binding.staging_path = "/arbitrary".to_owned();
        values.push(value);
        for value in values {
            assert!(validate_request(&binding(), &value).is_err());
        }
    }

    #[test]
    fn producer_canonical_binding_bytes_are_accepted_by_helper() {
        // This is the broker's expected_real_binding serialization contract:
        // serde_json::to_vec_pretty over the nested canonical object.
        let producer_value = serde_json::json!({
            "protocol_version": 1,
            "preparation_id": "5d87db391be74e86bd0c7dca042295c3",
            "domain_name": "forge-prepare-fedora-workstation-44-1.7-5d87db39",
            "domain_uuid": "ae82467d-10dd-4d33-b6ab-52f67e11e795",
            "staging_identity": {
                "path": "/var/lib/libvirt/images/forge-stage-fedora-workstation-44-1.7-5d87db39.qcow2",
                "volume_name": "forge-stage-fedora-workstation-44-1.7-5d87db39.qcow2",
                "volume_key": "/var/lib/libvirt/images/forge-stage-fedora-workstation-44-1.7-5d87db39.qcow2",
                "inode": 445_745,
                "capacity_bytes": 80u64 * 1024 * 1024 * 1024
            },
            "normalization_recipe": "V1",
            "expected_state": "InstalledSystemProven",
            "bootstrap_transaction_id": "bootstrap-test",
            "helper_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "generator_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "channel_name": "org.majorforge.preparation.0"
        });
        let canonical_bytes = serde_json::to_vec_pretty(&producer_value).unwrap();
        let parsed = parse_binding_bytes(&canonical_bytes).unwrap();
        assert!(validate_binding(&parsed).is_ok());
    }

    #[test]
    fn binding_contract_rejects_legacy_unknown_and_identity_mismatches() {
        let canonical = serde_json::to_value(binding()).unwrap();
        let mut cases = Vec::new();
        let mut legacy = canonical.clone();
        legacy.as_object_mut().unwrap().remove("staging_identity");
        legacy.as_object_mut().unwrap().insert(
            "staging_path".to_owned(),
            serde_json::Value::String("/var/lib/libvirt/images/legacy.qcow2".to_owned()),
        );
        cases.push(serde_json::to_vec(&legacy).unwrap());
        let mut unknown = canonical.clone();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("extra".to_owned(), serde_json::Value::Bool(true));
        cases.push(serde_json::to_vec(&unknown).unwrap());
        for field in [
            "preparation_id",
            "domain_uuid",
            "normalization_recipe",
            "channel_name",
        ] {
            let mut mismatch = canonical.clone();
            mismatch
                .as_object_mut()
                .unwrap()
                .get_mut(field)
                .unwrap()
                .clone_from(&serde_json::Value::String("wrong".to_owned()));
            cases.push(serde_json::to_vec(&mismatch).unwrap());
        }
        cases.push(b"not-json".to_vec());
        for bytes in cases {
            let result = parse_binding_bytes(&bytes).and_then(|value| validate_binding(&value));
            assert!(result.is_err(), "accepted malformed binding: {bytes:?}");
        }
    }
}
