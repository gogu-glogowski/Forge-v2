use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
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
struct Binding {
    protocol_version: u32,
    preparation_id: String,
    domain_name: String,
    domain_uuid: String,
    staging_path: String,
    expected_state: String,
    bootstrap_transaction_id: String,
    helper_sha256: String,
}

#[derive(Debug, Deserialize)]
struct Request {
    protocol_version: u32,
    binding: RequestBinding,
    operation: String,
    operation_id: String,
    nonce: String,
}

#[derive(Debug, Deserialize)]
struct RequestBinding {
    preparation_id: String,
    domain_name: String,
    domain_uuid: String,
    staging_path: String,
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
}

#[derive(Debug, Serialize)]
struct ResultEnvelope<'a> {
    protocol_version: u32,
    binding: ResultBinding<'a>,
    operation: &'static str,
    operation_id: &'a str,
    nonce: &'a str,
    completion: &'static str,
    inventory: Inventory,
    error_code: Option<&'static str>,
    guest_sequence: u64,
}

#[derive(Debug, Serialize)]
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
    let binding: Binding =
        serde_json::from_slice(&fs::read(RUN_BINDING).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    if binding.protocol_version != PROTOCOL_VERSION
        || binding.expected_state != "InstalledSystemProven"
    {
        return Err("binding refused".to_owned());
    }
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
        },
    )?;
    let mut line = String::new();
    BufReader::new(channel.try_clone().map_err(|e| e.to_string())?)
        .read_line(&mut line)
        .map_err(|e| e.to_string())?;
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
                staging_path: &binding.staging_path,
                recipe: "V1",
                expected_state: "InstalledSystemProven",
            },
            operation: "ReadOnlyGuestInventoryProbe",
            operation_id: &request.operation_id,
            nonce: &request.nonce,
            completion: "Completed",
            inventory,
            error_code: None,
            guest_sequence: 1,
        },
    )
}

fn validate_request(binding: &Binding, request: &Request) -> Result<(), String> {
    if request.protocol_version != PROTOCOL_VERSION
        || request.operation != "ReadOnlyGuestInventoryProbe"
        || request.operation_id.len() < 16
        || request.nonce.len() < 32
        || request.binding.preparation_id != binding.preparation_id
        || request.binding.domain_name != binding.domain_name
        || request.binding.domain_uuid != binding.domain_uuid
        || request.binding.staging_path != binding.staging_path
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
            staging_path:
                "/var/lib/libvirt/images/forge-stage-fedora-workstation-44-1.7-5d87db39.qcow2"
                    .to_owned(),
            expected_state: "InstalledSystemProven".to_owned(),
            bootstrap_transaction_id: "bootstrap-test".to_owned(),
            helper_sha256: "a".repeat(64),
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
                staging_path: binding.staging_path,
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
}
