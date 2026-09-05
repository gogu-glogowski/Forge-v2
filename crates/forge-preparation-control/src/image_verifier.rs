//! Narrow privileged verifier for a preparation-owned Fedora staging volume.
//! It accepts an identity, never a filesystem path, and performs only read-only
//! qemu-img checks.

use serde::Deserialize;
use std::path::PathBuf;
use std::process::Command;

const CAPACITY: u64 = 80 * 1024 * 1024 * 1024;
const IMAGE_ROOT: &str = "/var/lib/libvirt/images";

#[derive(Debug, Deserialize)]
struct QcowInfo {
    format: String,
    #[serde(rename = "virtual-size")]
    virtual_size: u64,
    #[serde(rename = "backing-filename")]
    backing_filename: Option<String>,
}

fn staging_path(preparation_id: &str) -> Result<PathBuf, String> {
    if preparation_id.len() != 32
        || !preparation_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("preparation identity refused".to_owned());
    }
    Ok(PathBuf::from(format!(
        "{IMAGE_ROOT}/forge-stage-fedora-workstation-44-1.7-{}.qcow2",
        &preparation_id[..8]
    )))
}

fn verify(preparation_id: &str) -> Result<(), String> {
    let path = staging_path(preparation_id)?;
    let info = Command::new("/usr/bin/qemu-img")
        .args(["info", "--output=json", "--"])
        .arg(&path)
        .output()
        .map_err(|error| format!("qemu-img info unavailable: {error}"))?;
    if !info.status.success() {
        return Err(format!(
            "qemu-img info refused: {}",
            String::from_utf8_lossy(&info.stderr).trim()
        ));
    }
    let metadata: QcowInfo = serde_json::from_slice(&info.stdout)
        .map_err(|error| format!("qemu-img info was malformed: {error}"))?;
    if metadata.format != "qcow2"
        || metadata.virtual_size != CAPACITY
        || metadata.backing_filename.is_some()
    {
        return Err("staging image shape refused".to_owned());
    }
    let check = Command::new("/usr/bin/qemu-img")
        .args(["check", "--"])
        .arg(&path)
        .output()
        .map_err(|error| format!("qemu-img check unavailable: {error}"))?;
    if !check.status.success() {
        return Err(format!(
            "qemu-img check refused: {}",
            String::from_utf8_lossy(&check.stderr).trim()
        ));
    }
    println!(
        "VERIFIED preparation_id={preparation_id} format=qcow2 capacity={CAPACITY} backing=none health=pass"
    );
    Ok(())
}

fn main() -> std::process::ExitCode {
    let arguments = std::env::args().collect::<Vec<_>>();
    if arguments.len() != 3 || arguments[1] != "--preparation-id" {
        eprintln!("usage: forge-image-verifier --preparation-id <32-hex-id>");
        return std::process::ExitCode::from(2);
    }
    verify(&arguments[2]).map_or_else(
        |error| {
            eprintln!("forge-image-verifier: {error}");
            std::process::ExitCode::from(1)
        },
        |()| std::process::ExitCode::SUCCESS,
    )
}

#[cfg(test)]
mod tests {
    use super::staging_path;

    #[test]
    fn derives_only_the_typed_staging_identity() {
        let path = staging_path("4ad083f66d9d4dd0a834250ddef9826d").unwrap();
        assert_eq!(
            path.to_string_lossy(),
            "/var/lib/libvirt/images/forge-stage-fedora-workstation-44-1.7-4ad083f6.qcow2"
        );
        assert!(staging_path("../../etc/passwd").is_err());
    }
}
