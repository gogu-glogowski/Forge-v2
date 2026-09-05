//! Typed, fixed-target offline helper replacement authority.
#![allow(dead_code)]
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

pub const HELPER_REL: &str = "usr/libexec/forge-preparation-control";
pub const GENERATOR_REL: &str =
    "usr/lib/systemd/system-generators/forge-preparation-control-generator";
pub const BINDING_REL: &str = "usr/lib/forge-preparation-control/binding.json";
pub const OLD_SHA256: &str = "bb546fa9bf6efc11bde7687cba792421afc46616287a4fa468eadf3a7d0ad4a2";
pub const OLD_BYTES: u64 = 784_624;
pub const NEW_SHA256: &str = "cfc6ee47afa64767e6eb93594235f203e89fd76ca4ce851548ce02d3545b16a5";
pub const NEW_BYTES: u64 = 802_896;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperState {
    OldExact,
    NewExact,
    PartialOrMismatched,
    Missing,
    Indeterminate,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplacementPlan {
    ReplacementAuthorized,
    ReplayRefused,
    RecoveryRequired,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplacementTransaction {
    pub preparation_id: String,
    pub domain_name: String,
    pub domain_uuid: String,
    pub staging_identity: String,
    pub remediation_transaction_id: String,
    pub protocol_version: u32,
    pub normalization_recipe: String,
    pub canonical_binding_sha256: String,
    pub generator_sha256: String,
    pub old_helper_sha256: String,
    pub old_helper_bytes: u64,
    pub new_helper_sha256: String,
    pub new_helper_bytes: u64,
}

pub fn classify(root: &Path, tx: &ReplacementTransaction) -> HelperState {
    classify_impl(root, tx, 0, 0)
}
fn classify_impl(root: &Path, tx: &ReplacementTransaction, owner: u32, group: u32) -> HelperState {
    let path = root.join(HELPER_REL);
    let metadata = match fs::metadata(&path) {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return HelperState::Missing,
        Err(_) => return HelperState::Indeterminate,
    };
    let Ok(digest) = digest(&path) else {
        return HelperState::Indeterminate;
    };
    if metadata.uid() != owner || metadata.gid() != group || metadata.mode() & 0o777 != 0o755 {
        return HelperState::PartialOrMismatched;
    }
    if digest == tx.old_helper_sha256
        && metadata.len() == tx.old_helper_bytes
        && exact_companions(root, tx)
    {
        HelperState::OldExact
    } else if digest == tx.new_helper_sha256
        && metadata.len() == tx.new_helper_bytes
        && exact_companions(root, tx)
    {
        HelperState::NewExact
    } else {
        HelperState::PartialOrMismatched
    }
}

pub fn plan(state: HelperState, completion_evidence: bool) -> ReplacementPlan {
    match (state, completion_evidence) {
        (HelperState::OldExact, false) => ReplacementPlan::ReplacementAuthorized,
        (HelperState::NewExact, true) => ReplacementPlan::ReplayRefused,
        (HelperState::NewExact, false) => ReplacementPlan::RecoveryRequired,
        _ => ReplacementPlan::Blocked,
    }
}

pub fn replace(root: &Path, artifact: &[u8], tx: &ReplacementTransaction) -> Result<(), String> {
    replace_impl(root, artifact, tx, 0, 0)
}
fn replace_impl(
    root: &Path,
    artifact: &[u8],
    tx: &ReplacementTransaction,
    owner: u32,
    group: u32,
) -> Result<(), String> {
    if artifact.len() as u64 != tx.new_helper_bytes
        || format!("{:x}", Sha256::digest(artifact)) != tx.new_helper_sha256
    {
        return Err("NewHelperIdentityRefused".into());
    }
    if classify_impl(root, tx, owner, group) != HelperState::OldExact {
        return Err("OldHelperIdentityRefused".into());
    }
    let target = root.join(HELPER_REL);
    let temp = target.with_extension("r2.tmp");
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o755)
        .open(&temp)
        .map_err(|e| e.to_string())?;
    f.write_all(artifact)
        .and_then(|()| f.sync_all())
        .map_err(|e| e.to_string())?;
    fs::set_permissions(&temp, fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())?;
    fs::rename(&temp, &target).map_err(|e| e.to_string())?;
    if classify_impl(root, tx, owner, group) != HelperState::NewExact {
        return Err("ReplacementVerificationRefused".into());
    }
    let evidence_dir = root.join(".forge-r2");
    fs::create_dir_all(&evidence_dir).map_err(|e| e.to_string())?;
    let evidence = format!(
        "transaction={}\npreparation={}\ndomain_uuid={}\nstaging={}\npath={}\nold_sha256={}\nold_bytes={}\nnew_sha256={}\nnew_bytes={}\ngenerator_sha256={}\nbinding_sha256={}\nprotocol={}\nrecipe={}\nverification=Passed\n",
        tx.remediation_transaction_id,
        tx.preparation_id,
        tx.domain_uuid,
        tx.staging_identity,
        HELPER_REL,
        tx.old_helper_sha256,
        tx.old_helper_bytes,
        tx.new_helper_sha256,
        tx.new_helper_bytes,
        tx.generator_sha256,
        tx.canonical_binding_sha256,
        tx.protocol_version,
        tx.normalization_recipe
    );
    let temp_evidence = evidence_dir.join("evidence.tmp");
    fs::write(&temp_evidence, evidence).map_err(|e| e.to_string())?;
    fs::rename(temp_evidence, evidence_dir.join("evidence")).map_err(|e| e.to_string())?;
    let mut ledger = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(evidence_dir.join("ledger"))
        .map_err(|_| "ReplayRefused".to_owned())?;
    ledger
        .write_all(tx.remediation_transaction_id.as_bytes())
        .and_then(|()| ledger.write_all(b"\n"))
        .and_then(|()| ledger.sync_all())
        .map_err(|e| e.to_string())?;
    fs::write(
        evidence_dir.join("journal"),
        format!("Completed {}\n", tx.remediation_transaction_id),
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

fn exact_companions(root: &Path, tx: &ReplacementTransaction) -> bool {
    let generator = root.join(GENERATOR_REL);
    let binding = root.join(BINDING_REL);
    digest(&generator).is_ok_and(|d| d == tx.generator_sha256)
        && digest(&binding).is_ok_and(|d| d == tx.canonical_binding_sha256)
}
fn digest(path: &Path) -> Result<String, String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(fs::read(path).map_err(|e| e.to_string())?)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    fn fixture() -> (PathBuf, ReplacementTransaction, Vec<u8>, Vec<u8>) {
        let root = std::env::temp_dir().join(format!(
            "forge-r2-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join("usr/libexec")).unwrap();
        fs::create_dir_all(root.join("usr/lib/systemd/system-generators")).unwrap();
        fs::create_dir_all(root.join("usr/lib/forge-preparation-control")).unwrap();
        let old = vec![b'o'; usize::try_from(OLD_BYTES).unwrap()];
        let new = vec![b'n'; usize::try_from(NEW_BYTES).unwrap()];
        fs::write(root.join(HELPER_REL), &old).unwrap();
        fs::write(root.join(GENERATOR_REL), b"generator").unwrap();
        fs::write(root.join(BINDING_REL), b"binding").unwrap();
        for p in [root.join(HELPER_REL), root.join(GENERATOR_REL)] {
            fs::set_permissions(p, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let tx = ReplacementTransaction {
            preparation_id: "p".into(),
            domain_name: "d".into(),
            domain_uuid: "u".into(),
            staging_identity: "s".into(),
            remediation_transaction_id: "r2-test".into(),
            protocol_version: 1,
            normalization_recipe: "V1".into(),
            canonical_binding_sha256: format!("{:x}", Sha256::digest(b"binding")),
            generator_sha256: format!("{:x}", Sha256::digest(b"generator")),
            old_helper_sha256: format!("{:x}", Sha256::digest(&old)),
            old_helper_bytes: old.len() as u64,
            new_helper_sha256: format!("{:x}", Sha256::digest(&new)),
            new_helper_bytes: new.len() as u64,
        };
        (root, tx, old, new)
    }
    #[test]
    fn typed_lifecycle_and_replay_are_fail_closed() {
        let (root, tx, old, new) = fixture();
        let meta = fs::metadata(root.join(HELPER_REL)).unwrap();
        let uid = meta.uid();
        let gid = meta.gid();
        assert_eq!(classify_impl(&root, &tx, uid, gid), HelperState::OldExact);
        assert_eq!(
            plan(classify_impl(&root, &tx, uid, gid), false),
            ReplacementPlan::ReplacementAuthorized
        );
        assert_eq!(
            plan(HelperState::NewExact, true),
            ReplacementPlan::ReplayRefused
        );
        assert_eq!(
            plan(HelperState::PartialOrMismatched, false),
            ReplacementPlan::Blocked
        );
        assert_eq!(old.len() as u64, OLD_BYTES);
        assert_eq!(new.len() as u64, NEW_BYTES);
        assert!(replace_impl(&root, b"bad", &tx, uid, gid).is_err());
        assert!(replace_impl(&root, &new, &tx, uid, gid).is_ok());
        assert_eq!(classify_impl(&root, &tx, uid, gid), HelperState::NewExact);
        assert_eq!(
            plan(classify_impl(&root, &tx, uid, gid), true),
            ReplacementPlan::ReplayRefused
        );
        assert!(replace_impl(&root, &new, &tx, uid, gid).is_err());
        assert_eq!(
            fs::read_to_string(root.join(".forge-r2/ledger"))
                .unwrap()
                .lines()
                .count(),
            1
        );
        assert!(root.join(".forge-r2/evidence").exists());
        let _ = fs::remove_dir_all(root);
    }
    #[test]
    fn classifier_rejects_missing_wrong_and_metadata_states() {
        let (root, tx, _, _) = fixture();
        let generator_before = fs::read(root.join(GENERATOR_REL)).unwrap();
        let binding_before = fs::read(root.join(BINDING_REL)).unwrap();
        let meta = fs::metadata(root.join(HELPER_REL)).unwrap();
        let uid = meta.uid();
        let gid = meta.gid();
        assert_eq!(classify_impl(&root, &tx, uid, gid), HelperState::OldExact);
        fs::set_permissions(root.join(HELPER_REL), fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            classify_impl(&root, &tx, uid, gid),
            HelperState::PartialOrMismatched
        );
        fs::remove_file(root.join(HELPER_REL)).unwrap();
        assert_eq!(classify_impl(&root, &tx, uid, gid), HelperState::Missing);
        assert_eq!(
            fs::read(root.join(GENERATOR_REL)).unwrap(),
            generator_before
        );
        assert_eq!(fs::read(root.join(BINDING_REL)).unwrap(), binding_before);
        let _ = fs::remove_dir_all(root);
    }
}
