//! Durable Forge ownership manifests and pure reconciliation.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

mod managed;
pub use managed::*;

pub const SCHEMA_VERSION: u32 = 1;
pub const STATE_DIRECTORY_MODE: u32 = 0o700;
pub const STATE_FILE_MODE: u32 = 0o600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceRole {
    SharedBase,
    WritableOverlay,
    NoCloudSeed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GenerationStatus {
    Preparing,
    Active,
    Retained,
    Failed,
    Cleaned,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedResource {
    pub role: ResourceRole,
    pub volume_name: String,
    pub volume_key: String,
    pub path: String,
    pub format: String,
    pub capacity_bytes: u64,
    pub backing_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationManifest {
    pub schema_version: u32,
    pub domain_name: String,
    pub domain_uuid: String,
    pub generation_id: String,
    pub created_unix_seconds: u64,
    pub libvirt_uri: String,
    pub storage_pool_name: String,
    pub storage_pool_uuid: String,
    pub status: GenerationStatus,
    pub resources: Vec<ManagedResource>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedResource {
    pub role: ResourceRole,
    pub volume_name: String,
    pub volume_key: String,
    pub path: String,
    pub format: String,
    pub capacity_bytes: u64,
    pub backing_path: Option<String>,
    pub referenced_by_domains: Vec<String>,
    pub backing_for_volumes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedGeneration {
    pub domain_name: String,
    pub domain_uuid: String,
    pub domain_persistent: bool,
    pub libvirt_uri: String,
    pub storage_pool_name: String,
    pub storage_pool_uuid: String,
    pub resources: Vec<ObservedResource>,
    pub unmanaged_resources: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconciliationStatus {
    Consistent,
    Drifted,
    Missing,
    Conflict,
    Unmanaged,
    CorruptState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconciliationIssue {
    pub status: ReconciliationStatus,
    pub field: String,
    pub expected: String,
    pub actual: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconciliationReport {
    pub status: ReconciliationStatus,
    pub issues: Vec<ReconciliationIssue>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdoptionPlan {
    pub manifest_path: PathBuf,
    pub manifest: GenerationManifest,
    pub adoptable_resources: Vec<ManagedResource>,
    pub unmanaged_resources: Vec<String>,
    pub mutation: bool,
}

#[derive(Debug)]
pub enum StateError {
    Io(std::io::Error),
    CorruptManifest(String),
    UnsupportedSchema(u32),
    InvalidObservedState(String),
    AlreadyExists(PathBuf),
}

impl fmt::Display for StateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "state I/O failed: {error}"),
            Self::CorruptManifest(error) => write!(formatter, "manifest is corrupt: {error}"),
            Self::UnsupportedSchema(version) => {
                write!(formatter, "unsupported manifest schema version: {version}")
            }
            Self::InvalidObservedState(reason) => {
                write!(
                    formatter,
                    "observed libvirt state cannot be adopted: {reason}"
                )
            }
            Self::AlreadyExists(path) => {
                write!(formatter, "manifest already exists: {}", path.display())
            }
        }
    }
}

impl std::error::Error for StateError {}

impl From<std::io::Error> for StateError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

#[must_use]
pub fn state_directory(home: &Path) -> PathBuf {
    home.join(".local/share/forge/state")
}

#[must_use]
pub fn manifest_path(state_directory: &Path, domain_name: &str) -> PathBuf {
    state_directory.join(format!("{domain_name}.json"))
}

/// Serializes a manifest as stable, readable JSON.
///
/// # Errors
/// Returns a typed serialization error.
pub fn serialize(manifest: &GenerationManifest) -> Result<Vec<u8>, StateError> {
    serde_json::to_vec_pretty(manifest)
        .map(|mut bytes| {
            bytes.push(b'\n');
            bytes
        })
        .map_err(|error| StateError::CorruptManifest(error.to_string()))
}

/// Parses a manifest and rejects unknown schema versions or malformed data.
///
/// # Errors
/// Returns a typed corrupt/schema error.
pub fn deserialize(bytes: &[u8]) -> Result<GenerationManifest, StateError> {
    let manifest: GenerationManifest = serde_json::from_slice(bytes)
        .map_err(|error| StateError::CorruptManifest(error.to_string()))?;
    if manifest.schema_version != SCHEMA_VERSION {
        return Err(StateError::UnsupportedSchema(manifest.schema_version));
    }
    Ok(manifest)
}

/// Reads a manifest. Missing state is represented by `Ok(None)`.
///
/// # Errors
/// Returns a typed I/O, corruption, or schema error.
pub fn read_manifest(path: &Path) -> Result<Option<GenerationManifest>, StateError> {
    match fs::read(path) {
        Ok(bytes) => deserialize(&bytes).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(StateError::Io(error)),
    }
}

/// Atomically writes a manifest with explicit private permissions.
///
/// Lifecycle: serialize, same-directory temporary file, flush, file fsync,
/// atomic rename, directory fsync.
///
/// # Errors
/// Preserves the previous final file when writing fails before rename.
pub fn write_manifest_atomic(path: &Path, manifest: &GenerationManifest) -> Result<(), StateError> {
    let parent = path.parent().ok_or_else(|| {
        StateError::InvalidObservedState("manifest path has no parent".to_owned())
    })?;
    fs::create_dir_all(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(STATE_DIRECTORY_MODE))?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("manifest"),
        std::process::id()
    ));
    let bytes = serialize(manifest)?;
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(STATE_FILE_MODE)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.flush()?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(STATE_FILE_MODE))?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[must_use]
pub fn new_generation_id() -> String {
    format!("gen-{}", Uuid::new_v4())
}

/// Builds a zero-mutation adoption plan for the currently active generation.
///
/// # Errors
/// Fails closed when domain identity, topology, or active references are ambiguous.
pub fn plan_adoption(
    observed: &ObservedGeneration,
    path: PathBuf,
    now: SystemTime,
) -> Result<AdoptionPlan, StateError> {
    if observed.domain_name != "fedora-lab" || !observed.domain_persistent {
        return Err(StateError::InvalidObservedState(
            "only the persistent fedora-lab domain can be adopted".to_owned(),
        ));
    }
    let resource = |role| {
        observed
            .resources
            .iter()
            .find(|resource| resource.role == role)
    };
    let base = resource(ResourceRole::SharedBase)
        .ok_or_else(|| StateError::InvalidObservedState("shared base is missing".to_owned()))?;
    let overlay = resource(ResourceRole::WritableOverlay)
        .ok_or_else(|| StateError::InvalidObservedState("active overlay is missing".to_owned()))?;
    let seed = resource(ResourceRole::NoCloudSeed)
        .ok_or_else(|| StateError::InvalidObservedState("active seed is missing".to_owned()))?;
    if observed.resources.len() != 3
        || base.format != "qcow2"
        || base.backing_path.is_some()
        || overlay.format != "qcow2"
        || overlay.backing_path.as_deref() != Some(base.path.as_str())
        || !overlay
            .referenced_by_domains
            .contains(&observed.domain_name)
        || !seed.referenced_by_domains.contains(&observed.domain_name)
        || !matches!(seed.format.as_str(), "raw" | "iso")
    {
        return Err(StateError::InvalidObservedState(
            "active base/overlay/seed topology is not unambiguous".to_owned(),
        ));
    }
    let duration = now.duration_since(UNIX_EPOCH).map_err(|error| {
        StateError::InvalidObservedState(format!("system clock predates Unix epoch: {error}"))
    })?;
    let resources = observed
        .resources
        .iter()
        .map(|resource| ManagedResource {
            role: resource.role,
            volume_name: resource.volume_name.clone(),
            volume_key: resource.volume_key.clone(),
            path: resource.path.clone(),
            format: resource.format.clone(),
            capacity_bytes: resource.capacity_bytes,
            backing_path: resource.backing_path.clone(),
        })
        .collect::<Vec<_>>();
    let manifest = GenerationManifest {
        schema_version: SCHEMA_VERSION,
        domain_name: observed.domain_name.clone(),
        domain_uuid: observed.domain_uuid.clone(),
        generation_id: new_generation_id(),
        created_unix_seconds: duration.as_secs(),
        libvirt_uri: observed.libvirt_uri.clone(),
        storage_pool_name: observed.storage_pool_name.clone(),
        storage_pool_uuid: observed.storage_pool_uuid.clone(),
        status: GenerationStatus::Active,
        resources: resources.clone(),
    };
    Ok(AdoptionPlan {
        manifest_path: path,
        manifest,
        adoptable_resources: resources,
        unmanaged_resources: observed.unmanaged_resources.clone(),
        mutation: false,
    })
}

/// Reconciles Forge ownership intent with independently observed libvirt state.
#[must_use]
pub fn reconcile(
    manifest: &GenerationManifest,
    observed: &ObservedGeneration,
) -> ReconciliationReport {
    let mut issues = Vec::new();
    if !observed.domain_persistent {
        issues.push(ReconciliationIssue {
            status: ReconciliationStatus::Conflict,
            field: "domain_persistent".to_owned(),
            expected: "true".to_owned(),
            actual: "false".to_owned(),
        });
    }
    for (field, expected, actual) in [
        (
            "domain_name",
            manifest.domain_name.as_str(),
            observed.domain_name.as_str(),
        ),
        (
            "domain_uuid",
            manifest.domain_uuid.as_str(),
            observed.domain_uuid.as_str(),
        ),
        (
            "libvirt_uri",
            manifest.libvirt_uri.as_str(),
            observed.libvirt_uri.as_str(),
        ),
        (
            "storage_pool_name",
            manifest.storage_pool_name.as_str(),
            observed.storage_pool_name.as_str(),
        ),
        (
            "storage_pool_uuid",
            manifest.storage_pool_uuid.as_str(),
            observed.storage_pool_uuid.as_str(),
        ),
    ] {
        compare(
            &mut issues,
            ReconciliationStatus::Conflict,
            field,
            expected,
            actual,
        );
    }
    for expected in &manifest.resources {
        reconcile_resource(expected, observed, &manifest.domain_name, &mut issues);
    }
    ReconciliationReport {
        status: reconciliation_status(&issues),
        issues,
    }
}

fn reconcile_resource(
    expected: &ManagedResource,
    observed: &ObservedGeneration,
    domain_name: &str,
    issues: &mut Vec<ReconciliationIssue>,
) {
    let Some(actual) = observed
        .resources
        .iter()
        .find(|resource| resource.role == expected.role)
    else {
        issues.push(ReconciliationIssue {
            status: ReconciliationStatus::Missing,
            field: format!("resource.{:?}", expected.role),
            expected: expected.path.clone(),
            actual: "missing".to_owned(),
        });
        return;
    };
    for (field, expected, actual) in [
        (
            "volume_name",
            expected.volume_name.as_str(),
            actual.volume_name.as_str(),
        ),
        (
            "volume_key",
            expected.volume_key.as_str(),
            actual.volume_key.as_str(),
        ),
        ("path", expected.path.as_str(), actual.path.as_str()),
    ] {
        compare(
            issues,
            ReconciliationStatus::Conflict,
            field,
            expected,
            actual,
        );
    }
    compare(
        issues,
        ReconciliationStatus::Drifted,
        "format",
        &expected.format,
        &actual.format,
    );
    compare_value(
        issues,
        ReconciliationStatus::Drifted,
        "capacity_bytes",
        &expected.capacity_bytes,
        &actual.capacity_bytes,
    );
    compare(
        issues,
        ReconciliationStatus::Conflict,
        "backing_path",
        &format!("{:?}", expected.backing_path),
        &format!("{:?}", actual.backing_path),
    );
    if matches!(
        expected.role,
        ResourceRole::WritableOverlay | ResourceRole::NoCloudSeed
    ) && !actual
        .referenced_by_domains
        .iter()
        .any(|reference| reference == domain_name)
    {
        issues.push(ReconciliationIssue {
            status: ReconciliationStatus::Conflict,
            field: format!("resource.{:?}.domain_reference", expected.role),
            expected: domain_name.to_owned(),
            actual: format!("{:?}", actual.referenced_by_domains),
        });
    }
}

fn reconciliation_status(issues: &[ReconciliationIssue]) -> ReconciliationStatus {
    [
        ReconciliationStatus::Conflict,
        ReconciliationStatus::Missing,
        ReconciliationStatus::Drifted,
    ]
    .into_iter()
    .find(|status| issues.iter().any(|issue| issue.status == *status))
    .unwrap_or(ReconciliationStatus::Consistent)
}

fn compare(
    issues: &mut Vec<ReconciliationIssue>,
    status: ReconciliationStatus,
    field: &str,
    expected: &str,
    actual: &str,
) {
    if expected != actual {
        issues.push(ReconciliationIssue {
            status,
            field: field.to_owned(),
            expected: expected.to_owned(),
            actual: actual.to_owned(),
        });
    }
}

fn compare_value<T: fmt::Display + PartialEq>(
    issues: &mut Vec<ReconciliationIssue>,
    status: ReconciliationStatus,
    field: &str,
    expected: &T,
    actual: &T,
) {
    if expected != actual {
        issues.push(ReconciliationIssue {
            status,
            field: field.to_owned(),
            expected: expected.to_string(),
            actual: actual.to_string(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observed() -> ObservedGeneration {
        let resource = |role: ResourceRole,
                        name: &str,
                        format: &str,
                        capacity: u64,
                        backing: Option<&str>,
                        referenced: Vec<String>| ObservedResource {
            role,
            volume_name: name.to_owned(),
            volume_key: format!("key-{name}"),
            path: format!("/pool/{name}"),
            format: format.to_owned(),
            capacity_bytes: capacity,
            backing_path: backing.map(str::to_owned),
            referenced_by_domains: referenced,
            backing_for_volumes: Vec::new(),
        };
        ObservedGeneration {
            domain_name: "fedora-lab".to_owned(),
            domain_uuid: "domain-uuid".to_owned(),
            domain_persistent: true,
            libvirt_uri: "qemu:///system".to_owned(),
            storage_pool_name: "default".to_owned(),
            storage_pool_uuid: "pool-uuid".to_owned(),
            resources: vec![
                resource(
                    ResourceRole::SharedBase,
                    "base.qcow2",
                    "qcow2",
                    5,
                    None,
                    Vec::new(),
                ),
                resource(
                    ResourceRole::WritableOverlay,
                    "overlay.qcow2",
                    "qcow2",
                    64,
                    Some("/pool/base.qcow2"),
                    vec!["fedora-lab".to_owned()],
                ),
                resource(
                    ResourceRole::NoCloudSeed,
                    "seed.iso",
                    "raw",
                    1,
                    None,
                    vec!["fedora-lab".to_owned()],
                ),
            ],
            unmanaged_resources: vec!["legacy.qcow2".to_owned()],
        }
    }

    fn plan() -> AdoptionPlan {
        plan_adoption(
            &observed(),
            PathBuf::from("/state/fedora-lab.json"),
            UNIX_EPOCH + std::time::Duration::from_secs(10),
        )
        .unwrap()
    }

    fn unique_directory() -> PathBuf {
        std::env::temp_dir().join(format!(
            "forge-state-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn manifest_serializes_and_deserializes() {
        let manifest = plan().manifest;
        assert_eq!(
            deserialize(&serialize(&manifest).unwrap()).unwrap(),
            manifest
        );
    }

    #[test]
    fn unknown_schema_and_corrupt_manifest_fail_closed() {
        let mut value: serde_json::Value =
            serde_json::from_slice(&serialize(&plan().manifest).unwrap()).unwrap();
        value["schema_version"] = 99.into();
        assert!(matches!(
            deserialize(&serde_json::to_vec(&value).unwrap()),
            Err(StateError::UnsupportedSchema(99))
        ));
        assert!(matches!(
            deserialize(b"{broken"),
            Err(StateError::CorruptManifest(_))
        ));
        assert!(matches!(
            deserialize(br#"{"schema_version":1}"#),
            Err(StateError::CorruptManifest(_))
        ));
    }

    #[test]
    fn atomic_write_replaces_complete_manifest_and_uses_private_modes() {
        let directory = unique_directory();
        let path = manifest_path(&directory, "fedora-lab");
        let first = plan().manifest;
        write_manifest_atomic(&path, &first).unwrap();
        let mut second = first.clone();
        second.generation_id = "replacement".to_owned();
        write_manifest_atomic(&path, &second).unwrap();
        assert_eq!(read_manifest(&path).unwrap(), Some(second));
        assert_eq!(
            fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn failed_temporary_write_preserves_previous_manifest() {
        let directory = unique_directory();
        let path = manifest_path(&directory, "fedora-lab");
        let first = plan().manifest;
        write_manifest_atomic(&path, &first).unwrap();
        let temporary = directory.join(format!(".fedora-lab.json.{}.tmp", std::process::id()));
        fs::create_dir(&temporary).unwrap();
        let mut replacement = first.clone();
        replacement.generation_id = "must-not-appear".to_owned();
        assert!(write_manifest_atomic(&path, &replacement).is_err());
        assert_eq!(read_manifest(&path).unwrap(), Some(first));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn active_generation_is_consistent() {
        let plan = plan();
        assert_eq!(
            reconcile(&plan.manifest, &observed()).status,
            ReconciliationStatus::Consistent
        );
        assert!(!plan.mutation);
    }

    #[test]
    fn identity_pool_and_volume_drift_are_conflicts() {
        for mutation in 0..4 {
            let plan = plan();
            let mut actual = observed();
            match mutation {
                0 => actual.domain_uuid = "other-domain".to_owned(),
                1 => actual.storage_pool_uuid = "other-pool".to_owned(),
                2 => actual.resources[1].volume_key = "other-key".to_owned(),
                _ => actual.resources[1].path = "/other/overlay.qcow2".to_owned(),
            }
            assert_eq!(
                reconcile(&plan.manifest, &actual).status,
                ReconciliationStatus::Conflict
            );
        }
    }

    #[test]
    fn capacity_format_and_backing_changes_are_typed() {
        for mutation in 0..3 {
            let plan = plan();
            let mut actual = observed();
            match mutation {
                0 => actual.resources[1].capacity_bytes += 1,
                1 => actual.resources[1].format = "raw".to_owned(),
                _ => actual.resources[1].backing_path = Some("/pool/other.qcow2".to_owned()),
            }
            let expected = if mutation < 2 {
                ReconciliationStatus::Drifted
            } else {
                ReconciliationStatus::Conflict
            };
            assert_eq!(reconcile(&plan.manifest, &actual).status, expected);
        }
    }

    #[test]
    fn missing_volume_is_reported() {
        let plan = plan();
        let mut actual = observed();
        actual
            .resources
            .retain(|resource| resource.role != ResourceRole::NoCloudSeed);
        let report = reconcile(&plan.manifest, &actual);
        assert_eq!(report.status, ReconciliationStatus::Missing);
        assert!(report.issues.iter().any(|issue| issue.actual == "missing"));
    }

    #[test]
    fn unmanaged_legacy_resource_is_not_adopted() {
        let plan = plan();
        assert_eq!(plan.unmanaged_resources, ["legacy.qcow2"]);
        assert!(
            !plan
                .adoptable_resources
                .iter()
                .any(|resource| resource.volume_name == "legacy.qcow2")
        );
    }

    #[test]
    fn shared_base_is_not_a_disposable_generation_disk() {
        let plan = plan();
        let base = plan
            .manifest
            .resources
            .iter()
            .find(|resource| resource.role == ResourceRole::SharedBase)
            .unwrap();
        assert!(base.backing_path.is_none());
        assert_ne!(base.role, ResourceRole::WritableOverlay);
    }

    #[test]
    fn adoption_rejects_ambiguous_active_references_without_mutation() {
        let mut actual = observed();
        actual.resources[1].referenced_by_domains.clear();
        assert!(matches!(
            plan_adoption(&actual, PathBuf::from("/state/a.json"), UNIX_EPOCH),
            Err(StateError::InvalidObservedState(_))
        ));
    }

    #[test]
    fn adoption_dry_run_does_not_create_state_file() {
        let directory = unique_directory();
        let path = manifest_path(&directory, "fedora-lab");
        let plan = plan_adoption(&observed(), path.clone(), UNIX_EPOCH).unwrap();
        assert!(!plan.mutation);
        assert!(!path.exists());
        assert!(!directory.exists());
    }

    #[test]
    fn new_manifests_receive_distinct_random_v4_generation_ids() {
        let first = plan_adoption(&observed(), PathBuf::from("/state/a"), UNIX_EPOCH).unwrap();
        let second = plan_adoption(&observed(), PathBuf::from("/state/a"), UNIX_EPOCH).unwrap();
        assert_ne!(first.manifest.generation_id, second.manifest.generation_id);
        for id in [first.manifest.generation_id, second.manifest.generation_id] {
            let uuid = Uuid::parse_str(id.trim_start_matches("gen-")).unwrap();
            assert_eq!(uuid.get_version_num(), 4);
        }
    }

    #[test]
    fn serialization_reconciliation_and_reread_preserve_generation_id() {
        let directory = unique_directory();
        let path = manifest_path(&directory, "fedora-lab");
        let manifest = plan().manifest;
        let generation_id = manifest.generation_id.clone();
        let decoded = deserialize(&serialize(&manifest).unwrap()).unwrap();
        assert_eq!(decoded.generation_id, generation_id);

        assert_eq!(
            reconcile(&manifest, &observed()).status,
            ReconciliationStatus::Consistent
        );
        assert_eq!(manifest.generation_id, generation_id);

        write_manifest_atomic(&path, &manifest).unwrap();
        let reread = read_manifest(&path).unwrap().unwrap();
        assert_eq!(reread.generation_id, generation_id);
        fs::remove_dir_all(directory).unwrap();
    }
}
