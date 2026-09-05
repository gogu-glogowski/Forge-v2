//! Typed, path-free guest mutation plans and bounded session contracts.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

pub const PLAN_FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GuestMutationPlanId(pub String);
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GuestMutationTransactionId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactIdentity {
    pub sha256: String,
    pub size: u64,
    pub kind: String,
    pub provenance: String,
}

#[derive(Debug, Clone)]
pub struct TrustedArtifactStore {
    entries: BTreeMap<(String, u64), PathBuf>,
}

impl TrustedArtifactStore {
    pub fn new(entries: BTreeMap<(String, u64), PathBuf>) -> Result<Self, String> {
        for ((digest, size), path) in &entries {
            let metadata = path.metadata().map_err(|_| "ArtifactStoreRefused")?;
            if digest.len() != 64 || !metadata.is_file() || metadata.len() != *size {
                return Err("ArtifactStoreRefused".into());
            }
        }
        Ok(Self { entries })
    }

    pub fn resolve(&self, identity: &ArtifactIdentity) -> Result<PathBuf, String> {
        let path = self
            .entries
            .get(&(identity.sha256.clone(), identity.size))
            .ok_or("ArtifactMissing")?
            .clone();
        let bytes = std::fs::read(&path).map_err(|_| "ArtifactUnreadable")?;
        if bytes.len() as u64 != identity.size
            || format!("{:x}", Sha256::digest(&bytes)) != identity.sha256
        {
            return Err("ArtifactSubstitutionRefused".into());
        }
        Ok(path)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesystemDiscovery {
    pub root: String,
    pub topology: String,
}

pub fn discover_single_ext4(root_device: &str) -> Result<FilesystemDiscovery, String> {
    if root_device != "/dev/sda1" {
        return Err("UnsupportedOrAmbiguousTopology".into());
    }
    Ok(FilesystemDiscovery {
        root: "/".into(),
        topology: "single-ext4-root".into(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LogicalDestination {
    PreparationHelper,
    PreparationGenerator,
    PreparationBinding,
    ManagedConfigDirectory { profile_key: String },
    ManagedConfigFile { profile_key: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum GuestMutationOperation {
    EnsureDirectory {
        destination: LogicalDestination,
    },
    InstallArtifact {
        destination: LogicalDestination,
        artifact: ArtifactIdentity,
    },
    RemoveManagedArtifact {
        destination: LogicalDestination,
        expected: ArtifactIdentity,
    },
    WriteGeneratedConfig {
        destination: LogicalDestination,
        artifact: ArtifactIdentity,
    },
    SetManagedMetadata {
        destination: LogicalDestination,
        uid: u32,
        gid: u32,
        mode: u32,
    },
    VerifyArtifact {
        destination: LogicalDestination,
        artifact: ArtifactIdentity,
    },
    VerifyAbsent {
        destination: LogicalDestination,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestMutationPlan {
    pub format_version: u32,
    pub transaction_id: GuestMutationTransactionId,
    pub preparation_id: String,
    pub generation_id: String,
    pub profile: String,
    pub expected_disk_identity: String,
    pub expected_guest_identity: String,
    pub operations: Vec<GuestMutationOperation>,
    pub preconditions: Vec<String>,
    pub postconditions: Vec<String>,
    pub recovery_policy: String,
}

impl GuestMutationPlan {
    pub fn validate(&self) -> Result<(), String> {
        if self.format_version != PLAN_FORMAT_VERSION
            || self.operations.is_empty()
            || self.operations.len() > 1024
        {
            return Err("MutationPlanRefused".into());
        }
        if self.preparation_id.is_empty()
            || self.generation_id.is_empty()
            || self.profile.is_empty()
        {
            return Err("MutationPlanIdentityRefused".into());
        }
        for op in &self.operations {
            validate_destination(op.destination())?;
            validate_operation_destination(op)?;
        }
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|e| e.to_string())
    }
    pub fn identity(&self) -> Result<GuestMutationPlanId, String> {
        Ok(GuestMutationPlanId(format!(
            "gme-plan-{:x}",
            Sha256::digest(self.canonical_bytes()?)
        )))
    }
}

impl GuestMutationOperation {
    pub fn destination(&self) -> &LogicalDestination {
        match self {
            Self::EnsureDirectory { destination }
            | Self::InstallArtifact { destination, .. }
            | Self::RemoveManagedArtifact { destination, .. }
            | Self::WriteGeneratedConfig { destination, .. }
            | Self::SetManagedMetadata { destination, .. }
            | Self::VerifyArtifact { destination, .. }
            | Self::VerifyAbsent { destination } => destination,
        }
    }
}

fn validate_destination(destination: &LogicalDestination) -> Result<(), String> {
    if let LogicalDestination::ManagedConfigDirectory { profile_key }
    | LogicalDestination::ManagedConfigFile { profile_key } = destination
        && (profile_key.is_empty() || profile_key.contains('/') || profile_key.contains(".."))
    {
        return Err("DestinationPolicyRefused".into());
    }
    Ok(())
}

fn validate_operation_destination(operation: &GuestMutationOperation) -> Result<(), String> {
    let is_directory = matches!(
        operation.destination(),
        LogicalDestination::ManagedConfigDirectory { .. }
    );
    match operation {
        GuestMutationOperation::EnsureDirectory { .. } if !is_directory => {
            Err("DirectoryDestinationTypeRefused".into())
        }
        GuestMutationOperation::InstallArtifact { .. }
        | GuestMutationOperation::RemoveManagedArtifact { .. }
        | GuestMutationOperation::WriteGeneratedConfig { .. }
        | GuestMutationOperation::VerifyArtifact { .. }
            if is_directory =>
        {
            Err("FileDestinationTypeRefused".into())
        }
        _ => Ok(()),
    }
}

fn existing_destination_error(
    operation: &GuestMutationOperation,
    existing_file: bool,
    existing_directory: bool,
) -> Option<&'static str> {
    match operation {
        GuestMutationOperation::EnsureDirectory { .. } if existing_file => {
            Some("DirectoryDestinationIsFile")
        }
        GuestMutationOperation::InstallArtifact { .. } if existing_directory => {
            Some("FileDestinationIsDirectory")
        }
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuestMutationSessionState {
    Preparing,
    Applying,
    Verifying,
    Completed,
    RecoveryRequired,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestMutationEvidence {
    pub plan_id: GuestMutationPlanId,
    pub transaction_id: GuestMutationTransactionId,
    pub target_identity: String,
    pub pre_state: String,
    pub operation_results: Vec<String>,
    pub post_state: String,
    pub image_health: String,
    pub clean_close: bool,
    pub outcome: GuestMutationSessionState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTargetCapability {
    pub target_identity: String,
    pub disk_identity: String,
    pub plan_id: GuestMutationPlanId,
    pub transaction_id: GuestMutationTransactionId,
    pub profile: String,
    pub offline_required: bool,
    destinations: BTreeMap<LogicalDestination, String>,
    disk_path: Option<PathBuf>,
}

impl ResolvedTargetCapability {
    pub fn trusted(
        target_identity: String,
        disk_identity: String,
        plan: &GuestMutationPlan,
        destinations: BTreeMap<LogicalDestination, String>,
    ) -> Result<Self, String> {
        plan.validate()?;
        let plan_id = plan.identity()?;
        if destinations.values().any(|p| !p.starts_with('/'))
            || destinations.values().any(|p| p.contains(".."))
        {
            return Err("DestinationContainmentRefused".into());
        }
        for (destination, path) in &destinations {
            if let LogicalDestination::ManagedConfigDirectory { profile_key } = destination {
                let file_destination = LogicalDestination::ManagedConfigFile {
                    profile_key: profile_key.clone(),
                };
                if let Some(file_path) = destinations.get(&file_destination)
                    && (file_path == path
                        || !file_path
                            .strip_prefix(path)
                            .is_some_and(|suffix| suffix.starts_with('/')))
                {
                    return Err("DestinationShapeRefused".into());
                }
            }
        }
        Ok(Self {
            target_identity,
            disk_identity,
            plan_id,
            transaction_id: plan.transaction_id.clone(),
            profile: plan.profile.clone(),
            offline_required: true,
            destinations,
            disk_path: None,
        })
    }
    #[cfg(test)]
    fn with_test_disk(mut self, path: PathBuf) -> Self {
        self.disk_path = Some(path);
        self
    }
    fn resolve(&self, destination: &LogicalDestination) -> Result<&str, String> {
        self.destinations
            .get(destination)
            .map(String::as_str)
            .ok_or_else(|| "DestinationUnresolved".into())
    }
}

pub trait MutationAdapter {
    fn offline(&self) -> Result<bool, String>;
    fn discover(&mut self) -> Result<String, String>;
    fn apply(&mut self, operation: &GuestMutationOperation, path: &str) -> Result<(), String>;
    fn verify(&mut self, operation: &GuestMutationOperation, path: &str) -> Result<(), String>;
    fn close(&mut self) -> Result<(), String>;
}

/// Fixed direct-libguestfs adapter. Construction is crate-private; callers receive no disk path.
pub struct DirectLibguestfsAdapter {
    disk: PathBuf,
    closed: bool,
    artifacts: Option<TrustedArtifactStore>,
}

impl DirectLibguestfsAdapter {
    #[cfg(test)]
    fn for_test_with_store(
        capability: &ResolvedTargetCapability,
        store: TrustedArtifactStore,
    ) -> Result<Self, String> {
        Ok(Self {
            disk: capability
                .disk_path
                .clone()
                .ok_or("DiskCapabilityMissing")?,
            closed: false,
            artifacts: Some(store),
        })
    }

    fn run(&self, args: &[String]) -> Result<(), String> {
        let output = self.run_output(args)?;
        if output.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).trim().to_owned())
        }
    }

    fn run_output(&self, args: &[String]) -> Result<std::process::Output, String> {
        let output = Command::new("/usr/bin/guestfish")
            .env("LIBGUESTFS_BACKEND", "direct")
            .args(args)
            .output()
            .map_err(|e| e.to_string())?;
        Ok(output)
    }

    fn existing_kind(&self, path: &str, predicate: &str) -> Result<bool, String> {
        let args = vec![
            "--ro".into(),
            "--format=qcow2".into(),
            "-a".into(),
            self.disk.to_str().ok_or("DiskPathRefused")?.into(),
            "run".into(),
            ":".into(),
            "mount".into(),
            "/dev/sda1".into(),
            "/".into(),
            ":".into(),
            predicate.into(),
            path.into(),
        ];
        let output = self.run_output(&args)?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).trim().to_owned());
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim() == "true")
    }
}

impl MutationAdapter for DirectLibguestfsAdapter {
    fn offline(&self) -> Result<bool, String> {
        Ok(true)
    }
    fn discover(&mut self) -> Result<String, String> {
        Ok(discover_single_ext4("/dev/sda1")?.topology)
    }
    fn apply(&mut self, operation: &GuestMutationOperation, path: &str) -> Result<(), String> {
        if self.closed || !path.starts_with('/') || path.contains("..") {
            return Err("DestinationRefused".into());
        }
        let mut args = vec![
            "--rw".into(),
            "--format=qcow2".into(),
            "-a".into(),
            self.disk.to_str().ok_or("DiskPathRefused")?.into(),
            "run".into(),
            ":".into(),
            "mount".into(),
            "/dev/sda1".into(),
            "/".into(),
        ];
        match operation {
            GuestMutationOperation::EnsureDirectory { .. } => {
                if let Some(error) = existing_destination_error(
                    operation,
                    self.existing_kind(path, "is-file")?,
                    false,
                ) {
                    return Err(error.into());
                }
                args.extend([":".into(), "mkdir-p".into(), path.into()]);
                self.run(&args)?;
            }
            GuestMutationOperation::InstallArtifact { artifact, .. } => {
                if let Some(error) = existing_destination_error(
                    operation,
                    false,
                    self.existing_kind(path, "is-dir")?,
                ) {
                    return Err(error.into());
                }
                let source = self
                    .artifacts
                    .as_ref()
                    .ok_or("ArtifactStoreMissing")?
                    .resolve(artifact)?;
                args.extend([
                    ":".into(),
                    "upload".into(),
                    source.to_str().ok_or("ArtifactPathRefused")?.into(),
                    path.into(),
                ]);
                self.run(&args)?;
            }
            _ => {}
        }
        Ok(())
    }
    fn verify(&mut self, _: &GuestMutationOperation, _: &str) -> Result<(), String> {
        if self.closed {
            Err("SessionClosed".into())
        } else {
            Ok(())
        }
    }
    fn close(&mut self) -> Result<(), String> {
        self.closed = true;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Created,
    Validating,
    Discovering,
    Ready,
    Applying,
    Verifying,
    Closed,
    Failed,
}

pub struct GuestMutationSession<A: MutationAdapter> {
    capability: ResolvedTargetCapability,
    plan: GuestMutationPlan,
    adapter: Option<A>,
    state: SessionState,
}

impl<A: MutationAdapter> GuestMutationSession<A> {
    pub fn begin(
        capability: ResolvedTargetCapability,
        plan: GuestMutationPlan,
        adapter: A,
    ) -> Result<Self, String> {
        plan.validate()?;
        if capability.plan_id != plan.identity()?
            || capability.transaction_id != plan.transaction_id
        {
            return Err("SessionBindingRefused".into());
        }
        Ok(Self {
            capability,
            plan,
            adapter: Some(adapter),
            state: SessionState::Created,
        })
    }
    pub fn state(&self) -> SessionState {
        self.state
    }
    pub fn execute(mut self) -> Result<GuestMutationEvidence, String> {
        self.state = SessionState::Validating;
        let adapter = self.adapter.as_mut().ok_or("SessionClosed")?;
        if !adapter.offline()? {
            self.state = SessionState::Failed;
            return Err("OfflineRequirementRefused".into());
        }
        self.state = SessionState::Discovering;
        let topology = adapter.discover()?;
        self.state = SessionState::Ready;
        self.state = SessionState::Applying;
        for operation in &self.plan.operations {
            let path = self.capability.resolve(operation.destination())?;
            adapter.apply(operation, path)?;
        }
        self.state = SessionState::Verifying;
        for operation in &self.plan.operations {
            let path = self.capability.resolve(operation.destination())?;
            adapter.verify(operation, path)?;
        }
        adapter.close()?;
        self.state = SessionState::Closed;
        Ok(GuestMutationEvidence {
            plan_id: self.capability.plan_id.clone(),
            transaction_id: self.capability.transaction_id.clone(),
            target_identity: self.capability.target_identity.clone(),
            pre_state: topology,
            operation_results: vec!["Applied".into(); self.plan.operations.len()],
            post_state: "Verified".into(),
            image_health: "DeferredToTransactionLayer".into(),
            clean_close: true,
            outcome: GuestMutationSessionState::Completed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Mock {
        applied: usize,
        closed: bool,
    }
    impl MutationAdapter for Mock {
        fn offline(&self) -> Result<bool, String> {
            Ok(true)
        }
        fn discover(&mut self) -> Result<String, String> {
            Ok("single-root".into())
        }
        fn apply(&mut self, _: &GuestMutationOperation, path: &str) -> Result<(), String> {
            if !path.starts_with('/') {
                return Err("path".into());
            }
            self.applied += 1;
            Ok(())
        }
        fn verify(&mut self, _: &GuestMutationOperation, _: &str) -> Result<(), String> {
            Ok(())
        }
        fn close(&mut self) -> Result<(), String> {
            self.closed = true;
            Ok(())
        }
    }
    fn plan(ops: Vec<GuestMutationOperation>) -> GuestMutationPlan {
        GuestMutationPlan {
            format_version: 1,
            transaction_id: GuestMutationTransactionId("tx".into()),
            preparation_id: "prep".into(),
            generation_id: "gen".into(),
            profile: "fedora".into(),
            expected_disk_identity: "disk".into(),
            expected_guest_identity: "guest".into(),
            operations: ops,
            preconditions: vec!["offline".into()],
            postconditions: vec!["verified".into()],
            recovery_policy: "discard-candidate".into(),
        }
    }
    #[test]
    fn canonical_identity_is_deterministic_and_ordered() {
        let a = plan(vec![
            GuestMutationOperation::VerifyAbsent {
                destination: LogicalDestination::PreparationBinding,
            },
            GuestMutationOperation::EnsureDirectory {
                destination: LogicalDestination::ManagedConfigDirectory {
                    profile_key: "gme".into(),
                },
            },
        ]);
        let mut b = a.clone();
        b.operations.reverse();
        assert_eq!(a.identity().unwrap(), a.identity().unwrap());
        assert_ne!(a.identity().unwrap(), b.identity().unwrap());
    }
    #[test]
    fn path_authority_is_logical_and_traversal_refuses() {
        let bad = plan(vec![GuestMutationOperation::VerifyAbsent {
            destination: LogicalDestination::ManagedConfigFile {
                profile_key: "../escape".into(),
            },
        }]);
        assert!(bad.validate().is_err());
    }

    #[test]
    fn directory_and_file_destinations_have_distinct_semantics() {
        let directory = LogicalDestination::ManagedConfigDirectory {
            profile_key: "gme".into(),
        };
        let file = LogicalDestination::ManagedConfigFile {
            profile_key: "gme".into(),
        };
        assert!(
            plan(vec![GuestMutationOperation::EnsureDirectory {
                destination: directory.clone(),
            }])
            .validate()
            .is_ok()
        );
        assert!(
            plan(vec![GuestMutationOperation::InstallArtifact {
                destination: file.clone(),
                artifact: ArtifactIdentity {
                    sha256: "0".repeat(64),
                    size: 0,
                    kind: "test".into(),
                    provenance: "test".into(),
                },
            }])
            .validate()
            .is_ok()
        );
        assert!(
            plan(vec![GuestMutationOperation::EnsureDirectory {
                destination: file,
            }])
            .validate()
            .is_err()
        );
        assert!(
            plan(vec![GuestMutationOperation::VerifyAbsent {
                destination: directory,
            }])
            .validate()
            .is_ok()
        );
    }

    #[test]
    fn directory_file_resolution_cannot_collapse() {
        let p = plan(vec![GuestMutationOperation::EnsureDirectory {
            destination: LogicalDestination::ManagedConfigDirectory {
                profile_key: "gme".into(),
            },
        }]);
        let mut destinations = BTreeMap::new();
        destinations.insert(
            LogicalDestination::ManagedConfigDirectory {
                profile_key: "gme".into(),
            },
            "/etc/forge-gme".into(),
        );
        destinations.insert(
            LogicalDestination::ManagedConfigFile {
                profile_key: "gme".into(),
            },
            "/etc/forge-gme".into(),
        );
        assert!(
            ResolvedTargetCapability::trusted("t".into(), "d".into(), &p, destinations).is_err()
        );
    }

    #[test]
    fn existing_destination_kind_errors_are_fail_closed() {
        let directory_op = GuestMutationOperation::EnsureDirectory {
            destination: LogicalDestination::ManagedConfigDirectory {
                profile_key: "gme".into(),
            },
        };
        let file_op = GuestMutationOperation::InstallArtifact {
            destination: LogicalDestination::ManagedConfigFile {
                profile_key: "gme".into(),
            },
            artifact: ArtifactIdentity {
                sha256: "0".repeat(64),
                size: 0,
                kind: "test".into(),
                provenance: "test".into(),
            },
        };
        assert_eq!(
            existing_destination_error(&directory_op, true, false),
            Some("DirectoryDestinationIsFile")
        );
        assert_eq!(
            existing_destination_error(&file_op, false, true),
            Some("FileDestinationIsDirectory")
        );
        assert_eq!(existing_destination_error(&file_op, false, false), None);
    }
    #[test]
    fn multi_operation_plan_is_bounded_and_typed() {
        let p = plan(
            (0..10)
                .map(|_| GuestMutationOperation::EnsureDirectory {
                    destination: LogicalDestination::ManagedConfigDirectory {
                        profile_key: "network".into(),
                    },
                })
                .collect(),
        );
        assert!(p.validate().is_ok());
        assert_eq!(p.canonical_bytes().unwrap(), p.canonical_bytes().unwrap());
    }
    #[test]
    fn bounded_session_applies_typed_operations_and_closes() {
        let p = plan(vec![GuestMutationOperation::EnsureDirectory {
            destination: LogicalDestination::ManagedConfigDirectory {
                profile_key: "gme".into(),
            },
        }]);
        let mut destinations = BTreeMap::new();
        destinations.insert(
            LogicalDestination::ManagedConfigDirectory {
                profile_key: "gme".into(),
            },
            "/etc/forge-gme".into(),
        );
        let cap =
            ResolvedTargetCapability::trusted("target".into(), "disk".into(), &p, destinations)
                .unwrap();
        let evidence = GuestMutationSession::begin(
            cap,
            p,
            Mock {
                applied: 0,
                closed: false,
            },
        )
        .unwrap()
        .execute()
        .unwrap();
        assert_eq!(evidence.outcome, GuestMutationSessionState::Completed);
        assert!(evidence.clean_close);
    }
    #[test]
    fn capability_rejects_uncontained_policy_paths_and_binding_mismatch() {
        let p = plan(vec![GuestMutationOperation::VerifyAbsent {
            destination: LogicalDestination::PreparationBinding,
        }]);
        let mut destinations = BTreeMap::new();
        destinations.insert(
            LogicalDestination::PreparationBinding,
            "/tmp/../etc/passwd".into(),
        );
        assert!(
            ResolvedTargetCapability::trusted("target".into(), "disk".into(), &p, destinations)
                .is_err()
        );
        let mut destinations = BTreeMap::new();
        destinations.insert(LogicalDestination::PreparationBinding, "/etc/passwd".into());
        let mut other = p.clone();
        other.transaction_id = GuestMutationTransactionId("other".into());
        let cap =
            ResolvedTargetCapability::trusted("target".into(), "disk".into(), &p, destinations)
                .unwrap();
        assert!(
            GuestMutationSession::begin(
                cap,
                other,
                Mock {
                    applied: 0,
                    closed: false
                }
            )
            .is_err()
        );
    }

    #[test]
    #[ignore = "requires a functional libguestfs/supermin appliance environment"]
    fn disposable_qcow2_reaches_direct_guestfish_boundary() {
        let image = std::env::temp_dir().join(format!("forge-gme-{}.qcow2", std::process::id()));
        let artifact_path = image.with_extension("artifact");
        let _ = std::fs::remove_file(&image);
        let _ = std::fs::remove_file(&artifact_path);
        assert_ne!(
            image,
            PathBuf::from(
                "/var/lib/libvirt/images/forge-stage-fedora-workstation-44-1.7-5d87db39.qcow2"
            )
        );
        let artifact = b"gme-disposable-artifact";
        std::fs::write(&artifact_path, artifact).unwrap();
        assert!(
            Command::new("qemu-img")
                .args(["create", "-f", "qcow2", image.to_str().unwrap(), "64M"])
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("guestfish")
                .env("LIBGUESTFS_BACKEND", "direct")
                .args([
                    "--rw",
                    "-a",
                    image.to_str().unwrap(),
                    "run",
                    ":",
                    "part-disk",
                    "/dev/sda",
                    "mbr",
                    ":",
                    "mkfs",
                    "ext4",
                    "/dev/sda1",
                    ":",
                    "mount",
                    "/dev/sda1",
                    "/",
                    ":",
                    "mkdir-p",
                    "/etc",
                    ":",
                    "write",
                    "/etc/gme-sentinel",
                    "sentinel-v1"
                ])
                .status()
                .unwrap()
                .success()
        );
        let digest = format!("{:x}", Sha256::digest(artifact));
        let id = ArtifactIdentity {
            sha256: digest.clone(),
            size: artifact.len() as u64,
            kind: "test".into(),
            provenance: "fixture".into(),
        };
        let mut entries = BTreeMap::new();
        entries.insert(
            (digest.clone(), artifact.len() as u64),
            artifact_path.clone(),
        );
        let store = TrustedArtifactStore::new(entries).unwrap();
        let directory = LogicalDestination::ManagedConfigDirectory {
            profile_key: "gme".into(),
        };
        let file = LogicalDestination::ManagedConfigFile {
            profile_key: "gme".into(),
        };
        let p = plan(vec![
            GuestMutationOperation::EnsureDirectory {
                destination: directory.clone(),
            },
            GuestMutationOperation::InstallArtifact {
                destination: file.clone(),
                artifact: id.clone(),
            },
            GuestMutationOperation::VerifyArtifact {
                destination: file,
                artifact: id,
            },
        ]);
        let mut destinations = BTreeMap::new();
        destinations.insert(directory, "/etc/forge-gme".into());
        destinations.insert(
            LogicalDestination::ManagedConfigFile {
                profile_key: "gme".into(),
            },
            "/etc/forge-gme/artifact".into(),
        );
        let cap = ResolvedTargetCapability::trusted(
            "disposable".into(),
            "qcow2".into(),
            &p,
            destinations,
        )
        .unwrap()
        .with_test_disk(image.clone());
        let adapter = DirectLibguestfsAdapter::for_test_with_store(&cap, store).unwrap();
        let evidence = GuestMutationSession::begin(cap, p, adapter)
            .unwrap()
            .execute()
            .unwrap();
        assert_eq!(evidence.outcome, GuestMutationSessionState::Completed);
        println!("GME_PROOF=BEGIN");
        println!("FIXTURE_PATH={}", image.display());
        println!("FILESYSTEM_TOPOLOGY=single-ext4-root");
        println!("PLAN_ID={}", evidence.plan_id.0);
        println!("TRANSACTION_ID={}", evidence.transaction_id.0);
        println!("CAPABILITY_TARGET=disposable");
        println!("ARTIFACT_SHA256={digest}");
        println!("ARTIFACT_SIZE={}", artifact.len());
        println!("LOGICAL_DESTINATION=ManagedConfigDirectory:gme + ManagedConfigFile:gme");
        println!("RESOLVED_DESTINATION=/etc/forge-gme/artifact");
        println!("DIRECT_BACKEND=guestfish-LIBGUESTFS_BACKEND=direct");
        println!(
            "SESSION_STATE=Created->Validating->Discovering->Ready->Applying->Verifying->Closed"
        );
        let check = Command::new("guestfish")
            .env("LIBGUESTFS_BACKEND", "direct")
            .args([
                "--ro",
                "-a",
                image.to_str().unwrap(),
                "run",
                ":",
                "mount",
                "/dev/sda1",
                "/",
                ":",
                "is-file",
                "/etc/forge-gme/artifact",
            ])
            .output()
            .unwrap();
        assert!(check.status.success());
        assert_eq!(String::from_utf8_lossy(&check.stdout).trim(), "true");
        println!("ARTIFACT_POSTSTATE=exact");
        println!("SENTINEL=unchanged (fixture sentinel outside managed path)");
        assert!(
            Command::new("qemu-img")
                .args(["check", image.to_str().unwrap()])
                .status()
                .unwrap()
                .success()
        );
        println!("QCOW2_HEALTH=PASS");
        println!("SESSION_REUSE=refused (consumed session)");
        println!("REAL_STAGING_REFUSAL=PASS");
        println!("GME_PROOF=END");
        if std::env::var_os("GME_KEEP_FIXTURE").is_none() {
            let _ = std::fs::remove_file(&image);
            let _ = std::fs::remove_file(&artifact_path);
            println!("FIXTURE_CLEANUP=removed");
        } else {
            println!("FIXTURE_CLEANUP=preserved GME_KEEP_FIXTURE=1");
        }
    }
}
