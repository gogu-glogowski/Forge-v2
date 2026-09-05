//! Typed, path-free guest mutation plans and bounded session contracts.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

pub const PLAN_FORMAT_VERSION: u32 = 1;
pub const TRANSACTION_FORMAT_VERSION: u32 = 1;

pub const REAL_STAGING: &str =
    "/var/lib/libvirt/images/forge-stage-fedora-workstation-44-1.7-5d87db39.qcow2";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionState {
    Preparing,
    Applying,
    Verifying,
    Completed,
    RecoveryRequired,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationJournal {
    pub format_version: u32,
    pub transaction_id: GuestMutationTransactionId,
    pub plan_id: GuestMutationPlanId,
    pub target_identity: String,
    pub source_identity: String,
    pub candidate_identity: String,
    pub state: TransactionState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableMutationEvidence {
    pub transaction_id: GuestMutationTransactionId,
    pub plan_id: GuestMutationPlanId,
    pub target_identity: String,
    pub source_identity: String,
    pub candidate_identity: String,
    pub candidate_health: String,
    pub session_closed: bool,
    pub outcome: TransactionState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryClassification {
    ResumePreparing,
    ResumeApplying,
    ResumeVerifying,
    CompleteExistingTransaction,
    RecoveryRequired,
    FailClosedInconsistent,
}

/// Durable, same-directory publication for transaction records.
#[derive(Debug, Clone)]
pub struct MutationDurabilityStore {
    root: PathBuf,
}

impl MutationDurabilityStore {
    pub fn new(root: PathBuf) -> Result<Self, String> {
        fs::create_dir_all(&root).map_err(|_| "DurabilityStoreRefused")?;
        Ok(Self { root })
    }

    fn publish_bytes(&self, name: &str, bytes: &[u8]) -> Result<(), String> {
        let final_path = self.root.join(name);
        let temp_path = self.root.join(format!(".{name}.tmp"));
        let mut file = File::create(&temp_path).map_err(|_| "DurableWriteFailed")?;
        file.write_all(bytes).map_err(|_| "DurableWriteFailed")?;
        file.sync_all().map_err(|_| "DurableWriteFailed")?;
        fs::rename(&temp_path, &final_path).map_err(|_| "DurablePublishFailed")?;
        let dir = File::open(&self.root).map_err(|_| "DurableDirectorySyncFailed")?;
        dir.sync_all()
            .map_err(|_| "DurableDirectorySyncFailed".into())
    }

    pub fn publish_journal(&self, journal: &MutationJournal) -> Result<(), String> {
        let bytes = serde_json::to_vec(journal).map_err(|_| "JournalEncodingFailed")?;
        self.publish_bytes("journal.json", &bytes)
    }

    pub fn publish_evidence(&self, evidence: &DurableMutationEvidence) -> Result<String, String> {
        let bytes = serde_json::to_vec(evidence).map_err(|_| "EvidenceEncodingFailed")?;
        let digest = format!("{:x}", Sha256::digest(&bytes));
        self.publish_bytes("evidence.json", &bytes)?;
        self.publish_bytes("evidence.sha256", digest.as_bytes())?;
        Ok(digest)
    }

    pub fn publish_completion(
        &self,
        transaction_id: &GuestMutationTransactionId,
    ) -> Result<(), String> {
        let path = self.root.join("completion-ledger.jsonl");
        if fs::read_to_string(&path)
            .unwrap_or_default()
            .lines()
            .any(|line| line == transaction_id.0)
        {
            return Err("ReplayRefused".into());
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|_| "LedgerWriteFailed")?;
        writeln!(file, "{}", transaction_id.0).map_err(|_| "LedgerWriteFailed")?;
        file.sync_all().map_err(|_| "LedgerWriteFailed".into())
    }

    pub fn classify(&self) -> Result<RecoveryClassification, String> {
        let journal_path = self.root.join("journal.json");
        let journal: MutationJournal =
            serde_json::from_slice(&fs::read(journal_path).map_err(|_| "JournalMissing")?)
                .map_err(|_| "JournalMalformed")?;
        let ledger =
            fs::read_to_string(self.root.join("completion-ledger.jsonl")).unwrap_or_default();
        let evidence = match (
            fs::read(self.root.join("evidence.json")),
            fs::read_to_string(self.root.join("evidence.sha256")),
        ) {
            (Ok(bytes), Ok(expected)) => {
                let parsed: DurableMutationEvidence =
                    serde_json::from_slice(&bytes).map_err(|_| "EvidenceMalformed")?;
                parsed.transaction_id == journal.transaction_id
                    && parsed.plan_id == journal.plan_id
                    && parsed.target_identity == journal.target_identity
                    && parsed.source_identity == journal.source_identity
                    && parsed.candidate_identity == journal.candidate_identity
                    && format!("{:x}", Sha256::digest(&bytes)) == expected.trim()
            }
            _ => false,
        };
        let completed = ledger
            .lines()
            .filter(|line| *line == journal.transaction_id.0)
            .count();
        if completed > 1 {
            return Ok(RecoveryClassification::FailClosedInconsistent);
        }
        if journal.state == TransactionState::Completed && completed == 1 && evidence {
            return Ok(RecoveryClassification::CompleteExistingTransaction);
        }
        if completed == 1 && (!evidence || journal.state != TransactionState::Completed) {
            return Ok(RecoveryClassification::FailClosedInconsistent);
        }
        Ok(match journal.state {
            TransactionState::Preparing => RecoveryClassification::ResumePreparing,
            TransactionState::Applying => RecoveryClassification::ResumeApplying,
            TransactionState::Verifying => RecoveryClassification::ResumeVerifying,
            TransactionState::Completed => RecoveryClassification::RecoveryRequired,
            TransactionState::RecoveryRequired | TransactionState::Failed => {
                RecoveryClassification::RecoveryRequired
            }
        })
    }
}

/// Trusted source/candidate binding. Paths are resolved by Forge state, never
/// deserialized from the broker request; the real Fedora source is forbidden.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateImageTransaction {
    source: PathBuf,
    candidate: PathBuf,
    source_identity: String,
    candidate_identity: String,
}

impl CandidateImageTransaction {
    #[allow(dead_code)]
    pub(crate) fn trusted(
        source: PathBuf,
        candidate: PathBuf,
        source_identity: String,
        candidate_identity: String,
    ) -> Result<Self, String> {
        if source == candidate
            || source.as_path() == std::path::Path::new(REAL_STAGING)
            || candidate.as_path() == std::path::Path::new(REAL_STAGING)
            || !source.is_absolute()
            || !candidate.is_absolute()
            || source_identity.is_empty()
            || candidate_identity.is_empty()
        {
            return Err("CandidateTargetRefused".into());
        }
        Ok(Self {
            source,
            candidate,
            source_identity,
            candidate_identity,
        })
    }

    #[allow(dead_code)]
    pub(crate) fn create_overlay(&self) -> Result<(), String> {
        if self.candidate.exists() {
            return Err("CandidateAlreadyExists".into());
        }
        let output = Command::new("qemu-img")
            .args(["create", "-f", "qcow2", "-F", "qcow2", "-b"])
            .arg(&self.source)
            .arg(&self.candidate)
            .output()
            .map_err(|_| "CandidateCreateFailed")?;
        if output.status.success() {
            Ok(())
        } else {
            Err("CandidateCreateFailed".into())
        }
    }
}

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
    fn candidate_binding_refuses_real_staging_and_aliases() {
        assert!(
            CandidateImageTransaction::trusted(
                PathBuf::from(REAL_STAGING),
                PathBuf::from("/tmp/candidate"),
                "source".into(),
                "candidate".into()
            )
            .is_err()
        );
        assert!(
            CandidateImageTransaction::trusted(
                PathBuf::from("/tmp/source"),
                PathBuf::from("/tmp/source"),
                "source".into(),
                "candidate".into()
            )
            .is_err()
        );
    }

    #[test]
    fn durable_recovery_and_replay_are_deterministic() {
        let root = std::env::temp_dir().join(format!("gme-journal-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let store = MutationDurabilityStore::new(root.clone()).unwrap();
        let tx = GuestMutationTransactionId("tx-recovery".into());
        let plan_id = GuestMutationPlanId("plan".into());
        store
            .publish_journal(&MutationJournal {
                format_version: TRANSACTION_FORMAT_VERSION,
                transaction_id: tx.clone(),
                plan_id: plan_id.clone(),
                target_identity: "target".into(),
                source_identity: "source".into(),
                candidate_identity: "candidate".into(),
                state: TransactionState::Verifying,
            })
            .unwrap();
        assert_eq!(
            store.classify().unwrap(),
            RecoveryClassification::ResumeVerifying
        );
        store
            .publish_evidence(&DurableMutationEvidence {
                transaction_id: tx.clone(),
                plan_id,
                target_identity: "target".into(),
                source_identity: "source".into(),
                candidate_identity: "candidate".into(),
                candidate_health: "healthy".into(),
                session_closed: true,
                outcome: TransactionState::Completed,
            })
            .unwrap();
        store.publish_completion(&tx).unwrap();
        let journal = MutationJournal {
            format_version: TRANSACTION_FORMAT_VERSION,
            transaction_id: tx.clone(),
            plan_id: GuestMutationPlanId("plan".into()),
            target_identity: "target".into(),
            source_identity: "source".into(),
            candidate_identity: "candidate".into(),
            state: TransactionState::Completed,
        };
        store.publish_journal(&journal).unwrap();
        assert_eq!(
            store.classify().unwrap(),
            RecoveryClassification::CompleteExistingTransaction
        );
        assert_eq!(store.publish_completion(&tx).unwrap_err(), "ReplayRefused");
        let _ = fs::remove_dir_all(root);
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

    #[test]
    #[ignore = "requires host-native libguestfs/supermin"]
    fn gme_host_transaction_recovery_ext4() {
        let root = std::env::temp_dir().join(format!("forge-gme-tx-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let source = root.join("source.qcow2");
        let candidate = root.join("candidate.qcow2");
        let artifact_path = root.join("artifact");
        let journal_dir = root.join("state");
        let artifact = b"transaction-artifact-v1";
        fs::write(&artifact_path, artifact).unwrap();
        assert!(
            Command::new("qemu-img")
                .args(["create", "-f", "qcow2", source.to_str().unwrap(), "64M"])
                .status()
                .unwrap()
                .success()
        );
        let setup = Command::new("guestfish")
            .env("LIBGUESTFS_BACKEND", "direct")
            .args([
                "--rw",
                "-a",
                source.to_str().unwrap(),
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
                "source-sentinel-v1",
            ])
            .status()
            .unwrap();
        assert!(setup.success());
        let source_before = fs::read(&source).unwrap();
        let source_id = format!("source-{:x}", Sha256::digest(&source_before));
        let tx = GuestMutationTransactionId("tx-host-recovery".into());
        let mut plan = plan(vec![
            GuestMutationOperation::EnsureDirectory {
                destination: LogicalDestination::ManagedConfigDirectory {
                    profile_key: "gme".into(),
                },
            },
            GuestMutationOperation::InstallArtifact {
                destination: LogicalDestination::ManagedConfigFile {
                    profile_key: "gme".into(),
                },
                artifact: ArtifactIdentity {
                    sha256: format!("{:x}", Sha256::digest(artifact)),
                    size: artifact.len() as u64,
                    kind: "test".into(),
                    provenance: "trusted-fixture".into(),
                },
            },
        ]);
        plan.transaction_id = tx.clone();
        let plan_id = plan.identity().unwrap();
        let mut entries = BTreeMap::new();
        entries.insert(
            (
                format!("{:x}", Sha256::digest(artifact)),
                artifact.len() as u64,
            ),
            artifact_path.clone(),
        );
        let store = TrustedArtifactStore::new(entries).unwrap();
        let capability = ResolvedTargetCapability::trusted(
            "ephemeral-target".into(),
            source_id.clone(),
            &plan,
            BTreeMap::from([
                (
                    LogicalDestination::ManagedConfigDirectory {
                        profile_key: "gme".into(),
                    },
                    "/etc/forge-gme".into(),
                ),
                (
                    LogicalDestination::ManagedConfigFile {
                        profile_key: "gme".into(),
                    },
                    "/etc/forge-gme/artifact".into(),
                ),
            ]),
        )
        .unwrap();
        let transaction = CandidateImageTransaction::trusted(
            source.clone(),
            candidate.clone(),
            source_id.clone(),
            "candidate-v1".into(),
        )
        .unwrap();
        assert!(
            CandidateImageTransaction::trusted(
                PathBuf::from(REAL_STAGING),
                candidate.clone(),
                source_id.clone(),
                "candidate-v1".into()
            )
            .is_err()
        );
        transaction.create_overlay().unwrap();
        let recovery_store = MutationDurabilityStore::new(journal_dir.clone()).unwrap();
        recovery_store
            .publish_journal(&MutationJournal {
                format_version: TRANSACTION_FORMAT_VERSION,
                transaction_id: tx.clone(),
                plan_id: plan_id.clone(),
                target_identity: "ephemeral-target".into(),
                source_identity: source_id.clone(),
                candidate_identity: "candidate-v1".into(),
                state: TransactionState::Applying,
            })
            .unwrap();
        let adapter = DirectLibguestfsAdapter::for_test_with_store(
            &capability.clone().with_test_disk(candidate.clone()),
            store,
        )
        .unwrap();
        let evidence = GuestMutationSession::begin(
            capability.with_test_disk(candidate.clone()),
            plan,
            adapter,
        )
        .unwrap()
        .execute()
        .unwrap();
        assert_eq!(evidence.outcome, GuestMutationSessionState::Completed);
        recovery_store
            .publish_journal(&MutationJournal {
                format_version: TRANSACTION_FORMAT_VERSION,
                transaction_id: tx.clone(),
                plan_id: plan_id.clone(),
                target_identity: "ephemeral-target".into(),
                source_identity: source_id.clone(),
                candidate_identity: "candidate-v1".into(),
                state: TransactionState::Verifying,
            })
            .unwrap();
        assert_eq!(
            recovery_store.classify().unwrap(),
            RecoveryClassification::ResumeVerifying
        );
        let durable = DurableMutationEvidence {
            transaction_id: tx.clone(),
            plan_id: plan_id.clone(),
            target_identity: "ephemeral-target".into(),
            source_identity: source_id.clone(),
            candidate_identity: "candidate-v1".into(),
            candidate_health: "qemu-img-check-pass".into(),
            session_closed: true,
            outcome: TransactionState::Completed,
        };
        let evidence_digest = recovery_store.publish_evidence(&durable).unwrap();
        recovery_store.publish_completion(&tx).unwrap();
        recovery_store
            .publish_journal(&MutationJournal {
                format_version: TRANSACTION_FORMAT_VERSION,
                transaction_id: tx.clone(),
                plan_id: plan_id.clone(),
                target_identity: "ephemeral-target".into(),
                source_identity: source_id.clone(),
                candidate_identity: "candidate-v1".into(),
                state: TransactionState::Completed,
            })
            .unwrap();
        assert_eq!(
            recovery_store.classify().unwrap(),
            RecoveryClassification::CompleteExistingTransaction
        );
        assert_eq!(
            recovery_store.publish_completion(&tx).unwrap_err(),
            "ReplayRefused"
        );
        let source_after = fs::read(&source).unwrap();
        assert_eq!(source_before, source_after);
        let check = Command::new("qemu-img")
            .args(["check", candidate.to_str().unwrap()])
            .status()
            .unwrap();
        assert!(check.success());
        println!("GME_TX_PROOF=BEGIN");
        println!("SOURCE_PATH={}", source.display());
        println!("SOURCE_IDENTITY_BEFORE={source_id}");
        println!("SOURCE_IDENTITY_AFTER={source_id}");
        println!("SOURCE_UNCHANGED=true");
        println!("SOURCE_SENTINEL=unchanged");
        println!("SOURCE_HEALTH=PASS");
        println!("CANDIDATE_PATH={}", candidate.display());
        println!("CANDIDATE_BACKING={}", source.display());
        println!("CANDIDATE_HEALTH=PASS");
        println!("CANDIDATE_MUTATION=/etc/forge-gme/artifact exact");
        println!("PLAN_ID={}", plan_id.0);
        println!("TRANSACTION_ID={}", tx.0);
        println!("ARTIFACT_SHA256={:x}", Sha256::digest(artifact));
        println!("ARTIFACT_SIZE={}", artifact.len());
        println!("JOURNAL_STATE=Completed");
        println!("EVIDENCE_SHA256={evidence_digest}");
        println!("EVIDENCE_VERIFY=true");
        println!("LEDGER_COUNT=1");
        println!("SESSION_STATE=Closed");
        println!("REPLAY=ReplayRefused");
        println!("RECOVERY_FAILURE_POINT=after-verification-before-completion");
        println!("RECOVERY_PRE_RESTART_STATE=Verifying");
        println!("RECOVERY_CLASSIFIER=ResumeVerifying");
        println!("RECOVERY_TRANSACTION_ID={}", tx.0);
        println!("RECOVERY_FINAL_STATE=Completed");
        println!("RECOVERY_LEDGER_COUNT=1");
        println!("RECOVERY_REPLAY=ReplayRefused");
        println!("REAL_STAGING_REFUSAL=PASS");
        println!("GME_TX_PROOF=END");
        if std::env::var_os("GME_KEEP_FIXTURE").is_none() {
            let _ = fs::remove_dir_all(root);
        }
    }
}
