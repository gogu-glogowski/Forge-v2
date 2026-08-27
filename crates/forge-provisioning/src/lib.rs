//! Minimal, secret-free Fedora-Lab cloud-init and first-boot planning.

use forge_core::VmState;
use sha2::{Digest, Sha256};
use std::fmt;
use std::time::Duration;

pub const FORGE_PUBLIC_KEY_PATH: &str = ".ssh/forge_ed25519.pub";
pub const SEED_VOLUME: &str = "fedora-lab-seed.iso";
pub const OVERLAY_VOLUME: &str = "fedora-lab.prepare.qcow2";
pub const BASE_VOLUME: &str = "forge-base-fedora-44.qcow2";
pub const REBUILD_OVERLAY_VOLUME: &str = "fedora-lab.rebuild.qcow2";
pub const REBUILD_SEED_VOLUME: &str = "fedora-lab-rebuild-seed.iso";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerationVolumeStatus {
    pub name: String,
    pub path: String,
    pub exists: bool,
    pub capacity_bytes: Option<u64>,
    pub format: Option<String>,
    pub backing_path: Option<String>,
    pub referenced_by_domains: Vec<String>,
    pub backing_for_volumes: Vec<String>,
    pub ownership_marker: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FedoraLabLifecycleStatus {
    pub domain_state: VmState,
    pub domain_uuid: String,
    pub persistent: bool,
    pub autostart: bool,
    pub default_network: DefaultNetworkStatus,
    pub active_overlay_path: String,
    pub active_backing_path: Option<String>,
    pub active_seed_path: Option<String>,
    pub guest_agent_channel: bool,
    pub guest_agent_status: GuestAgentStatus,
    pub ip_addresses: Vec<String>,
    pub base: GenerationVolumeStatus,
    pub current_overlay: GenerationVolumeStatus,
    pub current_seed: GenerationVolumeStatus,
    pub legacy_overlay: GenerationVolumeStatus,
    pub legacy_seed: GenerationVolumeStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultNetworkStatus {
    Active,
    Inactive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupResourceKind {
    Overlay,
    Seed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupCandidate {
    pub kind: CleanupResourceKind,
    pub name: String,
    pub path: String,
    pub capacity_bytes: u64,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerationCleanupPlan {
    pub domain_state: VmState,
    pub safe: bool,
    pub requires_shutdown: bool,
    pub preserve: Vec<String>,
    pub candidates: Vec<CleanupCandidate>,
    pub retained_unproven: Vec<String>,
    pub preconditions: Vec<String>,
    pub future_steps: Vec<String>,
}

/// Plans cleanup of the known Prompt 08 legacy generation without mutation.
///
/// # Errors
/// Refuses to nominate any resource unless the active domain unambiguously
/// uses the rebuilt overlay/seed and the verified base relationship.
pub fn plan_generation_cleanup(
    status: &FedoraLabLifecycleStatus,
) -> Result<GenerationCleanupPlan, ProvisioningError> {
    if !status.persistent
        || status.active_overlay_path != status.current_overlay.path
        || status.active_backing_path.as_deref() != Some(status.base.path.as_str())
        || status.active_seed_path.as_deref() != Some(status.current_seed.path.as_str())
        || !status.base.exists
        || status.base.format.as_deref() != Some("qcow2")
        || status.base.capacity_bytes != Some(5 * 1024 * 1024 * 1024)
        || status.base.backing_path.is_some()
        || !status.current_overlay.exists
        || !status.current_seed.exists
        || !status.guest_agent_channel
    {
        return Err(ProvisioningError::CleanupUnsafe(
            "active Fedora-Lab generation cannot be proven from domain and storage metadata"
                .to_owned(),
        ));
    }
    let mut candidates = Vec::new();
    let mut retained_unproven = Vec::new();
    for (kind, volume) in [
        (CleanupResourceKind::Overlay, &status.legacy_overlay),
        (CleanupResourceKind::Seed, &status.legacy_seed),
    ] {
        if !volume.exists {
            continue;
        }
        let expected_shape = match kind {
            CleanupResourceKind::Overlay => {
                volume.format.as_deref() == Some("qcow2")
                    && volume.capacity_bytes == Some(64 * 1024 * 1024 * 1024)
                    && volume.backing_path.as_deref() == Some(status.base.path.as_str())
            }
            CleanupResourceKind::Seed => {
                matches!(volume.format.as_deref(), Some("raw" | "iso"))
                    && volume.capacity_bytes.is_some_and(|capacity| capacity > 0)
                    && volume.backing_path.is_none()
            }
        };
        let unreferenced = volume.path != status.active_overlay_path
            && Some(volume.path.as_str()) != status.active_seed_path.as_deref()
            && Some(volume.path.as_str()) != status.active_backing_path.as_deref()
            && volume.referenced_by_domains.is_empty()
            && volume.backing_for_volumes.is_empty();
        if expected_shape && unreferenced && volume.ownership_marker.is_some() {
            candidates.push(CleanupCandidate {
                kind,
                name: volume.name.clone(),
                path: volume.path.clone(),
                capacity_bytes: volume.capacity_bytes.unwrap_or(0),
                reason: "same-pool Forge-owned legacy resource with expected shape and no domain or backing references".to_owned(),
            });
        } else {
            retained_unproven.push(format!(
                "{}: retained; ownership is not proven by durable metadata (shape valid: {expected_shape}, unreferenced: {unreferenced})",
                volume.path
            ));
        }
    }
    Ok(GenerationCleanupPlan {
        domain_state: status.domain_state,
        safe: true,
        requires_shutdown: status.domain_state == VmState::Running,
        preserve: vec![
            format!("verified base volume: {}", status.base.path),
            format!("active writable overlay: {}", status.current_overlay.path),
            format!("active NoCloud seed: {}", status.current_seed.path),
            format!("persistent domain UUID: {}", status.domain_uuid),
        ],
        candidates,
        retained_unproven,
        preconditions: vec![
            "obtain separate explicit confirmation for real cleanup".to_owned(),
            "perform controlled shutdown and observe unambiguous shut off".to_owned(),
            "re-read persistent domain XML and all volume metadata".to_owned(),
            "prove no cleanup candidate is referenced by the domain or a backing chain".to_owned(),
        ],
        future_steps: vec![
            "delete only the exact legacy seed and overlay names listed as candidates".to_owned(),
            "verify active overlay, active seed, base, and domain definition remain unchanged"
                .to_owned(),
            "report partial cleanup without deleting any additional resource if one deletion fails"
                .to_owned(),
        ],
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleAction {
    Start,
    Shutdown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleActionPlan {
    pub action: LifecycleAction,
    pub current_state: VmState,
    pub idempotent_result: Option<LifecycleNoop>,
    pub timeout_seconds: u64,
    pub checks: Vec<String>,
    pub steps: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleNoop {
    AlreadyRunning,
    AlreadyShutoff,
}

/// Plans start or graceful shutdown after validating the managed Fedora-Lab topology.
///
/// # Errors
/// Rejects transient domains and storage/device configurations outside the
/// current Forge-managed Fedora-Lab generation.
pub fn plan_lifecycle_action(
    status: &FedoraLabLifecycleStatus,
    action: LifecycleAction,
) -> Result<LifecycleActionPlan, ProvisioningError> {
    if !status.persistent
        || !status.base.exists
        || status.base.format.as_deref() != Some("qcow2")
        || status.base.capacity_bytes != Some(5 * 1024 * 1024 * 1024)
        || status.base.backing_path.is_some()
        || !status.current_overlay.exists
        || !status.current_seed.exists
        || status.active_overlay_path != status.current_overlay.path
        || status.active_backing_path.as_deref() != Some(status.base.path.as_str())
        || status.active_seed_path.as_deref() != Some(status.current_seed.path.as_str())
        || status.current_overlay.format.as_deref() != Some("qcow2")
        || status.current_overlay.capacity_bytes != Some(64 * 1024 * 1024 * 1024)
        || status.current_overlay.backing_path.as_deref() != Some(status.base.path.as_str())
        || !matches!(status.current_seed.format.as_deref(), Some("raw" | "iso"))
        || !status.guest_agent_channel
        || (action == LifecycleAction::Start
            && status.default_network != DefaultNetworkStatus::Active)
    {
        return Err(ProvisioningError::LifecycleUnsafe(
            "persistent Fedora-Lab identity and active base/overlay/seed topology could not be proven"
                .to_owned(),
        ));
    }
    let (idempotent_result, timeout_seconds, steps) = match action {
        LifecycleAction::Start if status.domain_state == VmState::Running => (
            Some(LifecycleNoop::AlreadyRunning),
            60,
            vec!["return typed AlreadyRunning without calling libvirt create".to_owned()],
        ),
        LifecycleAction::Start if status.domain_state == VmState::Shutoff => (
            None,
            180,
            vec![
                "call libvirt create exactly once".to_owned(),
                "wait at most 60s for running".to_owned(),
                "run typed DHCP, QGA, and SSH/cloud-init observability with finite timeouts"
                    .to_owned(),
            ],
        ),
        LifecycleAction::Start => {
            return Err(ProvisioningError::LifecycleUnsafe(format!(
                "domain cannot be started from state {}",
                status.domain_state
            )));
        }
        LifecycleAction::Shutdown if status.domain_state == VmState::Shutoff => (
            Some(LifecycleNoop::AlreadyShutoff),
            120,
            vec!["return typed AlreadyShutoff without calling libvirt shutdown".to_owned()],
        ),
        LifecycleAction::Shutdown if status.domain_state == VmState::Running => (
            None,
            120,
            vec![
                "request graceful libvirt shutdown exactly once".to_owned(),
                "wait at most 120s for unambiguous shut off".to_owned(),
                "never fall back to destroy or force-off".to_owned(),
            ],
        ),
        LifecycleAction::Shutdown => {
            return Err(ProvisioningError::LifecycleUnsafe(format!(
                "domain cannot be gracefully shut down from state {}",
                status.domain_state
            )));
        }
    };
    let mut checks = vec![
        "persistent domain".to_owned(),
        "active qcow2 overlay has the trusted base backing".to_owned(),
        "active NoCloud seed is present".to_owned(),
        "declarative QGA channel is present".to_owned(),
    ];
    if action == LifecycleAction::Start {
        checks.push("libvirt default network is active".to_owned());
    }
    Ok(LifecycleActionPlan {
        action,
        current_state: status.domain_state,
        idempotent_result,
        timeout_seconds,
        checks,
        steps,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebuildEnvironment {
    pub domain_state: VmState,
    pub domain_uuid: String,
    pub domain_persistent: bool,
    pub current_overlay_path: String,
    pub current_backing_path: Option<String>,
    pub base_path: String,
    pub base_exists: bool,
    pub seed_path: String,
    pub seed_exists: bool,
    pub pool_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebuildPlan {
    pub environment: RebuildEnvironment,
    pub verified_source_path: String,
    pub public_key_path: String,
    pub new_overlay_path: String,
    pub new_overlay_capacity_bytes: u64,
    pub new_seed_path: String,
    pub new_seed_sha256: String,
    pub preserved_resources: Vec<String>,
    pub replaced_resources: Vec<String>,
    pub steps: Vec<String>,
    pub rollback_boundaries: Vec<String>,
    pub first_boot_timeouts: BootTimeouts,
    pub domain_xml: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RebuildContext {
    pub overlay_created: bool,
    pub seed_created: bool,
    pub domain_switched: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebuildResult {
    pub context: RebuildContext,
    pub first_boot: BootResult,
}

/// Builds a mutation-free, transactional Fedora-Lab rebuild plan.
///
/// # Errors
/// Rejects missing or mismatched durable prerequisites and unsafe XML.
pub fn plan_rebuild(
    environment: &RebuildEnvironment,
    verified_source_path: &str,
    public_key_path: &str,
    new_overlay_capacity_bytes: u64,
    new_seed_sha256: String,
    domain_xml: String,
) -> Result<RebuildPlan, ProvisioningError> {
    if !environment.domain_persistent {
        return Err(ProvisioningError::InvalidDomainXml);
    }
    if !environment.base_exists {
        return Err(ProvisioningError::MissingBase);
    }
    if environment.current_backing_path.as_deref() != Some(environment.base_path.as_str()) {
        return Err(ProvisioningError::BackingMismatch);
    }
    if !domain_xml.contains("org.qemu.guest_agent.0")
        || domain_xml.matches("org.qemu.guest_agent.0").count() != 1
        || domain_xml.contains("<filesystem")
        || domain_xml.contains("<hostdev")
    {
        return Err(ProvisioningError::InvalidDomainXml);
    }
    let new_overlay_path = format!("{}/{}", environment.pool_path, REBUILD_OVERLAY_VOLUME);
    let new_seed_path = format!("{}/{}", environment.pool_path, REBUILD_SEED_VOLUME);
    Ok(RebuildPlan {
        environment: environment.clone(),
        verified_source_path: verified_source_path.to_owned(),
        public_key_path: public_key_path.to_owned(),
        new_overlay_path: new_overlay_path.clone(),
        new_overlay_capacity_bytes,
        new_seed_path: new_seed_path.clone(),
        new_seed_sha256,
        preserved_resources: vec![
            format!("verified source image: {verified_source_path}"),
            format!("immutable libvirt base: {BASE_VOLUME}"),
            format!("dedicated SSH public key: {public_key_path}"),
        ],
        replaced_resources: vec![
            "writable Fedora-Lab overlay".to_owned(),
            "Fedora-Lab NoCloud seed".to_owned(),
            "persistent Fedora-Lab domain definition".to_owned(),
        ],
        steps: vec![
            format!("preserve the current overlay {}", environment.current_overlay_path),
            format!("create {new_overlay_path} from backing {}", environment.base_path),
            "validate new overlay format, capacity, and exact backing through libvirt".to_owned(),
            format!("create and validate matching NoCloud seed {new_seed_path}"),
            "validate the new DomainSpec and libvirt XML, including one guest-agent channel"
                .to_owned(),
            "request a controlled guest shutdown and wait for shut off".to_owned(),
            "re-check that the preserved overlay, base, seed, and domain identity are unchanged"
                .to_owned(),
            "switch the shut-off persistent domain to the validated new overlay and seed"
                .to_owned(),
            "verify persistent XML, vda, read-only seed CD-ROM, and guest-agent channel"
                .to_owned(),
            "perform first boot with typed, finite observations".to_owned(),
            "clean up the old overlay and seed only after explicit end-to-end success".to_owned(),
        ],
        rollback_boundaries: vec![
            "before domain switch: remove only newly created rebuild overlay/seed; old instance remains intact"
                .to_owned(),
            "after domain switch but before verified first boot: restore the preserved old domain definition; retain old overlay/seed"
                .to_owned(),
            "after verified first boot: do not roll back automatically; old resources remain until explicit cleanup"
                .to_owned(),
        ],
        first_boot_timeouts: BootTimeouts::default(),
        domain_xml,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudInitData {
    pub user_data: String,
    pub meta_data: String,
    pub content_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootEnvironment {
    pub domain_state: VmState,
    pub domain_xml: String,
    pub overlay_exists: bool,
    pub overlay_backing_path: Option<String>,
    pub base_exists: bool,
    pub network_active: bool,
    pub seed_path: String,
    pub seed_checksum: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedPlan {
    pub volume_name: String,
    pub volume_path: String,
    pub create: bool,
    pub data: CloudInitData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootPlan {
    pub domain_name: String,
    pub state: VmState,
    pub overlay_path: String,
    pub base_path: String,
    pub seed: SeedPlan,
    pub domain_xml: String,
    pub ip_discovery: Vec<String>,
    pub first_boot_steps: Vec<String>,
    pub ssh_private_key_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainBootStatus {
    Running,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhcpLeaseStatus {
    Available(String),
    TimedOut { after_seconds: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestAgentStatus {
    Available,
    Unavailable,
    TimedOut { after_seconds: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshStatus {
    NotChecked,
    Reachable,
    Authenticated,
    TimedOut { after_seconds: u64 },
    AuthenticationFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloudInitStatus {
    Unknown,
    Running,
    Done,
    Error(String),
    TimedOut { after_seconds: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootTimeouts {
    pub domain_running_seconds: u64,
    pub dhcp_lease_seconds: u64,
    pub guest_agent_seconds: u64,
    pub ssh_seconds: u64,
    pub cloud_init_seconds: u64,
}

impl Default for BootTimeouts {
    fn default() -> Self {
        Self {
            domain_running_seconds: 60,
            dhcp_lease_seconds: 120,
            guest_agent_seconds: 180,
            ssh_seconds: 30,
            cloud_init_seconds: 600,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootResult {
    pub domain: DomainBootStatus,
    pub dhcp_lease: DhcpLeaseStatus,
    pub guest_agent: GuestAgentStatus,
    pub ssh: SshStatus,
    pub cloud_init: CloudInitStatus,
    pub forge_user_confirmed: bool,
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshObservation {
    pub status: SshStatus,
    pub cloud_init: CloudInitStatus,
    pub forge_user_confirmed: bool,
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitStage {
    DomainRunning,
    DomainShutoff,
    DhcpLease,
    GuestAgent,
    Ssh,
    CloudInit,
}

impl fmt::Display for WaitStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DomainRunning => "domain running",
            Self::DomainShutoff => "domain shut off",
            Self::DhcpLease => "DHCP lease",
            Self::GuestAgent => "QEMU guest agent",
            Self::Ssh => "SSH",
            Self::CloudInit => "cloud-init",
        })
    }
}

pub trait BootBackend {
    /// # Errors
    /// Returns a read-only discovery error.
    fn inspect(&mut self) -> Result<BootEnvironment, ProvisioningError>;
    /// # Errors
    /// Returns an error when the `NoCloud` ISO volume cannot be created.
    fn create_seed(&mut self, seed: &SeedPlan) -> Result<(), ProvisioningError>;
    /// # Errors
    /// Returns an error when the persistent domain cannot be updated.
    fn redefine(&mut self, xml: &str) -> Result<(), ProvisioningError>;
    /// # Errors
    /// Returns an error when the domain cannot be started.
    fn start(&mut self) -> Result<(), ProvisioningError>;
    /// # Errors
    /// Returns an error when the domain does not reach running state.
    fn wait_running(&mut self, timeout: Duration) -> Result<(), ProvisioningError>;
    /// # Errors
    /// Returns a discovery error; absence of an address is represented by `None`.
    fn discover_ip(&mut self, timeout: Duration) -> Result<Option<String>, ProvisioningError>;
    /// # Errors
    /// Returns a guest-agent communication error.
    fn wait_guest_agent(
        &mut self,
        timeout: Duration,
    ) -> Result<GuestAgentStatus, ProvisioningError>;
    /// # Errors
    /// Returns an SSH process error. Reachability, authentication failure, and
    /// timeout are represented explicitly in `SshObservation`.
    fn observe_ssh(
        &mut self,
        ip_address: &str,
        private_key_path: &str,
        timeout: Duration,
    ) -> Result<SshObservation, ProvisioningError>;
}

pub trait RebuildBackend: BootBackend {
    /// # Errors
    /// Returns an error if rebuild names collide or the new overlay fails validation.
    fn create_rebuild_overlay(&mut self, plan: &RebuildPlan) -> Result<(), ProvisioningError>;
    /// # Errors
    /// Returns an error if the new seed is not present and valid.
    fn validate_rebuild_seed(&mut self, plan: &RebuildPlan) -> Result<(), ProvisioningError>;
    /// # Errors
    /// Returns an error or timeout if controlled shutdown does not reach shut off.
    fn shutdown_and_wait(&mut self, timeout: Duration) -> Result<(), ProvisioningError>;
    /// # Errors
    /// Returns an error if durable resources or domain identity changed before switch.
    fn verify_pre_switch(&mut self, expected: &RebuildEnvironment)
    -> Result<(), ProvisioningError>;
    /// # Errors
    /// Returns an error if redefine or persistent XML verification fails.
    fn switch_and_verify(&mut self, plan: &RebuildPlan) -> Result<(), ProvisioningError>;
    /// Deletes only newly named rebuild resources after failure before switch.
    fn rollback_new_resources(&mut self, context: &RebuildContext) -> Vec<String>;
}

/// Executes the approved rebuild without cleaning up the old generation.
///
/// # Errors
/// Before switch, errors include rollback failures. After switch, the partial
/// state is retained and no automatic repair is attempted.
pub fn execute_rebuild<B: RebuildBackend>(
    backend: &mut B,
    plan: &RebuildPlan,
    seed: &SeedPlan,
) -> Result<RebuildResult, ProvisioningError> {
    let mut context = RebuildContext::default();
    let before_switch: Result<(), ProvisioningError> = (|| {
        backend.create_rebuild_overlay(plan)?;
        context.overlay_created = true;
        backend.create_seed(seed)?;
        context.seed_created = true;
        backend.validate_rebuild_seed(plan)?;
        backend.shutdown_and_wait(Duration::from_secs(120))?;
        backend.verify_pre_switch(&plan.environment)?;
        Ok(())
    })();
    if let Err(primary) = before_switch {
        let rollback = backend.rollback_new_resources(&context);
        return Err(ProvisioningError::RebuildBeforeSwitch {
            primary: primary.to_string(),
            rollback,
        });
    }
    backend.switch_and_verify(plan)?;
    context.domain_switched = true;
    backend.start()?;
    let timeouts = plan.first_boot_timeouts;
    backend.wait_running(Duration::from_secs(timeouts.domain_running_seconds))?;
    let ip = backend.discover_ip(Duration::from_secs(timeouts.dhcp_lease_seconds))?;
    let guest_agent =
        backend.wait_guest_agent(Duration::from_secs(timeouts.guest_agent_seconds))?;
    let ssh = if let Some(ip) = ip.as_deref() {
        backend.observe_ssh(
            ip,
            plan.public_key_path.trim_end_matches(".pub"),
            Duration::from_secs(timeouts.ssh_seconds),
        )?
    } else {
        SshObservation {
            status: SshStatus::TimedOut {
                after_seconds: timeouts.dhcp_lease_seconds,
            },
            cloud_init: CloudInitStatus::Unknown,
            forge_user_confirmed: false,
            hostname: None,
        }
    };
    Ok(RebuildResult {
        context,
        first_boot: BootResult {
            domain: DomainBootStatus::Running,
            dhcp_lease: ip.map_or(
                DhcpLeaseStatus::TimedOut {
                    after_seconds: timeouts.dhcp_lease_seconds,
                },
                DhcpLeaseStatus::Available,
            ),
            guest_agent,
            ssh: ssh.status,
            cloud_init: ssh.cloud_init,
            forge_user_confirmed: ssh.forge_user_confirmed,
            hostname: ssh.hostname,
        },
    })
}

/// Executes an explicitly confirmed first-boot plan.
///
/// # Errors
/// Returns the first seed, redefine, start, state, or guest discovery error.
pub fn execute<B: BootBackend>(
    backend: &mut B,
    plan: &BootPlan,
) -> Result<BootResult, ProvisioningError> {
    execute_with_timeouts(backend, plan, BootTimeouts::default())
}

/// Executes first boot with explicit finite observation deadlines.
///
/// # Errors
/// Returns the first mutation, discovery, or domain-state error.
pub fn execute_with_timeouts<B: BootBackend>(
    backend: &mut B,
    plan: &BootPlan,
    timeouts: BootTimeouts,
) -> Result<BootResult, ProvisioningError> {
    if plan.seed.create {
        backend.create_seed(&plan.seed)?;
    }
    backend.redefine(&plan.domain_xml)?;
    backend.start()?;
    backend.wait_running(Duration::from_secs(timeouts.domain_running_seconds))?;
    let ip_address = backend.discover_ip(Duration::from_secs(timeouts.dhcp_lease_seconds))?;
    let guest_agent =
        backend.wait_guest_agent(Duration::from_secs(timeouts.guest_agent_seconds))?;
    let ssh = if let Some(ip) = ip_address.as_deref() {
        backend.observe_ssh(
            ip,
            &plan.ssh_private_key_path,
            Duration::from_secs(timeouts.ssh_seconds),
        )?
    } else {
        SshObservation {
            status: SshStatus::TimedOut {
                after_seconds: timeouts.dhcp_lease_seconds,
            },
            cloud_init: CloudInitStatus::Unknown,
            forge_user_confirmed: false,
            hostname: None,
        }
    };
    Ok(BootResult {
        domain: DomainBootStatus::Running,
        dhcp_lease: ip_address.map_or(
            DhcpLeaseStatus::TimedOut {
                after_seconds: timeouts.dhcp_lease_seconds,
            },
            DhcpLeaseStatus::Available,
        ),
        guest_agent,
        ssh: ssh.status,
        cloud_init: ssh.cloud_init,
        forge_user_confirmed: ssh.forge_user_confirmed,
        hostname: ssh.hostname,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvisioningError {
    MissingPublicKey(String),
    InvalidPublicKey,
    AlreadyRunning,
    DomainNotShutoff(VmState),
    MissingOverlay,
    MissingBase,
    BackingMismatch,
    InactiveNetwork,
    SeedConflict,
    InvalidDomainXml,
    Timeout {
        stage: WaitStage,
        after_seconds: u64,
    },
    RebuildBeforeSwitch {
        primary: String,
        rollback: Vec<String>,
    },
    CleanupUnsafe(String),
    LifecycleUnsafe(String),
    Backend(String),
}

impl fmt::Display for ProvisioningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPublicKey(path) => write!(
                formatter,
                "dedicated Forge SSH public key is missing: {path}; create it explicitly with: ssh-keygen -t ed25519 -f ~/.ssh/forge_ed25519"
            ),
            Self::InvalidPublicKey => formatter
                .write_str("Forge SSH key must be a single valid public key, never a private key"),
            Self::AlreadyRunning => formatter.write_str("Fedora-Lab is already running"),
            Self::DomainNotShutoff(state) => write!(
                formatter,
                "Fedora-Lab must be shut off, current state: {state}"
            ),
            Self::MissingOverlay => formatter.write_str("Fedora-Lab overlay volume is missing"),
            Self::MissingBase => formatter.write_str("Fedora base volume is missing"),
            Self::BackingMismatch => {
                formatter.write_str("Fedora-Lab overlay backing does not match the trusted base")
            }
            Self::InactiveNetwork => formatter.write_str("libvirt network default is inactive"),
            Self::SeedConflict => formatter
                .write_str("existing cloud-init seed does not match the requested configuration"),
            Self::InvalidDomainXml => {
                formatter.write_str("domain XML cannot safely accept a cloud-init seed")
            }
            Self::Timeout {
                stage,
                after_seconds,
            } => write!(
                formatter,
                "timed out waiting for {stage} after {after_seconds}s"
            ),
            Self::RebuildBeforeSwitch { primary, rollback } if rollback.is_empty() => {
                write!(
                    formatter,
                    "rebuild failed before switch: {primary}; rollback succeeded"
                )
            }
            Self::RebuildBeforeSwitch { primary, rollback } => write!(
                formatter,
                "rebuild failed before switch: {primary}; rollback failures: {}",
                rollback.join("; ")
            ),
            Self::CleanupUnsafe(reason) => write!(formatter, "cleanup is unsafe: {reason}"),
            Self::LifecycleUnsafe(reason) => {
                write!(formatter, "lifecycle action is unsafe: {reason}")
            }
            Self::Backend(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for ProvisioningError {}

#[must_use]
pub fn is_public_ssh_key(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.contains('\n')
        && !trimmed.contains("PRIVATE KEY")
        && matches!(
            trimmed.split_whitespace().next(),
            Some("ssh-ed25519" | "ssh-rsa" | "ecdsa-sha2-nistp256")
        )
        && trimmed.split_whitespace().nth(1).is_some()
}

/// Builds minimal Fedora cloud-init data containing only a public SSH key.
///
/// # Errors
/// Returns an error for malformed or private key material.
pub fn cloud_init(public_key: &str) -> Result<CloudInitData, ProvisioningError> {
    let key = public_key.trim();
    if !is_public_ssh_key(key) {
        return Err(ProvisioningError::InvalidPublicKey);
    }
    let user_data = format!(
        "#cloud-config\nhostname: fedora-lab\nmanage_etc_hosts: true\ndisable_root: true\nssh_pwauth: false\nusers:\n  - name: forge\n    shell: /bin/bash\n    lock_passwd: true\n    ssh_authorized_keys:\n      - {key}\npackages:\n  - qemu-guest-agent\nruncmd:\n  - [systemctl, enable, --now, qemu-guest-agent.service]\n"
    );
    let meta_data = "instance-id: forge-fedora-lab-v1\nlocal-hostname: fedora-lab\n".to_owned();
    let mut hasher = Sha256::new();
    hasher.update(user_data.as_bytes());
    hasher.update(meta_data.as_bytes());
    Ok(CloudInitData {
        user_data,
        meta_data,
        content_sha256: format!("{:x}", hasher.finalize()),
    })
}

/// Builds a boot plan after enforcing all read-only prerequisites.
///
/// # Errors
/// Returns a typed error for unsafe state, missing storage/network, or seed conflict.
pub fn plan(
    public_key: &str,
    private_key_path: &str,
    environment: &BootEnvironment,
    pool_path: &str,
) -> Result<BootPlan, ProvisioningError> {
    if environment.domain_state == VmState::Running {
        return Err(ProvisioningError::AlreadyRunning);
    }
    if environment.domain_state != VmState::Shutoff {
        return Err(ProvisioningError::DomainNotShutoff(
            environment.domain_state,
        ));
    }
    if !environment.overlay_exists {
        return Err(ProvisioningError::MissingOverlay);
    }
    if !environment.base_exists {
        return Err(ProvisioningError::MissingBase);
    }
    let base_path = format!("{pool_path}/{BASE_VOLUME}");
    let overlay_path = format!("{pool_path}/{OVERLAY_VOLUME}");
    if environment.overlay_backing_path.as_deref() != Some(base_path.as_str()) {
        return Err(ProvisioningError::BackingMismatch);
    }
    if !environment.network_active {
        return Err(ProvisioningError::InactiveNetwork);
    }
    let data = cloud_init(public_key)?;
    let create = match &environment.seed_checksum {
        None => true,
        Some(checksum) if checksum == &data.content_sha256 => false,
        Some(_) => return Err(ProvisioningError::SeedConflict),
    };
    let domain_xml = attach_seed(&environment.domain_xml, &environment.seed_path)?;
    Ok(BootPlan {
        domain_name: "fedora-lab".to_owned(),
        state: environment.domain_state,
        overlay_path,
        base_path,
        seed: SeedPlan {
            volume_name: SEED_VOLUME.to_owned(),
            volume_path: environment.seed_path.clone(),
            create,
            data,
        },
        domain_xml,
        ip_discovery: vec![
            "libvirt guest-agent interface addresses".to_owned(),
            "libvirt DHCP lease interface addresses".to_owned(),
        ],
        first_boot_steps: vec![
            "create or reuse matching NoCloud seed".to_owned(),
            "redefine shut-off domain with seed CD-ROM".to_owned(),
            "start domain once".to_owned(),
            "wait for running state".to_owned(),
            "use guest agent only for availability and interface telemetry".to_owned(),
            "authenticate SSH as forge with a finite timeout".to_owned(),
            "read cloud-init status, id, and hostname through SSH without sudo".to_owned(),
        ],
        ssh_private_key_path: private_key_path.to_owned(),
    })
}

/// Adds one read-only `NoCloud` CD-ROM to existing Fedora-Lab XML.
///
/// # Errors
/// Returns an error when the XML is unsafe or has no devices section.
pub fn attach_seed(xml: &str, seed_path: &str) -> Result<String, ProvisioningError> {
    if xml.contains(seed_path) {
        return Ok(xml.to_owned());
    }
    if !seed_path.starts_with('/')
        || xml.contains("fedora-lab-seed.iso")
        || xml.contains("<filesystem")
        || xml.contains("<hostdev")
    {
        return Err(ProvisioningError::InvalidDomainXml);
    }
    let marker = "  </devices>";
    let position = xml
        .find(marker)
        .ok_or(ProvisioningError::InvalidDomainXml)?;
    let device = format!(
        "    <disk type='file' device='cdrom'>\n      <driver name='qemu' type='raw'/>\n      <source file='{seed_path}'/>\n      <target dev='sda' bus='sata'/>\n      <readonly/>\n    </disk>\n"
    );
    let mut output = xml.to_owned();
    output.insert_str(position, &device);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest forge";

    #[derive(Default)]
    struct MockBackend {
        mutations: usize,
    }

    impl BootBackend for MockBackend {
        fn inspect(&mut self) -> Result<BootEnvironment, ProvisioningError> {
            Ok(environment())
        }
        fn create_seed(&mut self, _: &SeedPlan) -> Result<(), ProvisioningError> {
            self.mutations += 1;
            Ok(())
        }
        fn redefine(&mut self, _: &str) -> Result<(), ProvisioningError> {
            self.mutations += 1;
            Ok(())
        }
        fn start(&mut self) -> Result<(), ProvisioningError> {
            self.mutations += 1;
            Ok(())
        }
        fn wait_running(&mut self, _: Duration) -> Result<(), ProvisioningError> {
            Ok(())
        }
        fn discover_ip(&mut self, _: Duration) -> Result<Option<String>, ProvisioningError> {
            Ok(Some("192.0.2.2".to_owned()))
        }
        fn wait_guest_agent(&mut self, _: Duration) -> Result<GuestAgentStatus, ProvisioningError> {
            Ok(GuestAgentStatus::Available)
        }
        fn observe_ssh(
            &mut self,
            _: &str,
            _: &str,
            _: Duration,
        ) -> Result<SshObservation, ProvisioningError> {
            Ok(SshObservation {
                status: SshStatus::Authenticated,
                cloud_init: CloudInitStatus::Done,
                forge_user_confirmed: true,
                hostname: Some("fedora-lab".to_owned()),
            })
        }
    }

    fn environment() -> BootEnvironment {
        BootEnvironment {
            domain_state: VmState::Shutoff,
            domain_xml: "<domain><devices>\n  </devices></domain>".to_owned(),
            overlay_exists: true,
            overlay_backing_path: Some("/pool/forge-base-fedora-44.qcow2".to_owned()),
            base_exists: true,
            network_active: true,
            seed_path: "/pool/fedora-lab-seed.iso".to_owned(),
            seed_checksum: None,
        }
    }

    #[test]
    fn user_data_is_key_only_and_disables_root_password_login() {
        let data = cloud_init(KEY).unwrap();
        assert!(data.user_data.contains("name: forge"));
        assert!(data.user_data.contains("lock_passwd: true"));
        assert!(data.user_data.contains("ssh_pwauth: false"));
        assert!(data.user_data.contains("disable_root: true"));
        assert!(
            !data
                .user_data
                .lines()
                .any(|line| line.trim_start().starts_with("passwd:"))
        );
        assert!(!data.user_data.contains("plain_text_passwd"));
        assert!(!data.user_data.contains("PRIVATE KEY"));
        assert!(!data.user_data.contains("NOPASSWD"));
        assert!(
            !data
                .user_data
                .lines()
                .any(|line| line.trim_start().starts_with("sudo:"))
        );
        assert!(!data.user_data.contains("wheel"));
    }

    #[test]
    fn hostname_and_guest_agent_are_configured() {
        let data = cloud_init(KEY).unwrap();
        assert!(data.user_data.contains("hostname: fedora-lab"));
        assert!(data.user_data.contains("qemu-guest-agent"));
        assert!(data.meta_data.contains("local-hostname: fedora-lab"));
    }

    #[test]
    fn private_key_material_is_rejected() {
        assert_eq!(
            cloud_init("-----BEGIN PRIVATE KEY-----"),
            Err(ProvisioningError::InvalidPublicKey)
        );
    }

    #[test]
    fn safe_seed_plan_has_read_only_cdrom_without_mutation() {
        let environment = environment();
        let plan = plan(KEY, "/keys/forge_ed25519", &environment, "/pool").unwrap();
        assert!(plan.seed.create);
        assert!(plan.domain_xml.contains("device='cdrom'"));
        assert!(plan.domain_xml.contains("<readonly/>"));
        assert_eq!(environment.seed_checksum, None);
    }

    #[test]
    fn first_boot_success_requires_explicit_observations() {
        let plan = plan(KEY, "/keys/forge_ed25519", &environment(), "/pool").unwrap();
        let result = execute(&mut MockBackend::default(), &plan).unwrap();
        assert_eq!(result.domain, DomainBootStatus::Running);
        assert_eq!(
            result.dhcp_lease,
            DhcpLeaseStatus::Available("192.0.2.2".to_owned())
        );
        assert_eq!(result.guest_agent, GuestAgentStatus::Available);
        assert_eq!(result.ssh, SshStatus::Authenticated);
        assert_eq!(result.cloud_init, CloudInitStatus::Done);
        assert!(result.forge_user_confirmed);
        assert_eq!(result.hostname.as_deref(), Some("fedora-lab"));
    }

    #[test]
    fn all_first_boot_waits_have_finite_typed_timeouts() {
        let timeouts = BootTimeouts::default();
        assert!(timeouts.domain_running_seconds > 0);
        assert!(timeouts.dhcp_lease_seconds > 0);
        assert!(timeouts.guest_agent_seconds > 0);
        assert!(timeouts.ssh_seconds > 0);
        assert!(timeouts.cloud_init_seconds > 0);
        assert!(matches!(
            GuestAgentStatus::TimedOut { after_seconds: 5 },
            GuestAgentStatus::TimedOut { after_seconds: 5 }
        ));
        assert!(matches!(
            SshStatus::TimedOut { after_seconds: 5 },
            SshStatus::TimedOut { after_seconds: 5 }
        ));
        assert!(matches!(
            CloudInitStatus::TimedOut { after_seconds: 5 },
            CloudInitStatus::TimedOut { after_seconds: 5 }
        ));
    }

    #[test]
    fn rebuild_plan_preserves_old_instance_until_verified_switch() {
        let environment = RebuildEnvironment {
            domain_state: VmState::Running,
            domain_uuid: "11111111-2222-3333-4444-555555555555".to_owned(),
            domain_persistent: true,
            current_overlay_path: "/pool/fedora-lab.prepare.qcow2".to_owned(),
            current_backing_path: Some("/pool/forge-base-fedora-44.qcow2".to_owned()),
            base_path: "/pool/forge-base-fedora-44.qcow2".to_owned(),
            base_exists: true,
            seed_path: "/pool/fedora-lab-seed.iso".to_owned(),
            seed_exists: true,
            pool_path: "/pool".to_owned(),
        };
        let xml = "<domain><devices><disk/><channel type='unix'><target type='virtio' name='org.qemu.guest_agent.0'/></channel></devices></domain>";
        let plan = plan_rebuild(
            &environment,
            "/trusted/fedora.qcow2",
            "/home/user/.ssh/forge_ed25519.pub",
            64 * 1024 * 1024 * 1024,
            "seed-checksum".to_owned(),
            xml.to_owned(),
        )
        .unwrap();
        assert_eq!(plan.environment.domain_state, VmState::Running);
        assert_eq!(plan.new_overlay_path, "/pool/fedora-lab.rebuild.qcow2");
        assert_eq!(plan.new_seed_path, "/pool/fedora-lab-rebuild-seed.iso");
        assert_eq!(plan.new_seed_sha256, "seed-checksum");
        assert!(plan.steps[0].contains("preserve the current overlay"));
        assert!(plan.steps[5].contains("controlled guest shutdown"));
        assert!(plan.steps.last().unwrap().contains("only after"));
        assert!(plan.rollback_boundaries[0].contains("old instance remains intact"));
        assert_eq!(plan.domain_xml.matches("org.qemu.guest_agent.0").count(), 1);
    }

    fn lifecycle_status() -> FedoraLabLifecycleStatus {
        let volume = |name: &str, exists: bool, capacity| GenerationVolumeStatus {
            name: name.to_owned(),
            path: format!("/pool/{name}"),
            exists,
            capacity_bytes: capacity,
            format: Some(
                if matches!(name, SEED_VOLUME | REBUILD_SEED_VOLUME) {
                    "raw"
                } else {
                    "qcow2"
                }
                .to_owned(),
            ),
            backing_path: matches!(name, OVERLAY_VOLUME | REBUILD_OVERLAY_VOLUME)
                .then(|| format!("/pool/{BASE_VOLUME}")),
            referenced_by_domains: Vec::new(),
            backing_for_volumes: Vec::new(),
            ownership_marker: None,
        };
        FedoraLabLifecycleStatus {
            domain_state: VmState::Running,
            domain_uuid: "11111111-2222-3333-4444-555555555555".to_owned(),
            persistent: true,
            autostart: false,
            default_network: DefaultNetworkStatus::Active,
            active_overlay_path: "/pool/fedora-lab.rebuild.qcow2".to_owned(),
            active_backing_path: Some("/pool/forge-base-fedora-44.qcow2".to_owned()),
            active_seed_path: Some("/pool/fedora-lab-rebuild-seed.iso".to_owned()),
            guest_agent_channel: true,
            guest_agent_status: GuestAgentStatus::Available,
            ip_addresses: vec!["192.0.2.10".to_owned()],
            base: volume(BASE_VOLUME, true, Some(5 * 1024 * 1024 * 1024)),
            current_overlay: volume(REBUILD_OVERLAY_VOLUME, true, Some(64 * 1024 * 1024 * 1024)),
            current_seed: volume(REBUILD_SEED_VOLUME, true, Some(374_784)),
            legacy_overlay: volume(OVERLAY_VOLUME, true, Some(64 * 1024 * 1024 * 1024)),
            legacy_seed: volume(SEED_VOLUME, true, Some(374_784)),
        }
    }

    #[test]
    fn cleanup_retains_legacy_generation_without_durable_ownership() {
        let plan = plan_generation_cleanup(&lifecycle_status()).unwrap();
        assert!(plan.safe);
        assert!(plan.requires_shutdown);
        assert!(plan.candidates.is_empty());
        assert_eq!(plan.retained_unproven.len(), 2);
        assert!(
            plan.preserve
                .iter()
                .any(|resource| resource.contains(REBUILD_OVERLAY_VOLUME))
        );
        assert!(
            !plan
                .candidates
                .iter()
                .any(|candidate| candidate.name == BASE_VOLUME)
        );
    }

    #[test]
    fn cleanup_requires_shape_references_and_ownership_marker() {
        let mut status = lifecycle_status();
        status.legacy_overlay.ownership_marker = Some("forge-generation:v1".to_owned());
        status.legacy_seed.ownership_marker = Some("forge-generation:v1".to_owned());
        let plan = plan_generation_cleanup(&status).unwrap();
        assert_eq!(plan.candidates.len(), 2);

        status
            .legacy_overlay
            .referenced_by_domains
            .push("other-vm".to_owned());
        let plan = plan_generation_cleanup(&status).unwrap();
        assert_eq!(plan.candidates.len(), 1);
        assert_eq!(plan.candidates[0].kind, CleanupResourceKind::Seed);
    }

    #[test]
    fn lifecycle_start_is_idempotent_and_shutdown_is_graceful_only() {
        let status = lifecycle_status();
        let start = plan_lifecycle_action(&status, LifecycleAction::Start).unwrap();
        assert_eq!(start.idempotent_result, Some(LifecycleNoop::AlreadyRunning));
        let shutdown = plan_lifecycle_action(&status, LifecycleAction::Shutdown).unwrap();
        assert!(shutdown.idempotent_result.is_none());
        assert!(
            shutdown
                .steps
                .iter()
                .any(|step| step.contains("never fall back"))
        );
    }

    #[test]
    fn start_requires_network_but_shutdown_does_not() {
        let mut status = lifecycle_status();
        status.default_network = DefaultNetworkStatus::Inactive;
        assert!(matches!(
            plan_lifecycle_action(&status, LifecycleAction::Start),
            Err(ProvisioningError::LifecycleUnsafe(_))
        ));
        assert!(plan_lifecycle_action(&status, LifecycleAction::Shutdown).is_ok());
    }

    #[test]
    fn shutoff_start_preflight_accepts_storage_verified_backing() {
        let mut status = lifecycle_status();
        status.domain_state = VmState::Shutoff;
        let plan = plan_lifecycle_action(&status, LifecycleAction::Start).unwrap();
        assert!(plan.idempotent_result.is_none());
        assert!(
            plan.steps
                .iter()
                .any(|step| step.contains("create exactly once"))
        );
    }

    #[test]
    fn cleanup_is_denied_when_active_generation_is_ambiguous() {
        let mut status = lifecycle_status();
        status.active_overlay_path = status.legacy_overlay.path.clone();
        assert!(matches!(
            plan_generation_cleanup(&status),
            Err(ProvisioningError::CleanupUnsafe(_))
        ));
    }

    #[test]
    fn already_running_is_idempotently_denied() {
        let mut environment = environment();
        environment.domain_state = VmState::Running;
        assert_eq!(
            plan(KEY, "/keys/forge_ed25519", &environment, "/pool"),
            Err(ProvisioningError::AlreadyRunning)
        );
    }

    #[test]
    fn missing_storage_and_inactive_network_are_denied() {
        let mut environment = environment();
        environment.overlay_exists = false;
        assert_eq!(
            plan(KEY, "/keys/forge_ed25519", &environment, "/pool"),
            Err(ProvisioningError::MissingOverlay)
        );
        environment.overlay_exists = true;
        environment.base_exists = false;
        assert_eq!(
            plan(KEY, "/keys/forge_ed25519", &environment, "/pool"),
            Err(ProvisioningError::MissingBase)
        );
        environment.base_exists = true;
        environment.network_active = false;
        assert_eq!(
            plan(KEY, "/keys/forge_ed25519", &environment, "/pool"),
            Err(ProvisioningError::InactiveNetwork)
        );
    }

    #[test]
    fn matching_seed_is_reused() {
        let mut environment = environment();
        environment.seed_checksum = Some(cloud_init(KEY).unwrap().content_sha256);
        assert!(
            !plan(KEY, "/keys/forge_ed25519", &environment, "/pool")
                .unwrap()
                .seed
                .create
        );
    }

    #[test]
    fn dry_run_planning_has_zero_backend_mutation() {
        let mut backend = MockBackend::default();
        let environment = backend.inspect().unwrap();
        let _ = plan(KEY, "/keys/forge_ed25519", &environment, "/pool").unwrap();
        assert_eq!(backend.mutations, 0);
    }
}
