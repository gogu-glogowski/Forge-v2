//! Transactional preparation of a trusted Fedora base volume and VM overlay.

use crate::{DefinedDomain, DomainDefineError, StorageError, StoragePoolInfo, VolumeInfo};
use forge_core::{GuestProfileKind, VmProfile, VmResourcePlan, VmState};
use forge_domain::{DomainMetadata, DomainSpec};
use forge_images::{ImageMetadata, ImageStatus};
use std::fmt;

pub const FEDORA_BASE_VOLUME: &str = "forge-base-fedora-44.qcow2";
pub const FEDORA_PREPARE_OVERLAY: &str = "fedora-lab.prepare.qcow2";
pub const EMPTY_OVERLAY_ALLOCATION_LIMIT: u64 = 4 * 1024 * 1024;

#[derive(Clone, Copy)]
struct SourceDimensions {
    file_bytes: u64,
    capacity_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseImageVolume {
    pub name: String,
    pub path: String,
    pub imported_bytes: u64,
    pub capacity_bytes: u64,
    pub format: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayVolume {
    pub name: String,
    pub path: String,
    pub capacity_bytes: u64,
    pub allocation_bytes: u64,
    pub format: String,
    pub backing_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExistingDomainInfo {
    pub name: String,
    pub uuid: String,
    pub state: VmState,
    pub persistent: bool,
    pub autostart: bool,
    pub disk_path: String,
    pub matches_legacy_forge_policy: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImagePreparePlan {
    pub source: ImageMetadata,
    pub source_size_bytes: u64,
    pub source_capacity_bytes: u64,
    pub pool: StoragePoolInfo,
    pub base: BaseImageVolume,
    pub overlay: OverlayVolume,
    pub existing_domain: ExistingDomainInfo,
    pub existing_volume: OverlayVolume,
    pub migration_safe: bool,
    pub spec: DomainSpec,
    pub xml: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImagePrepareStep {
    BaseCreated,
    OverlayCreated,
    DomainRedefined,
    LegacyVolumeRemoved,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QemuImgDiagnostic {
    Verified,
    SkippedInsufficientPermissions,
    Unavailable,
    Warning(String),
}

impl fmt::Display for QemuImgDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Verified => formatter.write_str("Verified"),
            Self::SkippedInsufficientPermissions => {
                formatter.write_str("Skipped: insufficient direct file permissions")
            }
            Self::Unavailable => formatter.write_str("Skipped: qemu-img unavailable"),
            Self::Warning(message) => write!(formatter, "Warning: {message}"),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImagePrepareContext {
    pub completed: Vec<ImagePrepareStep>,
    pub qemu_img_diagnostics: Vec<(String, QemuImgDiagnostic)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImagePrepareResult {
    pub base: VolumeInfo,
    pub overlay: VolumeInfo,
    pub domain: DefinedDomain,
    pub context: ImagePrepareContext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImagePrepareError {
    UnsupportedProfile,
    SourceImageNotVerified,
    BaseAlreadyExists(String),
    DomainNotFound(String),
    DomainRunning(VmState),
    UnsafeExistingVolume(String),
    BackingStoreMismatch {
        expected: String,
        actual: Option<String>,
    },
    InvalidDomain(String),
    Backend(String),
    MigrationFailure {
        primary: String,
        rollback: Vec<String>,
    },
    PostRedefineFailure(String),
    CleanupRequired(String),
}

impl fmt::Display for ImagePrepareError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedProfile => formatter.write_str("only fedora-lab can be prepared"),
            Self::SourceImageNotVerified => {
                formatter.write_str("Fedora source image is not verified")
            }
            Self::BaseAlreadyExists(name) => {
                write!(formatter, "base volume already exists: {name}")
            }
            Self::DomainNotFound(name) => write!(formatter, "domain does not exist: {name}"),
            Self::DomainRunning(state) => {
                write!(formatter, "domain must be shut off, current state: {state}")
            }
            Self::UnsafeExistingVolume(reason) => write!(
                formatter,
                "existing Fedora-Lab volume is unsafe to migrate: {reason}"
            ),
            Self::BackingStoreMismatch { expected, actual } => write!(
                formatter,
                "overlay backing store mismatch: expected {expected}, got {}",
                actual.as_deref().unwrap_or("none")
            ),
            Self::InvalidDomain(error) | Self::Backend(error) => formatter.write_str(error),
            Self::MigrationFailure { primary, rollback } if rollback.is_empty() => {
                write!(formatter, "migration failed: {primary}; rollback succeeded")
            }
            Self::MigrationFailure { primary, rollback } => write!(
                formatter,
                "migration failed: {primary}; rollback failures: {}",
                rollback.join("; ")
            ),
            Self::PostRedefineFailure(error) => write!(
                formatter,
                "domain was redefined; resources were preserved after later failure: {error}"
            ),
            Self::CleanupRequired(error) => write!(
                formatter,
                "Fedora-Lab uses the prepared overlay, but legacy-volume cleanup failed: {error}"
            ),
        }
    }
}

impl std::error::Error for ImagePrepareError {}

impl From<StorageError> for ImagePrepareError {
    fn from(error: StorageError) -> Self {
        Self::Backend(error.to_string())
    }
}

pub trait ImagePrepareBackend {
    /// # Errors
    /// Returns a backend discovery error.
    fn inspect_pool(&mut self, name: &str) -> Result<Option<StoragePoolInfo>, ImagePrepareError>;
    /// # Errors
    /// Returns a backend discovery error.
    fn inspect_domain(
        &mut self,
        name: &str,
    ) -> Result<Option<ExistingDomainInfo>, ImagePrepareError>;
    /// # Errors
    /// Returns a backend discovery error.
    fn inspect_volume(
        &mut self,
        pool: &str,
        name: &str,
    ) -> Result<Option<OverlayVolume>, ImagePrepareError>;
    /// # Errors
    /// Returns an error when the source cannot be read or does not match.
    fn verify_source_checksum(
        &mut self,
        path: &str,
        expected: &str,
    ) -> Result<(), ImagePrepareError>;
    /// # Errors
    /// Returns best-effort read-only qemu-img diagnostics. This is never the
    /// source of truth for a system libvirt volume.
    fn diagnose_qcow2(
        &mut self,
        path: &str,
        capacity: u64,
        backing_path: Option<&str>,
    ) -> QemuImgDiagnostic;
    /// # Errors
    /// Returns an error when creation or stream upload fails.
    fn import_base(
        &mut self,
        pool: &str,
        base: &BaseImageVolume,
        source_path: &str,
    ) -> Result<VolumeInfo, ImagePrepareError>;
    /// # Errors
    /// Returns an error when the backed qcow2 volume cannot be created.
    fn create_overlay(
        &mut self,
        pool: &str,
        overlay: &OverlayVolume,
    ) -> Result<VolumeInfo, ImagePrepareError>;
    /// # Errors
    /// Returns an error when the selected volume cannot be deleted.
    fn delete_volume(&mut self, pool: &str, name: &str) -> Result<(), ImagePrepareError>;
    /// # Errors
    /// Distinguishes failure before redefine from inspection failure after redefine.
    fn redefine_domain(&mut self, xml: &str) -> Result<DefinedDomain, DomainDefineError>;
}

/// Builds a read-only, fully validated migration plan for the legacy Fedora-Lab disk.
///
/// # Errors
/// Returns a typed error when source trust, domain state, pool, or legacy-volume
/// provenance cannot be established without mutation.
pub fn plan_image_prepare<B: ImagePrepareBackend>(
    backend: &mut B,
    profile: &VmProfile,
    resources: &VmResourcePlan,
    source: &ImageMetadata,
    source_size_bytes: u64,
    source_capacity_bytes: u64,
) -> Result<ImagePreparePlan, ImagePrepareError> {
    if profile.kind != GuestProfileKind::FedoraLab || profile.id.as_str() != "fedora-lab" {
        return Err(ImagePrepareError::UnsupportedProfile);
    }
    let expected = source.expected_checksum.as_deref();
    if source.status != ImageStatus::Verified
        || expected.is_none()
        || source.actual_checksum.as_deref() != expected
        || source_size_bytes == 0
        || source_capacity_bytes < source_size_bytes
    {
        return Err(ImagePrepareError::SourceImageNotVerified);
    }
    let pool = backend.inspect_pool(crate::DEFAULT_POOL)?.ok_or_else(|| {
        ImagePrepareError::Backend("storage pool default does not exist".to_owned())
    })?;
    if !pool.active || !pool.target_path.starts_with('/') {
        return Err(ImagePrepareError::Backend(
            "storage pool default is not usable".to_owned(),
        ));
    }
    if backend
        .inspect_volume(&pool.name, FEDORA_BASE_VOLUME)?
        .is_some()
    {
        return Err(ImagePrepareError::BaseAlreadyExists(
            FEDORA_BASE_VOLUME.to_owned(),
        ));
    }
    if backend
        .inspect_volume(&pool.name, FEDORA_PREPARE_OVERLAY)?
        .is_some()
    {
        return Err(ImagePrepareError::UnsafeExistingVolume(
            "staging overlay already exists and will not be overwritten".to_owned(),
        ));
    }
    let domain = backend
        .inspect_domain("fedora-lab")?
        .ok_or_else(|| ImagePrepareError::DomainNotFound("fedora-lab".to_owned()))?;
    if domain.state != VmState::Shutoff {
        return Err(ImagePrepareError::DomainRunning(domain.state));
    }
    let overlay_path = format!(
        "{}/{}",
        pool.target_path.trim_end_matches('/'),
        crate::FEDORA_LAB_VOLUME
    );
    if !domain.persistent
        || domain.autostart
        || domain.disk_path != overlay_path
        || !domain.matches_legacy_forge_policy
    {
        return Err(ImagePrepareError::UnsafeExistingVolume(
            "domain provenance, persistence, autostart, or disk path does not match the Prompt 05 Forge lifecycle".to_owned(),
        ));
    }
    let existing = backend
        .inspect_volume(&pool.name, crate::FEDORA_LAB_VOLUME)?
        .ok_or_else(|| {
            ImagePrepareError::UnsafeExistingVolume("expected legacy volume is missing".to_owned())
        })?;
    if existing.path != overlay_path
        || existing.format != "qcow2"
        || existing.capacity_bytes != resources.disk_bytes
        || existing.allocation_bytes > EMPTY_OVERLAY_ALLOCATION_LIMIT
        || existing.backing_path.is_some()
    {
        return Err(ImagePrepareError::UnsafeExistingVolume(
            "volume is not the empty, unbacked, sparse qcow2 created by Prompt 05".to_owned(),
        ));
    }
    build_image_plan(
        profile,
        resources,
        source,
        SourceDimensions {
            file_bytes: source_size_bytes,
            capacity_bytes: source_capacity_bytes,
        },
        pool,
        domain,
        existing,
    )
}

fn build_image_plan(
    profile: &VmProfile,
    resources: &VmResourcePlan,
    source: &ImageMetadata,
    dimensions: SourceDimensions,
    pool: StoragePoolInfo,
    domain: ExistingDomainInfo,
    existing: OverlayVolume,
) -> Result<ImagePreparePlan, ImagePrepareError> {
    let base_path = format!(
        "{}/{}",
        pool.target_path.trim_end_matches('/'),
        FEDORA_BASE_VOLUME
    );
    let overlay_path = format!(
        "{}/{}",
        pool.target_path.trim_end_matches('/'),
        FEDORA_PREPARE_OVERLAY
    );
    let base = BaseImageVolume {
        name: FEDORA_BASE_VOLUME.to_owned(),
        path: base_path.clone(),
        imported_bytes: dimensions.file_bytes,
        capacity_bytes: dimensions.capacity_bytes,
        format: "qcow2".to_owned(),
    };
    let overlay = OverlayVolume {
        name: FEDORA_PREPARE_OVERLAY.to_owned(),
        path: overlay_path.clone(),
        capacity_bytes: resources.disk_bytes,
        allocation_bytes: 0,
        format: "qcow2".to_owned(),
        backing_path: Some(base_path.clone()),
    };
    let mut spec = forge_domain::fedora_lab_spec(
        profile,
        resources,
        DomainMetadata {
            name: profile.id.to_string(),
            disk_path: overlay_path,
        },
    )
    .map_err(|error| ImagePrepareError::InvalidDomain(error.to_string()))?;
    spec.uuid = Some(domain.uuid.clone());
    forge_domain::validate(&spec)
        .map_err(|error| ImagePrepareError::InvalidDomain(error.to_string()))?;
    let xml = forge_domain::render_xml(&spec)
        .map_err(|error| ImagePrepareError::InvalidDomain(error.to_string()))?;
    Ok(ImagePreparePlan {
        source: source.clone(),
        source_size_bytes: dimensions.file_bytes,
        source_capacity_bytes: dimensions.capacity_bytes,
        pool,
        base,
        overlay,
        existing_domain: domain,
        existing_volume: existing,
        migration_safe: true,
        spec,
        xml,
    })
}

/// Executes a confirmed plan and rolls back only resources changed in this run before redefine.
///
/// # Errors
/// Returns a typed mutation, backing verification, redefine, or combined rollback error.
pub fn execute_image_prepare<B: ImagePrepareBackend>(
    backend: &mut B,
    plan: &ImagePreparePlan,
) -> Result<ImagePrepareResult, ImagePrepareError> {
    let expected = plan
        .source
        .expected_checksum
        .as_deref()
        .ok_or(ImagePrepareError::SourceImageNotVerified)?;
    backend.verify_source_checksum(plan.source.local_path.to_string_lossy().as_ref(), expected)?;
    if backend
        .inspect_volume(&plan.pool.name, &plan.base.name)?
        .is_some()
    {
        return Err(ImagePrepareError::BaseAlreadyExists(plan.base.name.clone()));
    }
    let mut context = ImagePrepareContext::default();
    let base = backend.import_base(
        &plan.pool.name,
        &plan.base,
        plan.source.local_path.to_string_lossy().as_ref(),
    )?;
    context.completed.push(ImagePrepareStep::BaseCreated);
    validate_imported_base(backend, plan, &context)?;
    context.qemu_img_diagnostics.push((
        plan.base.path.clone(),
        backend.diagnose_qcow2(&plan.base.path, plan.base.capacity_bytes, None),
    ));
    let overlay = match backend.create_overlay(&plan.pool.name, &plan.overlay) {
        Ok(volume) => {
            context.completed.push(ImagePrepareStep::OverlayCreated);
            volume
        }
        Err(error) => {
            return Err(rollback_before_redefine(
                backend,
                plan,
                &context,
                error.to_string(),
            ));
        }
    };
    let inspected = match backend.inspect_volume(&plan.pool.name, &plan.overlay.name) {
        Ok(Some(volume)) => volume,
        Ok(None) => {
            return Err(rollback_before_redefine(
                backend,
                plan,
                &context,
                "new overlay disappeared".to_owned(),
            ));
        }
        Err(error) => {
            return Err(rollback_before_redefine(
                backend,
                plan,
                &context,
                error.to_string(),
            ));
        }
    };
    if inspected.path != plan.overlay.path
        || inspected.format != "qcow2"
        || inspected.capacity_bytes != plan.overlay.capacity_bytes
        || inspected.backing_path.as_deref() != Some(plan.base.path.as_str())
    {
        return Err(rollback_before_redefine(
            backend,
            plan,
            &context,
            format!(
                "overlay failed libvirt path/format/capacity/backing validation: path={}, format={}, capacity={}, backing={}",
                inspected.path,
                inspected.format,
                inspected.capacity_bytes,
                inspected.backing_path.as_deref().unwrap_or("none")
            ),
        ));
    }
    context.qemu_img_diagnostics.push((
        plan.overlay.path.clone(),
        backend.diagnose_qcow2(
            &plan.overlay.path,
            plan.overlay.capacity_bytes,
            Some(&plan.base.path),
        ),
    ));
    match backend.redefine_domain(&plan.xml) {
        Ok(domain) => {
            context.completed.push(ImagePrepareStep::DomainRedefined);
            confirm_switch_and_cleanup(backend, plan, base, overlay, domain, context)
        }
        Err(error) if error.domain_defined => Err(ImagePrepareError::PostRedefineFailure(
            error.error.to_string(),
        )),
        Err(error) => Err(rollback_before_redefine(
            backend,
            plan,
            &context,
            error.error.to_string(),
        )),
    }
}

fn confirm_switch_and_cleanup<B: ImagePrepareBackend>(
    backend: &mut B,
    plan: &ImagePreparePlan,
    base: VolumeInfo,
    overlay: VolumeInfo,
    domain: DefinedDomain,
    mut context: ImagePrepareContext,
) -> Result<ImagePrepareResult, ImagePrepareError> {
    let current = backend
        .inspect_domain(&plan.existing_domain.name)
        .map_err(|error| ImagePrepareError::PostRedefineFailure(error.to_string()))?
        .ok_or_else(|| {
            ImagePrepareError::PostRedefineFailure("domain disappeared after redefine".to_owned())
        })?;
    if current.state != VmState::Shutoff || current.disk_path != plan.overlay.path {
        return Err(ImagePrepareError::PostRedefineFailure(format!(
            "domain does not point to confirmed prepared overlay {}",
            plan.overlay.path
        )));
    }
    if let Err(error) = backend.delete_volume(&plan.pool.name, &plan.existing_volume.name) {
        return Err(ImagePrepareError::CleanupRequired(error.to_string()));
    }
    context
        .completed
        .push(ImagePrepareStep::LegacyVolumeRemoved);
    Ok(ImagePrepareResult {
        base,
        overlay,
        domain,
        context,
    })
}

fn validate_imported_base<B: ImagePrepareBackend>(
    backend: &mut B,
    plan: &ImagePreparePlan,
    context: &ImagePrepareContext,
) -> Result<(), ImagePrepareError> {
    let imported = match backend.inspect_volume(&plan.pool.name, &plan.base.name) {
        Ok(Some(volume)) => volume,
        Ok(None) => {
            return Err(rollback_before_redefine(
                backend,
                plan,
                context,
                "imported base volume disappeared".to_owned(),
            ));
        }
        Err(error) => {
            return Err(rollback_before_redefine(
                backend,
                plan,
                context,
                error.to_string(),
            ));
        }
    };
    if imported.path == plan.base.path
        && imported.format == "qcow2"
        && imported.capacity_bytes == plan.base.capacity_bytes
        && imported.backing_path.is_none()
    {
        Ok(())
    } else {
        Err(rollback_before_redefine(
            backend,
            plan,
            context,
            "imported base volume failed path/format/capacity validation".to_owned(),
        ))
    }
}

fn rollback_before_redefine<B: ImagePrepareBackend>(
    backend: &mut B,
    plan: &ImagePreparePlan,
    context: &ImagePrepareContext,
    primary: String,
) -> ImagePrepareError {
    let mut rollback = Vec::new();
    if context
        .completed
        .contains(&ImagePrepareStep::OverlayCreated)
        && let Err(error) = backend.delete_volume(&plan.pool.name, &plan.overlay.name)
    {
        rollback.push(error.to_string());
    }
    if context.completed.contains(&ImagePrepareStep::BaseCreated)
        && let Err(error) = backend.delete_volume(&plan.pool.name, &plan.base.name)
    {
        rollback.push(error.to_string());
    }
    ImagePrepareError::MigrationFailure { primary, rollback }
}

#[cfg(test)]
mod tests {
    use super::*;
    use forge_core::{GpuMode, NetworkMode, VmResources};
    use std::path::PathBuf;

    const GIB: u64 = 1024 * 1024 * 1024;

    #[derive(Clone, Copy, Default)]
    enum Failure {
        #[default]
        None,
        CreateOverlay,
        BackingMismatch,
        RedefineBefore,
        RedefineAfter,
        Cleanup,
        QemuPermission,
    }

    struct MockBackend {
        base_exists: bool,
        domain: ExistingDomainInfo,
        legacy: OverlayVolume,
        failure: Failure,
        new_overlay: bool,
        legacy_exists: bool,
        imports: usize,
        creates: usize,
        deletes: usize,
        redefines: usize,
    }

    impl Default for MockBackend {
        fn default() -> Self {
            Self {
                base_exists: false,
                domain: ExistingDomainInfo {
                    name: "fedora-lab".to_owned(),
                    uuid: "d4d014f9-f8fe-4f40-a893-106c23da0e32".to_owned(),
                    state: VmState::Shutoff,
                    persistent: true,
                    autostart: false,
                    disk_path: "/var/lib/libvirt/images/fedora-lab.qcow2".to_owned(),
                    matches_legacy_forge_policy: true,
                },
                legacy: OverlayVolume {
                    name: crate::FEDORA_LAB_VOLUME.to_owned(),
                    path: "/var/lib/libvirt/images/fedora-lab.qcow2".to_owned(),
                    capacity_bytes: 64 * GIB,
                    allocation_bytes: 196_608,
                    format: "qcow2".to_owned(),
                    backing_path: None,
                },
                failure: Failure::None,
                new_overlay: false,
                legacy_exists: true,
                imports: 0,
                creates: 0,
                deletes: 0,
                redefines: 0,
            }
        }
    }

    impl ImagePrepareBackend for MockBackend {
        fn inspect_pool(
            &mut self,
            name: &str,
        ) -> Result<Option<StoragePoolInfo>, ImagePrepareError> {
            Ok(Some(StoragePoolInfo {
                name: name.to_owned(),
                active: true,
                target_path: "/var/lib/libvirt/images".to_owned(),
                available_bytes: 100 * GIB,
            }))
        }
        fn inspect_domain(
            &mut self,
            _: &str,
        ) -> Result<Option<ExistingDomainInfo>, ImagePrepareError> {
            Ok(Some(self.domain.clone()))
        }
        fn inspect_volume(
            &mut self,
            _: &str,
            name: &str,
        ) -> Result<Option<OverlayVolume>, ImagePrepareError> {
            if name == FEDORA_BASE_VOLUME {
                return Ok(self.base_exists.then(|| OverlayVolume {
                    name: name.to_owned(),
                    path: format!("/var/lib/libvirt/images/{name}"),
                    capacity_bytes: 5 * GIB,
                    allocation_bytes: GIB,
                    format: "qcow2".to_owned(),
                    backing_path: None,
                }));
            }
            if name == FEDORA_PREPARE_OVERLAY && self.new_overlay {
                let mut overlay = self.legacy.clone();
                overlay.name = FEDORA_PREPARE_OVERLAY.to_owned();
                overlay.path = format!("/var/lib/libvirt/images/{FEDORA_PREPARE_OVERLAY}");
                overlay.backing_path = if matches!(self.failure, Failure::BackingMismatch) {
                    Some("/var/lib/libvirt/images/wrong.qcow2".to_owned())
                } else {
                    Some(format!("/var/lib/libvirt/images/{FEDORA_BASE_VOLUME}"))
                };
                Ok(Some(overlay))
            } else if name == FEDORA_PREPARE_OVERLAY {
                Ok(None)
            } else {
                Ok(self.legacy_exists.then(|| self.legacy.clone()))
            }
        }
        fn verify_source_checksum(&mut self, _: &str, _: &str) -> Result<(), ImagePrepareError> {
            Ok(())
        }
        fn diagnose_qcow2(&mut self, _: &str, _: u64, _: Option<&str>) -> QemuImgDiagnostic {
            if matches!(self.failure, Failure::QemuPermission) {
                QemuImgDiagnostic::SkippedInsufficientPermissions
            } else {
                QemuImgDiagnostic::Verified
            }
        }
        fn import_base(
            &mut self,
            _: &str,
            base: &BaseImageVolume,
            _: &str,
        ) -> Result<VolumeInfo, ImagePrepareError> {
            self.imports += 1;
            self.base_exists = true;
            Ok(VolumeInfo {
                name: base.name.clone(),
                path: base.path.clone(),
                capacity_bytes: base.capacity_bytes,
                allocation_bytes: base.imported_bytes,
            })
        }
        fn create_overlay(
            &mut self,
            _: &str,
            overlay: &OverlayVolume,
        ) -> Result<VolumeInfo, ImagePrepareError> {
            self.creates += 1;
            if matches!(self.failure, Failure::CreateOverlay) {
                return Err(ImagePrepareError::Backend("overlay error".to_owned()));
            }
            self.new_overlay = true;
            Ok(VolumeInfo {
                name: overlay.name.clone(),
                path: overlay.path.clone(),
                capacity_bytes: overlay.capacity_bytes,
                allocation_bytes: 0,
            })
        }
        fn delete_volume(&mut self, _: &str, name: &str) -> Result<(), ImagePrepareError> {
            self.deletes += 1;
            if name == FEDORA_BASE_VOLUME {
                self.base_exists = false;
            }
            if name == FEDORA_PREPARE_OVERLAY {
                self.new_overlay = false;
            }
            if name == crate::FEDORA_LAB_VOLUME {
                if matches!(self.failure, Failure::Cleanup) {
                    return Err(ImagePrepareError::Backend("cleanup error".to_owned()));
                }
                self.legacy_exists = false;
            }
            Ok(())
        }
        fn redefine_domain(&mut self, _: &str) -> Result<DefinedDomain, DomainDefineError> {
            self.redefines += 1;
            if !matches!(self.failure, Failure::RedefineBefore) {
                self.domain.disk_path = format!("/var/lib/libvirt/images/{FEDORA_PREPARE_OVERLAY}");
            }
            if matches!(
                self.failure,
                Failure::RedefineBefore | Failure::RedefineAfter
            ) {
                return Err(DomainDefineError {
                    error: StorageError::Backend("redefine error".to_owned()),
                    domain_defined: matches!(self.failure, Failure::RedefineAfter),
                });
            }
            Ok(DefinedDomain {
                uuid: "uuid".to_owned(),
                state: VmState::Shutoff,
            })
        }
    }

    fn profile() -> VmProfile {
        VmProfile {
            id: forge_core::ProfileId::new("fedora-lab").unwrap(),
            display_name: "Fedora Lab".to_owned(),
            kind: GuestProfileKind::FedoraLab,
            instance_kind: forge_core::InstanceKind::Lab,
            guest_family: forge_core::GuestFamily::Fedora,
            architecture: forge_core::GuestArchitecture::X86_64,
            firmware_machine: forge_core::FirmwareMachinePolicy::UefiQ35,
            resources: VmResources {
                cpu_ratio_per_mille: 250,
                min_vcpus: 1,
                max_vcpus: 4,
                memory_start_ratio_per_mille: 200,
                memory_max_ratio_per_mille: 250,
                min_memory_bytes: 2 * GIB,
                host_memory_reserve_bytes: 2 * GIB,
                disk_bytes: 64 * GIB,
            },
            image_source: forge_core::ImageSourcePolicy::FedoraCloudBase {
                release: "44".to_owned(),
            },
            image_verification: forge_core::ImageVerificationPolicy::SignedSha256Checksums,
            provisioning: forge_core::ProvisioningPolicy::NoCloud {
                default_user: "forge".to_owned(),
                guest_agent: true,
            },
            network_policy: forge_core::NetworkPolicy::DefaultNat,
            graphics_policy: forge_core::GraphicsPolicy::Virtual,
            persistence: forge_core::PersistencePolicy::Persistent,
        }
    }

    fn resources() -> VmResourcePlan {
        VmResourcePlan {
            vcpus: 4,
            memory_start_bytes: 6 * GIB,
            memory_max_bytes: 8 * GIB,
            disk_bytes: 64 * GIB,
            network: NetworkMode::Nat,
            gpu: GpuMode::Virtual,
        }
    }

    fn source(status: ImageStatus) -> ImageMetadata {
        ImageMetadata {
            distro: "Fedora Cloud Base".to_owned(),
            release: "44".to_owned(),
            architecture: "x86_64".to_owned(),
            source_url: "https://download.fedoraproject.org/image".to_owned(),
            local_path: PathBuf::from("/home/test/.local/share/forge/images/fedora.qcow2"),
            expected_checksum: Some("abc".to_owned()),
            actual_checksum: Some("abc".to_owned()),
            verified_at_unix_seconds: Some(1),
            status,
        }
    }

    fn plan(backend: &mut MockBackend) -> Result<ImagePreparePlan, ImagePrepareError> {
        plan_image_prepare(
            backend,
            &profile(),
            &resources(),
            &source(ImageStatus::Verified),
            600 * 1024 * 1024,
            5 * GIB,
        )
    }

    #[test]
    fn source_image_not_verified_is_denied() {
        let mut backend = MockBackend::default();
        assert_eq!(
            plan_image_prepare(
                &mut backend,
                &profile(),
                &resources(),
                &source(ImageStatus::Unverified),
                1,
                5 * GIB,
            ),
            Err(ImagePrepareError::SourceImageNotVerified)
        );
    }

    #[test]
    fn existing_base_volume_is_never_overwritten() {
        let mut backend = MockBackend {
            base_exists: true,
            ..Default::default()
        };
        assert!(matches!(
            plan(&mut backend),
            Err(ImagePrepareError::BaseAlreadyExists(_))
        ));
    }

    #[test]
    fn running_domain_is_denied() {
        let mut backend = MockBackend::default();
        backend.domain.state = VmState::Running;
        assert!(matches!(
            plan(&mut backend),
            Err(ImagePrepareError::DomainRunning(VmState::Running))
        ));
    }

    #[test]
    fn unsafe_existing_volume_is_denied() {
        let mut backend = MockBackend::default();
        backend.legacy.allocation_bytes = 5 * GIB;
        assert!(matches!(
            plan(&mut backend),
            Err(ImagePrepareError::UnsafeExistingVolume(_))
        ));
    }

    #[test]
    fn safe_plan_has_correct_backing_and_no_mutation() {
        let mut backend = MockBackend::default();
        let plan = plan(&mut backend).unwrap();
        assert!(plan.migration_safe);
        assert_eq!(
            plan.overlay.backing_path.as_deref(),
            Some(plan.base.path.as_str())
        );
        assert!(plan.xml.contains(FEDORA_PREPARE_OVERLAY));
        assert!(backend.legacy_exists);
        assert_eq!(
            (
                backend.imports,
                backend.creates,
                backend.deletes,
                backend.redefines
            ),
            (0, 0, 0, 0)
        );
    }

    #[test]
    fn failure_before_redefine_rolls_back_overlay_and_base() {
        let mut backend = MockBackend {
            failure: Failure::RedefineBefore,
            ..Default::default()
        };
        let plan = plan(&mut backend).unwrap();
        assert!(matches!(
            execute_image_prepare(&mut backend, &plan),
            Err(ImagePrepareError::MigrationFailure { .. })
        ));
        assert_eq!(backend.redefines, 1);
        assert!(backend.legacy_exists);
        assert!(!backend.new_overlay);
        assert!(!backend.base_exists);
    }

    #[test]
    fn overlay_creation_failure_leaves_legacy_volume_untouched() {
        let mut backend = MockBackend {
            failure: Failure::CreateOverlay,
            ..Default::default()
        };
        let plan = plan(&mut backend).unwrap();
        assert!(matches!(
            execute_image_prepare(&mut backend, &plan),
            Err(ImagePrepareError::MigrationFailure { .. })
        ));
        assert_eq!(backend.redefines, 0);
        assert!(backend.legacy_exists);
        assert!(!backend.new_overlay);
        assert!(!backend.base_exists);
    }

    #[test]
    fn backing_mismatch_is_denied_and_rolled_back() {
        let mut backend = MockBackend {
            failure: Failure::BackingMismatch,
            ..Default::default()
        };
        let plan = plan(&mut backend).unwrap();
        assert!(matches!(
            execute_image_prepare(&mut backend, &plan),
            Err(ImagePrepareError::MigrationFailure { .. })
        ));
        assert_eq!(backend.redefines, 0);
        assert!(backend.legacy_exists);
        assert!(!backend.new_overlay);
        assert!(!backend.base_exists);
    }

    #[test]
    fn resources_are_protected_after_successful_redefine() {
        let mut backend = MockBackend {
            failure: Failure::RedefineAfter,
            ..Default::default()
        };
        let plan = plan(&mut backend).unwrap();
        assert!(matches!(
            execute_image_prepare(&mut backend, &plan),
            Err(ImagePrepareError::PostRedefineFailure(_))
        ));
        assert!(backend.base_exists);
        assert!(backend.new_overlay);
        assert!(backend.legacy_exists);
    }

    #[test]
    fn cleanup_failure_reports_partial_success_without_rollback() {
        let mut backend = MockBackend {
            failure: Failure::Cleanup,
            ..Default::default()
        };
        let plan = plan(&mut backend).unwrap();
        assert!(matches!(
            execute_image_prepare(&mut backend, &plan),
            Err(ImagePrepareError::CleanupRequired(_))
        ));
        assert!(backend.base_exists);
        assert!(backend.new_overlay);
        assert!(backend.legacy_exists);
        assert_eq!(
            backend.domain.disk_path,
            format!("/var/lib/libvirt/images/{FEDORA_PREPARE_OVERLAY}")
        );
    }

    #[test]
    fn qemu_img_permission_denied_is_diagnostic_not_rollback() {
        let mut backend = MockBackend {
            failure: Failure::QemuPermission,
            ..Default::default()
        };
        let plan = plan(&mut backend).unwrap();
        let result = execute_image_prepare(&mut backend, &plan).unwrap();
        assert_eq!(
            result.context.qemu_img_diagnostics,
            vec![
                (
                    plan.base.path.clone(),
                    QemuImgDiagnostic::SkippedInsufficientPermissions
                ),
                (
                    plan.overlay.path.clone(),
                    QemuImgDiagnostic::SkippedInsufficientPermissions
                )
            ]
        );
        assert!(!backend.legacy_exists);
        assert!(backend.new_overlay);
    }
}
