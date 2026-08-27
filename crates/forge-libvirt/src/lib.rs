//! Read-only adapter for the local libvirt API.

use forge_core::{DomainSummary, HostCapabilities, LibvirtInfo, VmState};
use serde::Deserialize;
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::process::Command;
use virt::connect::Connect;
use virt::domain::Domain;
use virt::error::{Error as VirtError, ErrorNumber};
use virt::storage_pool::StoragePool;
use virt::storage_vol::StorageVol;
use virt::stream::Stream;
use virt::sys;

pub const LOCAL_QEMU_URI: &str = "qemu:///system";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LibvirtError {
    Connection { uri: String, message: String },
    Query { operation: String, message: String },
    UnsupportedDomainState(u32),
    Mapping { field: String, message: String },
}

impl fmt::Display for LibvirtError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connection { uri, message } => {
                write!(formatter, "cannot connect to libvirt at {uri}: {message}")
            }
            Self::Query { operation, message } => {
                write!(formatter, "libvirt query {operation} failed: {message}")
            }
            Self::UnsupportedDomainState(state) => {
                write!(formatter, "unsupported libvirt domain state: {state}")
            }
            Self::Mapping { field, message } => {
                write!(formatter, "cannot map libvirt field {field}: {message}")
            }
        }
    }
}

impl std::error::Error for LibvirtError {}

/// Discovers the system libvirt/QEMU connection using read-only API calls.
///
/// # Errors
///
/// Returns a structured integration error when connecting, querying libvirt,
/// or mapping a domain state fails.
pub fn discover_local() -> Result<LibvirtInfo, LibvirtError> {
    discover(LOCAL_QEMU_URI)
}

/// Discovers a libvirt URI using an explicitly read-only connection.
///
/// # Errors
///
/// Returns a structured integration error when connecting, querying libvirt,
/// or mapping a domain state fails.
pub fn discover(uri: &str) -> Result<LibvirtInfo, LibvirtError> {
    let connection =
        Connect::open_read_only(Some(uri)).map_err(|error| LibvirtError::Connection {
            uri: uri.to_owned(),
            message: error.to_string(),
        })?;

    let active_uri = query("get URI", connection.get_uri())?;
    let libvirt_version =
        format_version(query("get libvirt version", connection.get_lib_version())?);
    let hypervisor_version = format_version(query(
        "get hypervisor version",
        connection.get_hyp_version(),
    )?);
    let hypervisor_type = query("get hypervisor type", connection.get_type())?;
    let alive = query("check connection", connection.is_alive())?;
    let node = query("get node capabilities", connection.get_node_info())?;
    let memory_bytes = node
        .memory
        .checked_mul(1024)
        .ok_or_else(|| LibvirtError::Mapping {
            field: "node memory".to_owned(),
            message: "KiB to bytes conversion overflowed".to_owned(),
        })?;
    let domains = query("list all domains", connection.list_all_domains(0))?
        .iter()
        .map(domain_summary)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(LibvirtInfo {
        uri: active_uri,
        libvirt_version,
        hypervisor_version,
        hypervisor_type,
        alive,
        capabilities: HostCapabilities {
            cpu_model: node.model,
            logical_cpus: node.cpus,
            memory_bytes,
        },
        domains: sorted_domains(domains),
    })
}

fn domain_summary(domain: &Domain) -> Result<DomainSummary, LibvirtError> {
    let name = query("get domain name", domain.get_name())?;
    let uuid = query("get domain UUID", domain.get_uuid_string())?;
    let (raw_state, _) = query("get domain state", domain.get_state())?;
    let persistent = query("get domain persistence", domain.is_persistent())?;
    Ok(DomainSummary {
        name,
        uuid,
        state: map_domain_state(raw_state)?,
        persistent,
    })
}

fn query<T>(operation: &str, result: Result<T, VirtError>) -> Result<T, LibvirtError> {
    result.map_err(|error| LibvirtError::Query {
        operation: operation.to_owned(),
        message: error.to_string(),
    })
}

/// Maps libvirt state constants to stable Forge domain values.
///
/// # Errors
///
/// Returns `UnsupportedDomainState` when a newer or invalid raw value is not
/// represented by the binding known to this adapter.
pub fn map_domain_state(state: sys::virDomainState) -> Result<VmState, LibvirtError> {
    match state {
        sys::VIR_DOMAIN_NOSTATE => Ok(VmState::Unknown),
        sys::VIR_DOMAIN_RUNNING | sys::VIR_DOMAIN_BLOCKED => Ok(VmState::Running),
        sys::VIR_DOMAIN_PAUSED | sys::VIR_DOMAIN_PMSUSPENDED => Ok(VmState::Paused),
        sys::VIR_DOMAIN_SHUTDOWN | sys::VIR_DOMAIN_SHUTOFF => Ok(VmState::Shutoff),
        sys::VIR_DOMAIN_CRASHED => Ok(VmState::Crashed),
        other => Err(LibvirtError::UnsupportedDomainState(other)),
    }
}

#[must_use]
pub fn sorted_domains(mut domains: Vec<DomainSummary>) -> Vec<DomainSummary> {
    domains.sort_by(|left, right| {
        left.name
            .to_lowercase()
            .cmp(&right.name.to_lowercase())
            .then_with(|| left.uuid.cmp(&right.uuid))
    });
    domains
}

#[must_use]
pub fn format_version(version: u32) -> String {
    let major = version / 1_000_000;
    let minor = version / 1_000 % 1_000;
    let release = version % 1_000;
    format!("{major}.{minor}.{release}")
}

pub struct LibvirtDefineBackend {
    connection: Connect,
}

impl LibvirtDefineBackend {
    /// Opens the local system libvirt connection used by an explicitly
    /// confirmed define operation.
    ///
    /// # Errors
    ///
    /// Returns a connection error when system libvirt is unavailable.
    pub fn connect_local() -> Result<Self, LibvirtError> {
        Connect::open(Some(LOCAL_QEMU_URI))
            .map(|connection| Self { connection })
            .map_err(|error| LibvirtError::Connection {
                uri: LOCAL_QEMU_URI.to_owned(),
                message: error.to_string(),
            })
    }

    fn pool(&self, name: &str) -> Result<StoragePool, forge_storage::StorageError> {
        StoragePool::lookup_by_name(&self.connection, name).map_err(storage_backend_error)
    }
}

impl forge_storage::DefineBackend for LibvirtDefineBackend {
    fn inspect_pool(
        &mut self,
        name: &str,
    ) -> Result<Option<forge_storage::StoragePoolInfo>, forge_storage::StorageError> {
        let pool = match StoragePool::lookup_by_name(&self.connection, name) {
            Ok(pool) => pool,
            Err(error) if error.code() == ErrorNumber::NoStoragePool => return Ok(None),
            Err(error) => return Err(storage_backend_error(error)),
        };
        let active = pool.is_active().map_err(storage_backend_error)?;
        let info = pool.get_info().map_err(storage_backend_error)?;
        let xml = pool.get_xml_desc(0).map_err(storage_backend_error)?;
        let target_path = xml_element(&xml, "path").ok_or_else(|| {
            forge_storage::StorageError::PoolUnusable(
                "libvirt pool XML has no target path".to_owned(),
            )
        })?;
        Ok(Some(forge_storage::StoragePoolInfo {
            name: name.to_owned(),
            active,
            target_path,
            available_bytes: info.available,
        }))
    }

    fn domain_exists(&mut self, name: &str) -> Result<bool, forge_storage::StorageError> {
        match Domain::lookup_by_name(&self.connection, name) {
            Ok(_) => Ok(true),
            Err(error) if error.code() == ErrorNumber::NoDomain => Ok(false),
            Err(error) => Err(storage_backend_error(error)),
        }
    }

    fn volume_exists(
        &mut self,
        pool: &str,
        name: &str,
    ) -> Result<bool, forge_storage::StorageError> {
        let pool = self.pool(pool)?;
        match StorageVol::lookup_by_name(&pool, name) {
            Ok(_) => Ok(true),
            Err(error) if error.code() == ErrorNumber::NoStorageVolume => Ok(false),
            Err(error) => Err(storage_backend_error(error)),
        }
    }

    fn create_volume(
        &mut self,
        pool: &str,
        name: &str,
        capacity_bytes: u64,
    ) -> Result<forge_storage::VolumeInfo, forge_storage::StorageError> {
        let pool = self.pool(pool)?;
        let xml = format!(
            "<volume><name>{name}</name><capacity unit='bytes'>{capacity_bytes}</capacity><allocation unit='bytes'>0</allocation><target><format type='qcow2'/></target></volume>"
        );
        let volume = StorageVol::create_xml(&pool, &xml, 0).map_err(storage_backend_error)?;
        let info = volume.get_info().map_err(storage_backend_error)?;
        let path = volume.get_path().map_err(storage_backend_error)?;
        Ok(forge_storage::VolumeInfo {
            name: name.to_owned(),
            path,
            capacity_bytes: info.capacity,
            allocation_bytes: info.allocation,
        })
    }

    fn define_domain(
        &mut self,
        xml: &str,
    ) -> Result<forge_storage::DefinedDomain, forge_storage::DomainDefineError> {
        let domain = Domain::define_xml(&self.connection, xml).map_err(|error| {
            forge_storage::DomainDefineError {
                error: storage_backend_error(error),
                domain_defined: false,
            }
        })?;
        let inspect_error = |error: forge_storage::StorageError| forge_storage::DomainDefineError {
            error,
            domain_defined: true,
        };
        let uuid = domain
            .get_uuid_string()
            .map_err(storage_backend_error)
            .map_err(inspect_error)?;
        let (state, _) = domain
            .get_state()
            .map_err(storage_backend_error)
            .map_err(inspect_error)?;
        let state = map_domain_state(state)
            .map_err(|error| forge_storage::StorageError::Backend(error.to_string()))
            .map_err(inspect_error)?;
        Ok(forge_storage::DefinedDomain { uuid, state })
    }

    fn delete_volume(&mut self, pool: &str, name: &str) -> Result<(), forge_storage::StorageError> {
        let pool = self.pool(pool)?;
        let volume = StorageVol::lookup_by_name(&pool, name).map_err(storage_backend_error)?;
        volume.delete(0).map_err(storage_backend_error)
    }
}

impl forge_storage::ImagePrepareBackend for LibvirtDefineBackend {
    fn inspect_pool(
        &mut self,
        name: &str,
    ) -> Result<Option<forge_storage::StoragePoolInfo>, forge_storage::ImagePrepareError> {
        forge_storage::DefineBackend::inspect_pool(self, name)
            .map_err(forge_storage::ImagePrepareError::from)
    }

    fn inspect_domain(
        &mut self,
        name: &str,
    ) -> Result<Option<forge_storage::ExistingDomainInfo>, forge_storage::ImagePrepareError> {
        let domain = match Domain::lookup_by_name(&self.connection, name) {
            Ok(domain) => domain,
            Err(error) if error.code() == ErrorNumber::NoDomain => return Ok(None),
            Err(error) => return Err(image_backend_error(error)),
        };
        let (raw_state, _) = domain.get_state().map_err(image_backend_error)?;
        let state = map_domain_state(raw_state)
            .map_err(|error| forge_storage::ImagePrepareError::Backend(error.to_string()))?;
        let persistent = domain.is_persistent().map_err(image_backend_error)?;
        let autostart = domain.get_autostart().map_err(image_backend_error)?;
        let uuid = domain.get_uuid_string().map_err(image_backend_error)?;
        let xml = domain.get_xml_desc(0).map_err(image_backend_error)?;
        let disk_path = domain_disk_path(&xml).ok_or_else(|| {
            forge_storage::ImagePrepareError::UnsafeExistingVolume(
                "domain XML has no file-backed disk".to_owned(),
            )
        })?;
        Ok(Some(forge_storage::ExistingDomainInfo {
            name: name.to_owned(),
            uuid,
            state,
            persistent,
            autostart,
            disk_path,
            matches_legacy_forge_policy: matches_legacy_fedora_lab_xml(&xml),
        }))
    }

    fn inspect_volume(
        &mut self,
        pool: &str,
        name: &str,
    ) -> Result<Option<forge_storage::OverlayVolume>, forge_storage::ImagePrepareError> {
        let pool = self
            .pool(pool)
            .map_err(forge_storage::ImagePrepareError::from)?;
        let volume = match StorageVol::lookup_by_name(&pool, name) {
            Ok(volume) => volume,
            Err(error) if error.code() == ErrorNumber::NoStorageVolume => return Ok(None),
            Err(error) => return Err(image_backend_error(error)),
        };
        let info = volume.get_info().map_err(image_backend_error)?;
        let path = volume.get_path().map_err(image_backend_error)?;
        let xml = volume.get_xml_desc(0).map_err(image_backend_error)?;
        Ok(Some(forge_storage::OverlayVolume {
            name: name.to_owned(),
            path,
            capacity_bytes: info.capacity,
            allocation_bytes: info.allocation,
            format: xml_attribute(&xml, "format", "type").unwrap_or_else(|| "unknown".to_owned()),
            backing_path: backing_store_path(&xml),
        }))
    }

    fn verify_source_checksum(
        &mut self,
        path: &str,
        expected: &str,
    ) -> Result<(), forge_storage::ImagePrepareError> {
        let actual = forge_images::sha256_file(std::path::Path::new(path))
            .map_err(|error| forge_storage::ImagePrepareError::Backend(error.to_string()))?;
        if actual == expected {
            Ok(())
        } else {
            Err(forge_storage::ImagePrepareError::SourceImageNotVerified)
        }
    }

    fn diagnose_qcow2(
        &mut self,
        path: &str,
        capacity: u64,
        backing_path: Option<&str>,
    ) -> forge_storage::QemuImgDiagnostic {
        let output = match Command::new("qemu-img")
            .args(["info", "--output=json", path])
            .output()
        {
            Ok(output) => output,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return forge_storage::QemuImgDiagnostic::Unavailable;
            }
            Err(error) => return forge_storage::QemuImgDiagnostic::Warning(error.to_string()),
        };
        if !output.status.success() {
            let message = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            if message.to_ascii_lowercase().contains("permission denied") {
                return forge_storage::QemuImgDiagnostic::SkippedInsufficientPermissions;
            }
            return forge_storage::QemuImgDiagnostic::Warning(format!(
                "qemu-img info failed for {path}: {message}"
            ));
        }
        let info: QemuImgInfo = match serde_json::from_slice(&output.stdout) {
            Ok(info) => info,
            Err(error) => {
                return forge_storage::QemuImgDiagnostic::Warning(format!(
                    "cannot decode qemu-img information for {path}: {error}"
                ));
            }
        };
        if info.format != "qcow2"
            || info.virtual_size != capacity
            || info.backing_filename.as_deref() != backing_path
        {
            return forge_storage::QemuImgDiagnostic::Warning(format!(
                "qemu-img validation mismatch for {path}: format={}, virtual-size={}, backing={}",
                info.format,
                info.virtual_size,
                info.backing_filename.as_deref().unwrap_or("none")
            ));
        }
        forge_storage::QemuImgDiagnostic::Verified
    }

    fn import_base(
        &mut self,
        pool: &str,
        base: &forge_storage::BaseImageVolume,
        source_path: &str,
    ) -> Result<forge_storage::VolumeInfo, forge_storage::ImagePrepareError> {
        let pool_handle = self
            .pool(pool)
            .map_err(forge_storage::ImagePrepareError::from)?;
        let xml = format!(
            "<volume><name>{}</name><capacity unit='bytes'>{}</capacity><allocation unit='bytes'>0</allocation><target><format type='qcow2'/><permissions><mode>0444</mode></permissions></target></volume>",
            base.name, base.capacity_bytes
        );
        let volume =
            StorageVol::create_xml(&pool_handle, &xml, sys::VIR_STORAGE_VOL_CREATE_VALIDATE)
                .map_err(image_backend_error)?;
        let upload_result =
            upload_file(&self.connection, &volume, source_path, base.imported_bytes);
        if let Err(error) = upload_result {
            let _ = volume.delete(0);
            return Err(error);
        }
        pool_handle.refresh(0).map_err(image_backend_error)?;
        volume_info(&volume, &base.name)
    }

    fn create_overlay(
        &mut self,
        pool: &str,
        overlay: &forge_storage::OverlayVolume,
    ) -> Result<forge_storage::VolumeInfo, forge_storage::ImagePrepareError> {
        let pool = self
            .pool(pool)
            .map_err(forge_storage::ImagePrepareError::from)?;
        let backing = overlay.backing_path.as_deref().ok_or_else(|| {
            forge_storage::ImagePrepareError::BackingStoreMismatch {
                expected: "a libvirt base volume".to_owned(),
                actual: None,
            }
        })?;
        let xml = format!(
            "<volume><name>{}</name><capacity unit='bytes'>{}</capacity><allocation unit='bytes'>0</allocation><target><format type='qcow2'/></target><backingStore><path>{backing}</path><format type='qcow2'/></backingStore></volume>",
            overlay.name, overlay.capacity_bytes
        );
        let volume = StorageVol::create_xml(&pool, &xml, sys::VIR_STORAGE_VOL_CREATE_VALIDATE)
            .map_err(image_backend_error)?;
        volume_info(&volume, &overlay.name)
    }

    fn delete_volume(
        &mut self,
        pool: &str,
        name: &str,
    ) -> Result<(), forge_storage::ImagePrepareError> {
        forge_storage::DefineBackend::delete_volume(self, pool, name)
            .map_err(forge_storage::ImagePrepareError::from)
    }

    fn redefine_domain(
        &mut self,
        xml: &str,
    ) -> Result<forge_storage::DefinedDomain, forge_storage::DomainDefineError> {
        forge_storage::DefineBackend::define_domain(self, xml)
    }
}

#[derive(Deserialize)]
struct QemuImgInfo {
    format: String,
    #[serde(rename = "virtual-size")]
    virtual_size: u64,
    #[serde(rename = "backing-filename")]
    backing_filename: Option<String>,
}

fn upload_file(
    connection: &Connect,
    volume: &StorageVol,
    source_path: &str,
    length: u64,
) -> Result<(), forge_storage::ImagePrepareError> {
    let mut file = File::open(source_path)
        .map_err(|error| forge_storage::ImagePrepareError::Backend(error.to_string()))?;
    let stream = Stream::new(connection, 0).map_err(image_backend_error)?;
    volume
        .upload(&stream, 0, length, 0)
        .map_err(image_backend_error)?;
    let mut buffer = vec![0_u8; 1024 * 1024];
    let mut total = 0_u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| forge_storage::ImagePrepareError::Backend(error.to_string()))?;
        if read == 0 {
            break;
        }
        let mut sent = 0;
        while sent < read {
            let count = stream
                .send(&buffer[sent..read])
                .map_err(image_backend_error)?;
            if count == 0 {
                return Err(forge_storage::ImagePrepareError::Backend(
                    "libvirt upload stream stopped accepting data".to_owned(),
                ));
            }
            sent += count;
        }
        total = total.checked_add(read as u64).ok_or_else(|| {
            forge_storage::ImagePrepareError::Backend("upload byte count overflowed".to_owned())
        })?;
    }
    if total != length {
        stream.abort().map_err(image_backend_error)?;
        return Err(forge_storage::ImagePrepareError::Backend(format!(
            "source size changed during upload: expected {length}, sent {total}"
        )));
    }
    stream.finish().map_err(image_backend_error)
}

fn volume_info(
    volume: &StorageVol,
    name: &str,
) -> Result<forge_storage::VolumeInfo, forge_storage::ImagePrepareError> {
    let info = volume.get_info().map_err(image_backend_error)?;
    let path = volume.get_path().map_err(image_backend_error)?;
    Ok(forge_storage::VolumeInfo {
        name: name.to_owned(),
        path,
        capacity_bytes: info.capacity,
        allocation_bytes: info.allocation,
    })
}

fn image_backend_error(error: VirtError) -> forge_storage::ImagePrepareError {
    let message = error.to_string();
    drop(error);
    forge_storage::ImagePrepareError::Backend(format!("libvirt image operation failed: {message}"))
}

fn domain_disk_path(xml: &str) -> Option<String> {
    let disk = xml
        .split("<disk ")
        .find(|section| section.contains("device='disk'") || section.contains("device=\"disk\""))?;
    xml_attribute(disk, "source", "file")
}

fn backing_store_path(xml: &str) -> Option<String> {
    let backing = xml
        .split_once("<backingStore")?
        .1
        .split_once("</backingStore>")?
        .0;
    xml_element(backing, "path")
}

fn xml_attribute(xml: &str, element: &str, attribute: &str) -> Option<String> {
    let start = xml.find(&format!("<{element} "))?;
    let end = xml[start..].find('>')? + start;
    let tag = &xml[start..=end];
    for quote in ['\'', '"'] {
        let marker = format!("{attribute}={quote}");
        if let Some(value_start) = tag.find(&marker) {
            let value_start = value_start + marker.len();
            let value_end = tag[value_start..].find(quote)? + value_start;
            return Some(tag[value_start..value_end].to_owned());
        }
    }
    None
}

fn matches_legacy_fedora_lab_xml(xml: &str) -> bool {
    xml_attribute(xml, "type", "machine").is_some_and(|machine| machine.contains("q35"))
        && (xml.contains("mode='host-passthrough'") || xml.contains("mode=\"host-passthrough\""))
        && xml.contains("fedora-lab.qcow2")
        && (xml.contains("type='qcow2'") || xml.contains("type=\"qcow2\""))
        && (xml.contains("bus='virtio'") || xml.contains("bus=\"virtio\""))
        && (xml.contains("network='default'") || xml.contains("network=\"default\""))
        && !xml.contains("<filesystem")
        && !xml.contains("<hostdev")
}

fn storage_backend_error(error: VirtError) -> forge_storage::StorageError {
    let message = error.to_string();
    drop(error);
    forge_storage::StorageError::Backend(format!("libvirt storage operation failed: {message}"))
}

fn xml_element(xml: &str, name: &str) -> Option<String> {
    let opening = format!("<{name}>");
    let closing = format!("</{name}>");
    let start = xml.find(&opening)? + opening.len();
    let end = xml[start..].find(&closing)? + start;
    Some(xml[start..end].trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain(name: &str, uuid: &str) -> DomainSummary {
        DomainSummary {
            name: name.to_owned(),
            uuid: uuid.to_owned(),
            state: VmState::Shutoff,
            persistent: true,
        }
    }

    #[test]
    fn maps_known_libvirt_states() {
        assert_eq!(
            map_domain_state(sys::VIR_DOMAIN_RUNNING),
            Ok(VmState::Running)
        );
        assert_eq!(
            map_domain_state(sys::VIR_DOMAIN_PAUSED),
            Ok(VmState::Paused)
        );
        assert_eq!(
            map_domain_state(sys::VIR_DOMAIN_SHUTOFF),
            Ok(VmState::Shutoff)
        );
        assert_eq!(
            map_domain_state(sys::VIR_DOMAIN_CRASHED),
            Ok(VmState::Crashed)
        );
        assert_eq!(
            map_domain_state(sys::VIR_DOMAIN_NOSTATE),
            Ok(VmState::Unknown)
        );
    }

    #[test]
    fn rejects_unknown_libvirt_state() {
        assert_eq!(
            map_domain_state(999),
            Err(LibvirtError::UnsupportedDomainState(999))
        );
    }

    #[test]
    fn sorts_domain_summaries_by_name_then_uuid() {
        let domains = vec![
            domain("zeta", "2"),
            domain("Alpha", "2"),
            domain("alpha", "1"),
        ];
        let sorted = sorted_domains(domains);
        let uuids = sorted
            .iter()
            .map(|domain| domain.uuid.as_str())
            .collect::<Vec<_>>();
        assert_eq!(uuids, ["1", "2", "2"]);
    }

    #[test]
    fn formats_domain_summary_readably() {
        assert_eq!(
            domain("fedora", "example-uuid").to_string(),
            "fedora\tshutoff\texample-uuid\tpersistent"
        );
    }

    #[test]
    fn formats_encoded_libvirt_version() {
        assert_eq!(format_version(12_003_004), "12.3.4");
    }
}
