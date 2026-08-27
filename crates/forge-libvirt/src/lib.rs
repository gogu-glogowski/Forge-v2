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
use virt::network::Network;
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

fn domain_cdrom_path(xml: &str) -> Option<String> {
    let disk = xml.split("<disk ").find(|section| {
        section.contains("device='cdrom'") || section.contains("device=\"cdrom\"")
    })?;
    xml_attribute(disk, "source", "file")
}

fn domain_source_paths(xml: &str) -> Vec<String> {
    xml.split("<source ")
        .skip(1)
        .filter_map(|section| xml_attribute(&format!("<source {section}"), "source", "file"))
        .collect()
}

fn active_volume_backing(
    domain_xml: &str,
    volume_backings: &[(String, Option<String>)],
) -> Option<String> {
    let active_path = domain_disk_path(domain_xml)?;
    volume_backings
        .iter()
        .find(|(path, _)| path == &active_path)
        .and_then(|(_, backing)| backing.clone())
}

fn generation_volume_status(
    pool: &StoragePool,
    pool_path: &str,
    name: &str,
    domain_references: &[(String, Vec<String>)],
    volume_backings: &[(String, Option<String>)],
) -> Result<forge_provisioning::GenerationVolumeStatus, forge_provisioning::ProvisioningError> {
    let expected_path = format!("{pool_path}/{name}");
    let volume = match StorageVol::lookup_by_name(pool, name) {
        Ok(volume) => volume,
        Err(error) if error.code() == ErrorNumber::NoStorageVolume => {
            return Ok(forge_provisioning::GenerationVolumeStatus {
                name: name.to_owned(),
                path: expected_path,
                exists: false,
                capacity_bytes: None,
                format: None,
                backing_path: None,
                referenced_by_domains: Vec::new(),
                backing_for_volumes: Vec::new(),
                ownership_marker: None,
            });
        }
        Err(error) => return Err(provisioning_backend_error(error)),
    };
    let info = volume.get_info().map_err(provisioning_backend_error)?;
    let path = volume.get_path().map_err(provisioning_backend_error)?;
    let xml = volume.get_xml_desc(0).map_err(provisioning_backend_error)?;
    Ok(forge_provisioning::GenerationVolumeStatus {
        name: name.to_owned(),
        path: path.clone(),
        exists: true,
        capacity_bytes: Some(info.capacity),
        format: xml_attribute(&xml, "format", "type"),
        backing_path: backing_store_path(&xml),
        referenced_by_domains: domain_references
            .iter()
            .filter(|(_, paths)| paths.contains(&path))
            .map(|(name, _)| name.clone())
            .collect(),
        backing_for_volumes: volume_backings
            .iter()
            .filter(|(_, backing)| backing.as_deref() == Some(path.as_str()))
            .map(|(volume_path, _)| volume_path.clone())
            .collect(),
        ownership_marker: None,
    })
}

fn domain_ip_addresses(domain: &Domain) -> Vec<String> {
    let mut addresses = Vec::new();
    for source in [
        sys::VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_AGENT,
        sys::VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE,
    ] {
        if let Ok(interfaces) = domain.interface_addresses(source, 0) {
            addresses.extend(
                interfaces
                    .into_iter()
                    .flat_map(|interface| interface.addrs)
                    .map(|address| address.addr)
                    .filter(|address| !address.starts_with("127.") && address != "::1"),
            );
        }
    }
    addresses.sort();
    addresses.dedup();
    addresses
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

pub struct LibvirtBootBackend {
    connection: Connect,
    instance: forge_core::InstanceName,
}

impl LibvirtBootBackend {
    /// # Errors
    /// Returns an error when system libvirt is unavailable.
    pub fn connect_local() -> Result<Self, LibvirtError> {
        let instance =
            forge_core::InstanceName::new("fedora-lab").map_err(|error| LibvirtError::Mapping {
                field: "compatibility instance".to_owned(),
                message: error.to_string(),
            })?;
        Self::connect_instance(instance)
    }

    /// Connects the operational adapter to one typed instance identity.
    ///
    /// # Errors
    /// Returns an error when system libvirt is unavailable.
    pub fn connect_instance(instance: forge_core::InstanceName) -> Result<Self, LibvirtError> {
        Connect::open(Some(LOCAL_QEMU_URI))
            .map(|connection| Self {
                connection,
                instance,
            })
            .map_err(|error| LibvirtError::Connection {
                uri: LOCAL_QEMU_URI.to_owned(),
                message: error.to_string(),
            })
    }

    fn domain(&self) -> Result<Domain, forge_provisioning::ProvisioningError> {
        Domain::lookup_by_name(&self.connection, self.instance.as_str())
            .map_err(provisioning_backend_error)
    }

    fn pool(&self) -> Result<StoragePool, forge_provisioning::ProvisioningError> {
        StoragePool::lookup_by_name(&self.connection, forge_storage::DEFAULT_POOL)
            .map_err(provisioning_backend_error)
    }

    /// Reads the current Fedora-Lab resources needed for a mutation-free rebuild plan.
    ///
    /// # Errors
    /// Returns an error when domain, pool, or volume metadata cannot be inspected.
    pub fn inspect_rebuild(
        &self,
    ) -> Result<forge_provisioning::RebuildEnvironment, forge_provisioning::ProvisioningError> {
        let domain = self.domain()?;
        let (raw_state, _) = domain.get_state().map_err(provisioning_backend_error)?;
        let domain_state = map_domain_state(raw_state)
            .map_err(|error| forge_provisioning::ProvisioningError::Backend(error.to_string()))?;
        let domain_xml = domain.get_xml_desc(0).map_err(provisioning_backend_error)?;
        let current_overlay_path = domain_disk_path(&domain_xml).ok_or_else(|| {
            forge_provisioning::ProvisioningError::Backend(
                "Fedora-Lab domain has no file-backed vda".to_owned(),
            )
        })?;
        let pool = self.pool()?;
        let pool_xml = pool.get_xml_desc(0).map_err(provisioning_backend_error)?;
        let pool_path = xml_element(&pool_xml, "path").ok_or_else(|| {
            forge_provisioning::ProvisioningError::Backend(
                "default pool has no target path".to_owned(),
            )
        })?;
        let volume = |name: &str| match StorageVol::lookup_by_name(&pool, name) {
            Ok(volume) => Ok(Some(volume)),
            Err(error) if error.code() == ErrorNumber::NoStorageVolume => Ok(None),
            Err(error) => Err(provisioning_backend_error(error)),
        };
        let current_overlay = StorageVol::lookup_by_path(&self.connection, &current_overlay_path)
            .map_err(provisioning_backend_error)?;
        let current_overlay_xml = current_overlay
            .get_xml_desc(0)
            .map_err(provisioning_backend_error)?;
        let base = volume(forge_provisioning::BASE_VOLUME)?;
        let seed = volume(forge_provisioning::SEED_VOLUME)?;
        Ok(forge_provisioning::RebuildEnvironment {
            domain_state,
            domain_uuid: domain
                .get_uuid_string()
                .map_err(provisioning_backend_error)?,
            domain_persistent: domain.is_persistent().map_err(provisioning_backend_error)?,
            current_overlay_path,
            current_backing_path: backing_store_path(&current_overlay_xml),
            base_path: format!("{pool_path}/{}", forge_provisioning::BASE_VOLUME),
            base_exists: base.is_some(),
            seed_path: format!("{pool_path}/{}", forge_provisioning::SEED_VOLUME),
            seed_exists: seed.is_some(),
            pool_path,
        })
    }

    /// Reads the active Fedora-Lab generation and known cleanup candidates.
    ///
    /// # Errors
    /// Returns an error when domain or storage metadata cannot be mapped.
    pub fn inspect_lifecycle(
        &self,
    ) -> Result<forge_provisioning::FedoraLabLifecycleStatus, forge_provisioning::ProvisioningError>
    {
        self.inspect_lifecycle_with_manifest(None)
    }

    /// Reads operational status using the exact active generation manifest.
    ///
    /// # Errors
    /// Refuses instance/domain identity mismatches and unavailable libvirt data.
    pub fn inspect_managed_lifecycle(
        &self,
        active: &forge_state::GenerationManifest,
    ) -> Result<forge_provisioning::InstanceLifecycleStatus, forge_provisioning::ProvisioningError>
    {
        if active.domain_name != self.instance.as_str() {
            return Err(forge_provisioning::ProvisioningError::Backend(
                "active manifest belongs to a different instance".to_owned(),
            ));
        }
        let status = self.inspect_lifecycle_with_manifest(Some(active))?;
        if status.domain_uuid != active.domain_uuid {
            return Err(forge_provisioning::ProvisioningError::Backend(
                "domain UUID differs from active generation manifest".to_owned(),
            ));
        }
        Ok(status)
    }

    #[allow(clippy::too_many_lines)]
    fn inspect_lifecycle_with_manifest(
        &self,
        active: Option<&forge_state::GenerationManifest>,
    ) -> Result<forge_provisioning::FedoraLabLifecycleStatus, forge_provisioning::ProvisioningError>
    {
        let domain = self.domain()?;
        let (raw_state, _) = domain.get_state().map_err(provisioning_backend_error)?;
        let domain_state = map_domain_state(raw_state)
            .map_err(|error| forge_provisioning::ProvisioningError::Backend(error.to_string()))?;
        let domain_xml = domain.get_xml_desc(0).map_err(provisioning_backend_error)?;
        let pool = if let Some(manifest) = active {
            StoragePool::lookup_by_name(&self.connection, &manifest.storage_pool_name)
                .map_err(provisioning_backend_error)?
        } else {
            self.pool()?
        };
        let pool_xml = pool.get_xml_desc(0).map_err(provisioning_backend_error)?;
        let pool_path = xml_element(&pool_xml, "path").ok_or_else(|| {
            forge_provisioning::ProvisioningError::Backend(
                "default pool has no target path".to_owned(),
            )
        })?;
        let domain_references = self
            .connection
            .list_all_domains(0)
            .map_err(provisioning_backend_error)?
            .iter()
            .map(|candidate| {
                let name = candidate.get_name().map_err(provisioning_backend_error)?;
                let xml = candidate
                    .get_xml_desc(0)
                    .map_err(provisioning_backend_error)?;
                Ok((name, domain_source_paths(&xml)))
            })
            .collect::<Result<Vec<_>, forge_provisioning::ProvisioningError>>()?;
        let volume_backings = pool
            .list_all_volumes(0)
            .map_err(provisioning_backend_error)?
            .iter()
            .map(|candidate| {
                let path = candidate.get_path().map_err(provisioning_backend_error)?;
                let xml = candidate
                    .get_xml_desc(0)
                    .map_err(provisioning_backend_error)?;
                Ok((path, backing_store_path(&xml)))
            })
            .collect::<Result<Vec<_>, forge_provisioning::ProvisioningError>>()?;
        let volume_status = |name: &str| {
            generation_volume_status(
                &pool,
                &pool_path,
                name,
                &domain_references,
                &volume_backings,
            )
        };
        let ip_addresses = if domain_state == VmState::Running {
            domain_ip_addresses(&domain)
        } else {
            Vec::new()
        };
        let guest_agent_channel = domain_xml.contains("org.qemu.guest_agent.0");
        let guest_agent_status = if !guest_agent_channel {
            forge_provisioning::GuestAgentStatus::Unavailable
        } else if domain_state == VmState::Running
            && domain
                .qemu_agent_command("{\"execute\":\"guest-ping\"}", 5, 0)
                .is_ok()
        {
            forge_provisioning::GuestAgentStatus::Available
        } else {
            forge_provisioning::GuestAgentStatus::Unavailable
        };
        let default_network_active = Network::lookup_by_name(&self.connection, "default")
            .and_then(|network| network.is_active())
            .map_err(provisioning_backend_error)?;
        let managed_name = |role: forge_state::ResourceRole, fallback: &str| {
            active
                .and_then(|manifest| {
                    manifest
                        .resources
                        .iter()
                        .find(|resource| resource.role == role)
                })
                .map_or_else(
                    || fallback.to_owned(),
                    |resource| resource.volume_name.clone(),
                )
        };
        let base_name = managed_name(
            forge_state::ResourceRole::SharedBase,
            forge_provisioning::BASE_VOLUME,
        );
        let overlay_name = managed_name(
            forge_state::ResourceRole::WritableOverlay,
            forge_provisioning::REBUILD_OVERLAY_VOLUME,
        );
        let seed_name = managed_name(
            forge_state::ResourceRole::NoCloudSeed,
            forge_provisioning::REBUILD_SEED_VOLUME,
        );
        Ok(forge_provisioning::FedoraLabLifecycleStatus {
            domain_state,
            domain_uuid: domain
                .get_uuid_string()
                .map_err(provisioning_backend_error)?,
            persistent: domain.is_persistent().map_err(provisioning_backend_error)?,
            autostart: domain.get_autostart().map_err(provisioning_backend_error)?,
            default_network: if default_network_active {
                forge_provisioning::DefaultNetworkStatus::Active
            } else {
                forge_provisioning::DefaultNetworkStatus::Inactive
            },
            active_overlay_path: domain_disk_path(&domain_xml).ok_or_else(|| {
                forge_provisioning::ProvisioningError::Backend(
                    "instance domain has no file-backed vda".to_owned(),
                )
            })?,
            active_backing_path: active_volume_backing(&domain_xml, &volume_backings),
            active_seed_path: domain_cdrom_path(&domain_xml),
            guest_agent_channel,
            guest_agent_status,
            ip_addresses,
            base: volume_status(&base_name)?,
            current_overlay: volume_status(&overlay_name)?,
            current_seed: volume_status(&seed_name)?,
            legacy_overlay: volume_status(forge_provisioning::OVERLAY_VOLUME)?,
            legacy_seed: volume_status(forge_provisioning::SEED_VOLUME)?,
        })
    }

    /// Reads the domain, pool, and active volume identities for Forge state reconciliation.
    ///
    /// # Errors
    /// Returns an error when any required libvirt identity or storage field is unavailable.
    pub fn inspect_state(
        &self,
    ) -> Result<forge_state::ObservedGeneration, forge_provisioning::ProvisioningError> {
        let lifecycle = self.inspect_lifecycle()?;
        let active_seed_path = lifecycle.active_seed_path.as_deref().ok_or_else(|| {
            forge_provisioning::ProvisioningError::Backend(
                "Fedora-Lab domain has no active file-backed seed".to_owned(),
            )
        })?;
        let unmanaged_resources = [&lifecycle.legacy_overlay, &lifecycle.legacy_seed]
            .into_iter()
            .filter(|volume| {
                volume.exists
                    && volume.path != lifecycle.active_overlay_path
                    && volume.path != active_seed_path
            })
            .map(|volume| volume.path.clone())
            .collect();
        let mut observed =
            self.inspect_generation_paths(&lifecycle.active_overlay_path, active_seed_path)?;
        observed.unmanaged_resources = unmanaged_resources;
        Ok(observed)
    }

    /// Reads exact libvirt identities for a prospective or retained generation.
    /// Domain XML supplies references; storage XML supplies format and backing.
    ///
    /// # Errors
    /// Returns a typed discovery/mapping error when any exact identity is unavailable.
    #[allow(clippy::too_many_lines)]
    pub fn inspect_generation_paths(
        &self,
        overlay_path: &str,
        seed_path: &str,
    ) -> Result<forge_state::ObservedGeneration, forge_provisioning::ProvisioningError> {
        self.inspect_generation_paths_in_pool(forge_storage::DEFAULT_POOL, overlay_path, seed_path)
    }

    #[allow(clippy::too_many_lines)]
    fn inspect_generation_paths_in_pool(
        &self,
        pool_name: &str,
        overlay_path: &str,
        seed_path: &str,
    ) -> Result<forge_state::ObservedGeneration, forge_provisioning::ProvisioningError> {
        let domain = self.domain()?;
        let domain_uuid = domain
            .get_uuid_string()
            .map_err(provisioning_backend_error)?;
        let domain_persistent = domain.is_persistent().map_err(provisioning_backend_error)?;
        let pool = StoragePool::lookup_by_name(&self.connection, pool_name)
            .map_err(provisioning_backend_error)?;
        let pool_xml = pool.get_xml_desc(0).map_err(provisioning_backend_error)?;
        let pool_path = xml_element(&pool_xml, "path").ok_or_else(|| {
            forge_provisioning::ProvisioningError::Backend(
                "default pool has no target path".to_owned(),
            )
        })?;
        let domain_references = self
            .connection
            .list_all_domains(0)
            .map_err(provisioning_backend_error)?
            .iter()
            .map(|domain| {
                Ok((
                    domain.get_name().map_err(provisioning_backend_error)?,
                    domain_source_paths(
                        &domain.get_xml_desc(0).map_err(provisioning_backend_error)?,
                    ),
                ))
            })
            .collect::<Result<Vec<_>, forge_provisioning::ProvisioningError>>()?;
        let volume_backings = pool
            .list_all_volumes(0)
            .map_err(provisioning_backend_error)?
            .iter()
            .map(|volume| {
                let path = volume.get_path().map_err(provisioning_backend_error)?;
                Ok((
                    path,
                    backing_store_path(
                        &volume.get_xml_desc(0).map_err(provisioning_backend_error)?,
                    ),
                ))
            })
            .collect::<Result<Vec<_>, forge_provisioning::ProvisioningError>>()?;
        let name = |path: &str| {
            std::path::Path::new(path)
                .file_name()
                .and_then(|v| v.to_str())
                .map(str::to_owned)
                .ok_or_else(|| {
                    forge_provisioning::ProvisioningError::Backend(format!(
                        "invalid volume path: {path}"
                    ))
                })
        };
        let overlay_status = generation_volume_status(
            &pool,
            &pool_path,
            &name(overlay_path)?,
            &domain_references,
            &volume_backings,
        )?;
        let base_path = overlay_status.backing_path.as_deref().ok_or_else(|| {
            forge_provisioning::ProvisioningError::Backend(
                "generation overlay has no backing volume".to_owned(),
            )
        })?;
        let base_status = generation_volume_status(
            &pool,
            &pool_path,
            &name(base_path)?,
            &domain_references,
            &volume_backings,
        )?;
        let statuses = [
            (forge_state::ResourceRole::SharedBase, base_status),
            (forge_state::ResourceRole::WritableOverlay, overlay_status),
            (
                forge_state::ResourceRole::NoCloudSeed,
                generation_volume_status(
                    &pool,
                    &pool_path,
                    &name(seed_path)?,
                    &domain_references,
                    &volume_backings,
                )?,
            ),
        ];
        let mut resources = Vec::new();
        for (role, status) in statuses {
            if !status.exists {
                return Err(forge_provisioning::ProvisioningError::Backend(format!(
                    "required generation resource is missing: {}",
                    status.path
                )));
            }
            let volume = StorageVol::lookup_by_path(&self.connection, &status.path)
                .map_err(provisioning_backend_error)?;
            resources.push(forge_state::ObservedResource {
                role,
                volume_name: status.name,
                volume_key: volume.get_key().map_err(provisioning_backend_error)?,
                path: status.path,
                format: status.format.ok_or_else(|| {
                    forge_provisioning::ProvisioningError::Backend(
                        "volume format unavailable".to_owned(),
                    )
                })?,
                capacity_bytes: status.capacity_bytes.ok_or_else(|| {
                    forge_provisioning::ProvisioningError::Backend(
                        "volume capacity unavailable".to_owned(),
                    )
                })?,
                backing_path: status.backing_path,
                referenced_by_domains: status.referenced_by_domains,
                backing_for_volumes: status.backing_for_volumes,
            });
        }
        Ok(forge_state::ObservedGeneration {
            domain_name: self.instance.to_string(),
            domain_uuid,
            domain_persistent,
            libvirt_uri: self
                .connection
                .get_uri()
                .map_err(provisioning_backend_error)?,
            storage_pool_name: pool_name.to_owned(),
            storage_pool_uuid: pool.get_uuid_string().map_err(provisioning_backend_error)?,
            resources,
            unmanaged_resources: Vec::new(),
        })
    }

    /// Reads the active instance generation using durable manifest identities.
    ///
    /// # Errors
    /// Refuses incomplete manifests and unavailable exact libvirt identities.
    pub fn inspect_managed_state(
        &self,
        active: &forge_state::GenerationManifest,
    ) -> Result<forge_state::ObservedGeneration, forge_provisioning::ProvisioningError> {
        if active.domain_name != self.instance.as_str() {
            return Err(forge_provisioning::ProvisioningError::Backend(
                "active manifest belongs to a different instance".to_owned(),
            ));
        }
        let resource_path = |role| {
            active
                .resources
                .iter()
                .find(|resource| resource.role == role)
                .map(|resource| resource.path.as_str())
                .ok_or_else(|| {
                    forge_provisioning::ProvisioningError::Backend(format!(
                        "active manifest lacks {role:?}"
                    ))
                })
        };
        self.inspect_generation_paths_in_pool(
            &active.storage_pool_name,
            resource_path(forge_state::ResourceRole::WritableOverlay)?,
            resource_path(forge_state::ResourceRole::NoCloudSeed)?,
        )
    }

    /// Deletes one exact, previously reconciled volume identity.
    ///
    /// # Errors
    /// Refuses shared or referenced resources and returns identity/delete errors.
    pub fn delete_managed_volume_exact(
        &self,
        expected: &forge_state::ManagedResource,
    ) -> Result<(), forge_provisioning::ProvisioningError> {
        if expected.role == forge_state::ResourceRole::SharedBase {
            return Err(forge_provisioning::ProvisioningError::Backend(
                "shared base deletion is forbidden".to_owned(),
            ));
        }
        for domain in self
            .connection
            .list_all_domains(0)
            .map_err(provisioning_backend_error)?
        {
            let xml = domain.get_xml_desc(0).map_err(provisioning_backend_error)?;
            if domain_source_paths(&xml)
                .iter()
                .any(|path| path == &expected.path)
            {
                return Err(forge_provisioning::ProvisioningError::Backend(
                    "volume gained a domain reference before delete".to_owned(),
                ));
            }
        }
        let pool = self.pool()?;
        for candidate in pool
            .list_all_volumes(0)
            .map_err(provisioning_backend_error)?
        {
            let xml = candidate
                .get_xml_desc(0)
                .map_err(provisioning_backend_error)?;
            if backing_store_path(&xml).as_deref() == Some(expected.path.as_str()) {
                return Err(forge_provisioning::ProvisioningError::Backend(
                    "volume gained a backing-store reference before delete".to_owned(),
                ));
            }
        }
        let volume = StorageVol::lookup_by_path(&self.connection, &expected.path)
            .map_err(provisioning_backend_error)?;
        let info = volume.get_info().map_err(provisioning_backend_error)?;
        let xml = volume.get_xml_desc(0).map_err(provisioning_backend_error)?;
        if volume.get_name().map_err(provisioning_backend_error)? != expected.volume_name
            || volume.get_key().map_err(provisioning_backend_error)? != expected.volume_key
            || info.capacity != expected.capacity_bytes
            || xml_attribute(&xml, "format", "type").as_deref() != Some(expected.format.as_str())
            || backing_store_path(&xml) != expected.backing_path
        {
            return Err(forge_provisioning::ProvisioningError::Backend(
                "volume identity changed immediately before delete".to_owned(),
            ));
        }
        volume.delete(0).map_err(provisioning_backend_error)
    }

    /// Proves that no libvirt storage volume remains at an exact managed path.
    /// # Errors
    /// Returns an error when the volume still exists or discovery is inconclusive.
    pub fn verify_managed_volume_absent(
        &self,
        expected: &forge_state::ManagedResource,
    ) -> Result<(), forge_provisioning::ProvisioningError> {
        match StorageVol::lookup_by_path(&self.connection, &expected.path) {
            Err(error) if error.code() == ErrorNumber::NoStorageVolume => Ok(()),
            Err(error) => Err(provisioning_backend_error(error)),
            Ok(volume) => {
                let key = volume.get_key().map_err(provisioning_backend_error)?;
                Err(forge_provisioning::ProvisioningError::Backend(format!(
                    "managed volume still exists after delete: path={} key={key}",
                    expected.path
                )))
            }
        }
    }

    /// Performs recovery-only SSH observability with a caller-supplied, dedicated known-hosts
    /// file. Global host keys and TOFU are disabled.
    /// # Errors
    /// Returns process errors; SSH and guest health failures remain typed in the observation.
    pub fn observe_recovery_ssh(
        &self,
        ip_address: &str,
        private_key_path: &str,
        known_hosts_path: &str,
        timeout: std::time::Duration,
    ) -> Result<forge_provisioning::SshObservation, forge_provisioning::ProvisioningError> {
        if !std::path::Path::new(known_hosts_path).is_file() {
            return Err(forge_provisioning::ProvisioningError::Backend(
                "dedicated recovery known_hosts is missing".to_owned(),
            ));
        }
        let mut child = Command::new("ssh")
            .args(["-i", private_key_path, "-o", "IdentitiesOnly=yes"])
            .args(["-o", "BatchMode=yes", "-o", "ConnectionAttempts=1"])
            .arg("-o")
            .arg(format!("ConnectTimeout={}", timeout.as_secs()))
            .args(["-o", "StrictHostKeyChecking=yes", "-o"])
            .arg(format!("UserKnownHostsFile={known_hosts_path}"))
            .args(["-o", "GlobalKnownHostsFile=/dev/null"])
            .arg(format!("forge@{ip_address}"))
            .arg("cloud-init status --long; id; hostname")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|error| forge_provisioning::ProvisioningError::Backend(error.to_string()))?;
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            if child
                .try_wait()
                .map_err(|error| forge_provisioning::ProvisioningError::Backend(error.to_string()))?
                .is_some()
            {
                let output = child.wait_with_output().map_err(|error| {
                    forge_provisioning::ProvisioningError::Backend(error.to_string())
                })?;
                return Ok(parse_recovery_ssh_observation(&output));
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        child
            .kill()
            .map_err(|error| forge_provisioning::ProvisioningError::Backend(error.to_string()))?;
        let _ = child.wait();
        Ok(forge_provisioning::SshObservation {
            status: forge_provisioning::SshStatus::TimedOut {
                after_seconds: timeout.as_secs(),
            },
            cloud_init: forge_provisioning::CloudInitStatus::Unknown,
            forge_user_confirmed: false,
            hostname: None,
        })
    }
}

impl forge_provisioning::BootBackend for LibvirtBootBackend {
    fn inspect(
        &mut self,
    ) -> Result<forge_provisioning::BootEnvironment, forge_provisioning::ProvisioningError> {
        let domain = self.domain()?;
        let (state, _) = domain.get_state().map_err(provisioning_backend_error)?;
        let state = map_domain_state(state)
            .map_err(|error| forge_provisioning::ProvisioningError::Backend(error.to_string()))?;
        let domain_xml = domain.get_xml_desc(0).map_err(provisioning_backend_error)?;
        let pool = self.pool()?;
        let pool_xml = pool.get_xml_desc(0).map_err(provisioning_backend_error)?;
        let pool_path = xml_element(&pool_xml, "path").ok_or_else(|| {
            forge_provisioning::ProvisioningError::Backend(
                "default pool has no target path".to_owned(),
            )
        })?;
        let volume = |name: &str| match StorageVol::lookup_by_name(&pool, name) {
            Ok(volume) => Ok(Some(volume)),
            Err(error) if error.code() == ErrorNumber::NoStorageVolume => Ok(None),
            Err(error) => Err(provisioning_backend_error(error)),
        };
        let overlay = volume(forge_provisioning::OVERLAY_VOLUME)?;
        let overlay_backing_path = overlay
            .as_ref()
            .and_then(|volume| volume.get_xml_desc(0).ok())
            .and_then(|xml| backing_store_path(&xml));
        let base_exists = volume(forge_provisioning::BASE_VOLUME)?.is_some();
        let seed = volume(forge_provisioning::SEED_VOLUME)?;
        let seed_checksum = seed
            .as_ref()
            .and_then(|volume| volume.get_xml_desc(0).ok())
            .and_then(|xml| xml_element(&xml, "description"))
            .and_then(|value| {
                value
                    .strip_prefix("forge-cloud-init-sha256:")
                    .map(str::to_owned)
            });
        let network = Network::lookup_by_name(&self.connection, "default")
            .map_err(provisioning_backend_error)?;
        Ok(forge_provisioning::BootEnvironment {
            domain_state: state,
            domain_xml,
            overlay_exists: overlay.is_some(),
            overlay_backing_path,
            base_exists,
            network_active: network.is_active().map_err(provisioning_backend_error)?,
            seed_path: format!("{pool_path}/{}", forge_provisioning::SEED_VOLUME),
            seed_checksum,
        })
    }

    fn create_seed(
        &mut self,
        seed: &forge_provisioning::SeedPlan,
    ) -> Result<(), forge_provisioning::ProvisioningError> {
        let temporary =
            std::env::temp_dir().join(format!("forge-cloud-init-{}", std::process::id()));
        std::fs::create_dir(&temporary)
            .map_err(|error| forge_provisioning::ProvisioningError::Backend(error.to_string()))?;
        let result = (|| {
            std::fs::write(temporary.join("user-data"), &seed.data.user_data).map_err(|error| {
                forge_provisioning::ProvisioningError::Backend(error.to_string())
            })?;
            std::fs::write(temporary.join("meta-data"), &seed.data.meta_data).map_err(|error| {
                forge_provisioning::ProvisioningError::Backend(error.to_string())
            })?;
            let iso = temporary.join("seed.iso");
            let output = Command::new("genisoimage")
                .current_dir(&temporary)
                .args(["-quiet", "-output"])
                .arg(&iso)
                .args([
                    "-volid",
                    "cidata",
                    "-joliet",
                    "-rock",
                    "user-data",
                    "meta-data",
                ])
                .output()
                .map_err(|error| {
                    forge_provisioning::ProvisioningError::Backend(error.to_string())
                })?;
            if !output.status.success() {
                return Err(forge_provisioning::ProvisioningError::Backend(
                    String::from_utf8_lossy(&output.stderr).to_string(),
                ));
            }
            let length = std::fs::metadata(&iso)
                .map_err(|error| forge_provisioning::ProvisioningError::Backend(error.to_string()))?
                .len();
            let pool = self.pool()?;
            let xml = seed_volume_xml(&seed.volume_name, length);
            let volume = StorageVol::create_xml(&pool, &xml, sys::VIR_STORAGE_VOL_CREATE_VALIDATE)
                .map_err(provisioning_backend_error)?;
            let upload = upload_file(
                &self.connection,
                &volume,
                iso.to_string_lossy().as_ref(),
                length,
            );
            if let Err(error) = upload {
                let _ = volume.delete(0);
                return Err(forge_provisioning::ProvisioningError::Backend(
                    error.to_string(),
                ));
            }
            Ok(())
        })();
        let _ = std::fs::remove_dir_all(&temporary);
        result
    }

    fn redefine(&mut self, xml: &str) -> Result<(), forge_provisioning::ProvisioningError> {
        Domain::define_xml(&self.connection, xml)
            .map(|_| ())
            .map_err(provisioning_backend_error)
    }

    fn start(&mut self) -> Result<(), forge_provisioning::ProvisioningError> {
        self.domain()?
            .create()
            .map(|_| ())
            .map_err(provisioning_backend_error)
    }

    fn wait_running(
        &mut self,
        timeout: std::time::Duration,
    ) -> Result<(), forge_provisioning::ProvisioningError> {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            let (state, _) = self
                .domain()?
                .get_state()
                .map_err(provisioning_backend_error)?;
            if map_domain_state(state).ok() == Some(VmState::Running) {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
        Err(forge_provisioning::ProvisioningError::Timeout {
            stage: forge_provisioning::WaitStage::DomainRunning,
            after_seconds: timeout.as_secs(),
        })
    }

    fn discover_ip(
        &mut self,
        timeout: std::time::Duration,
    ) -> Result<Option<String>, forge_provisioning::ProvisioningError> {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            let domain = self.domain()?;
            for source in [
                sys::VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_AGENT,
                sys::VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE,
            ] {
                if let Ok(interfaces) = domain.interface_addresses(source, 0)
                    && let Some(address) = interfaces
                        .into_iter()
                        .flat_map(|interface| interface.addrs)
                        .map(|address| address.addr)
                        .find(|address| !address.starts_with("127.") && address != "::1")
                {
                    return Ok(Some(address));
                }
            }
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
        Ok(None)
    }

    fn wait_guest_agent(
        &mut self,
        timeout: std::time::Duration,
    ) -> Result<forge_provisioning::GuestAgentStatus, forge_provisioning::ProvisioningError> {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            match self
                .domain()?
                .qemu_agent_command("{\"execute\":\"guest-ping\"}", 5, 0)
            {
                Ok(_) => return Ok(forge_provisioning::GuestAgentStatus::Available),
                Err(error)
                    if matches!(
                        error.code(),
                        ErrorNumber::OperationUnsupported | ErrorNumber::ConfigUnsupported
                    ) =>
                {
                    return Ok(forge_provisioning::GuestAgentStatus::Unavailable);
                }
                Err(_) => {}
            }
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
        Ok(forge_provisioning::GuestAgentStatus::TimedOut {
            after_seconds: timeout.as_secs(),
        })
    }

    fn observe_ssh(
        &mut self,
        ip_address: &str,
        private_key_path: &str,
        timeout: std::time::Duration,
    ) -> Result<forge_provisioning::SshObservation, forge_provisioning::ProvisioningError> {
        let remote =
            "cloud-init status --long; echo __FORGE_ID__; id; echo __FORGE_HOSTNAME__; hostname";
        let mut child = Command::new("ssh")
            .args(["-i", private_key_path, "-o", "BatchMode=yes"])
            .arg("-o")
            .arg(format!("ConnectTimeout={}", timeout.as_secs()))
            .args([
                "-o",
                "ConnectionAttempts=1",
                "-o",
                "StrictHostKeyChecking=accept-new",
                "-o",
                "UserKnownHostsFile=/tmp/forge-fedora-lab-known-hosts",
            ])
            .arg(format!("forge@{ip_address}"))
            .arg(remote)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|error| forge_provisioning::ProvisioningError::Backend(error.to_string()))?;
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            if child
                .try_wait()
                .map_err(|error| forge_provisioning::ProvisioningError::Backend(error.to_string()))?
                .is_some()
            {
                let output = child.wait_with_output().map_err(|error| {
                    forge_provisioning::ProvisioningError::Backend(error.to_string())
                })?;
                return Ok(parse_ssh_observation(&output));
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        child
            .kill()
            .map_err(|error| forge_provisioning::ProvisioningError::Backend(error.to_string()))?;
        let _ = child.wait();
        Ok(forge_provisioning::SshObservation {
            status: forge_provisioning::SshStatus::TimedOut {
                after_seconds: timeout.as_secs(),
            },
            cloud_init: forge_provisioning::CloudInitStatus::Unknown,
            forge_user_confirmed: false,
            hostname: None,
        })
    }
}

impl forge_provisioning::RebuildBackend for LibvirtBootBackend {
    fn create_rebuild_overlay(
        &mut self,
        plan: &forge_provisioning::RebuildPlan,
    ) -> Result<(), forge_provisioning::ProvisioningError> {
        let pool = self.pool()?;
        let overlay_name = std::path::Path::new(&plan.new_overlay_path)
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| {
                forge_provisioning::ProvisioningError::Backend(
                    "invalid managed overlay path".to_owned(),
                )
            })?;
        let seed_name = std::path::Path::new(&plan.new_seed_path)
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| {
                forge_provisioning::ProvisioningError::Backend(
                    "invalid managed seed path".to_owned(),
                )
            })?;
        for name in [overlay_name, seed_name] {
            match StorageVol::lookup_by_name(&pool, name) {
                Ok(_) => {
                    return Err(forge_provisioning::ProvisioningError::Backend(format!(
                        "rebuild resource already exists: {name}"
                    )));
                }
                Err(error) if error.code() == ErrorNumber::NoStorageVolume => {}
                Err(error) => return Err(provisioning_backend_error(error)),
            }
        }
        let xml = format!(
            "<volume><name>{}</name><capacity unit='bytes'>{}</capacity><allocation unit='bytes'>0</allocation><target><format type='qcow2'/></target><backingStore><path>{}</path><format type='qcow2'/></backingStore></volume>",
            overlay_name, plan.new_overlay_capacity_bytes, plan.environment.base_path
        );
        StorageVol::create_xml(&pool, &xml, sys::VIR_STORAGE_VOL_CREATE_VALIDATE)
            .map_err(provisioning_backend_error)?;
        let volume =
            StorageVol::lookup_by_name(&pool, overlay_name).map_err(provisioning_backend_error)?;
        let info = volume.get_info().map_err(provisioning_backend_error)?;
        let path = volume.get_path().map_err(provisioning_backend_error)?;
        let xml = volume.get_xml_desc(0).map_err(provisioning_backend_error)?;
        if path != plan.new_overlay_path
            || info.capacity != plan.new_overlay_capacity_bytes
            || xml_attribute(&xml, "format", "type").as_deref() != Some("qcow2")
            || backing_store_path(&xml).as_deref() != Some(plan.environment.base_path.as_str())
        {
            return Err(forge_provisioning::ProvisioningError::Backend(
                "new rebuild overlay failed libvirt validation".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_rebuild_seed(
        &mut self,
        plan: &forge_provisioning::RebuildPlan,
    ) -> Result<(), forge_provisioning::ProvisioningError> {
        let pool = self.pool()?;
        let seed_name = std::path::Path::new(&plan.new_seed_path)
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| {
                forge_provisioning::ProvisioningError::Backend(
                    "invalid managed seed path".to_owned(),
                )
            })?;
        let volume =
            StorageVol::lookup_by_name(&pool, seed_name).map_err(provisioning_backend_error)?;
        let info = volume.get_info().map_err(provisioning_backend_error)?;
        let path = volume.get_path().map_err(provisioning_backend_error)?;
        let xml = volume.get_xml_desc(0).map_err(provisioning_backend_error)?;
        let format = xml_attribute(&xml, "format", "type");
        if path != plan.new_seed_path
            || info.capacity == 0
            || !matches!(format.as_deref(), Some("raw" | "iso"))
        {
            return Err(forge_provisioning::ProvisioningError::Backend(
                "new rebuild seed failed libvirt validation".to_owned(),
            ));
        }
        Ok(())
    }

    fn shutdown_and_wait(
        &mut self,
        timeout: std::time::Duration,
    ) -> Result<forge_provisioning::ManagedShutdownStatus, forge_provisioning::ProvisioningError>
    {
        let domain = self.domain()?;
        let (state, _) = domain.get_state().map_err(provisioning_backend_error)?;
        let state = map_domain_state(state).map_err(|error| {
            forge_provisioning::ProvisioningError::LifecycleUnsafe(error.to_string())
        })?;
        if let Some(status) = forge_provisioning::managed_shutdown_status(state)? {
            return Ok(status);
        }
        domain.shutdown().map_err(provisioning_backend_error)?;
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            let (state, _) = self
                .domain()?
                .get_state()
                .map_err(provisioning_backend_error)?;
            if map_domain_state(state).ok() == Some(VmState::Shutoff) {
                return Ok(forge_provisioning::ManagedShutdownStatus::GracefulShutdownCompleted);
            }
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
        Err(forge_provisioning::ProvisioningError::Timeout {
            stage: forge_provisioning::WaitStage::DomainShutoff,
            after_seconds: timeout.as_secs(),
        })
    }

    fn verify_pre_switch(
        &mut self,
        expected: &forge_provisioning::RebuildEnvironment,
    ) -> Result<(), forge_provisioning::ProvisioningError> {
        let actual = self.inspect_rebuild()?;
        if actual.domain_state != VmState::Shutoff
            || actual.domain_uuid != expected.domain_uuid
            || actual.current_overlay_path != expected.current_overlay_path
            || actual.current_backing_path != expected.current_backing_path
            || actual.base_path != expected.base_path
            || !actual.base_exists
            || actual.seed_path != expected.seed_path
            || !actual.seed_exists
        {
            return Err(forge_provisioning::ProvisioningError::Backend(
                "durable Fedora-Lab resources changed before domain switch".to_owned(),
            ));
        }
        Ok(())
    }

    fn switch_and_verify(
        &mut self,
        plan: &forge_provisioning::RebuildPlan,
    ) -> Result<(), forge_provisioning::ProvisioningError> {
        Domain::define_xml(&self.connection, &plan.domain_xml)
            .map_err(provisioning_backend_error)?;
        let domain = self.domain()?;
        let xml = domain.get_xml_desc(0).map_err(provisioning_backend_error)?;
        if !domain.is_persistent().map_err(provisioning_backend_error)?
            || domain_disk_path(&xml).as_deref() != Some(plan.new_overlay_path.as_str())
            || !xml.contains(&plan.new_seed_path)
            || xml.matches("org.qemu.guest_agent.0").count() != 1
            || !xml.contains("<readonly")
        {
            return Err(forge_provisioning::ProvisioningError::Backend(
                "persistent domain XML verification failed after switch".to_owned(),
            ));
        }
        Ok(())
    }

    fn rollback_new_resources(
        &mut self,
        context: &forge_provisioning::RebuildContext,
    ) -> Vec<String> {
        let mut failures = Vec::new();
        let Ok(pool) = self.pool() else {
            return vec!["cannot open default pool for rebuild rollback".to_owned()];
        };
        for (created, name) in [
            (
                context.seed_created,
                context.seed_name.as_deref().unwrap_or(""),
            ),
            (
                context.overlay_created,
                context.overlay_name.as_deref().unwrap_or(""),
            ),
        ] {
            if created
                && let Ok(volume) = StorageVol::lookup_by_name(&pool, name)
                && let Err(error) = volume.delete(0)
            {
                failures.push(format!("cannot delete {name}: {error}"));
            }
        }
        failures
    }
}

fn provisioning_backend_error(error: VirtError) -> forge_provisioning::ProvisioningError {
    let message = error.to_string();
    drop(error);
    forge_provisioning::ProvisioningError::Backend(format!(
        "libvirt provisioning operation failed: {message}"
    ))
}

fn parse_ssh_observation(output: &std::process::Output) -> forge_provisioning::SshObservation {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let Some((cloud_output, identity_and_hostname)) = stdout.split_once("__FORGE_ID__") else {
        return forge_provisioning::SshObservation {
            status: if stderr.to_ascii_lowercase().contains("permission denied") {
                forge_provisioning::SshStatus::AuthenticationFailed
            } else {
                forge_provisioning::SshStatus::Reachable
            },
            cloud_init: forge_provisioning::CloudInitStatus::Unknown,
            forge_user_confirmed: false,
            hostname: None,
        };
    };
    let (identity, hostname) = identity_and_hostname
        .split_once("__FORGE_HOSTNAME__")
        .unwrap_or((identity_and_hostname, ""));
    let cloud_init = if cloud_output
        .lines()
        .any(|line| line.trim() == "status: done")
    {
        forge_provisioning::CloudInitStatus::Done
    } else if cloud_output
        .lines()
        .any(|line| line.trim() == "status: running")
    {
        forge_provisioning::CloudInitStatus::Running
    } else if cloud_output
        .lines()
        .any(|line| line.trim() == "status: error")
    {
        forge_provisioning::CloudInitStatus::Error(cloud_output.trim().to_owned())
    } else {
        forge_provisioning::CloudInitStatus::Unknown
    };
    forge_provisioning::SshObservation {
        status: forge_provisioning::SshStatus::Authenticated,
        cloud_init,
        forge_user_confirmed: identity.contains("forge"),
        hostname: hostname
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .map(str::to_owned),
    }
}

fn parse_recovery_ssh_observation(
    output: &std::process::Output,
) -> forge_provisioning::SshObservation {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        return forge_provisioning::SshObservation {
            status: if stderr.to_ascii_lowercase().contains("permission denied") {
                forge_provisioning::SshStatus::AuthenticationFailed
            } else {
                forge_provisioning::SshStatus::Reachable
            },
            cloud_init: forge_provisioning::CloudInitStatus::Unknown,
            forge_user_confirmed: false,
            hostname: None,
        };
    }
    let lines = stdout.lines().map(str::trim).collect::<Vec<_>>();
    let identity_position = lines.iter().position(|line| line.starts_with("uid="));
    let identity = identity_position.map_or("", |position| lines[position]);
    let hostname = identity_position.and_then(|position| {
        lines[position + 1..]
            .iter()
            .find(|line| !line.is_empty())
            .map(|line| (*line).to_owned())
    });
    let cloud_init = if lines.contains(&"status: done") {
        forge_provisioning::CloudInitStatus::Done
    } else if lines.contains(&"status: running") {
        forge_provisioning::CloudInitStatus::Running
    } else if lines.contains(&"status: error") {
        forge_provisioning::CloudInitStatus::Error(stdout.trim().to_owned())
    } else {
        forge_provisioning::CloudInitStatus::Unknown
    };
    forge_provisioning::SshObservation {
        status: forge_provisioning::SshStatus::Authenticated,
        cloud_init,
        forge_user_confirmed: identity.starts_with("uid=1000(forge)"),
        hostname,
    }
}

fn seed_volume_xml(name: &str, capacity_bytes: u64) -> String {
    format!(
        "<volume type='file'><name>{name}</name><capacity unit='bytes'>{capacity_bytes}</capacity><allocation unit='bytes'>0</allocation><target><format type='raw'/></target></volume>"
    )
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
    use std::os::unix::process::ExitStatusExt;

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

    #[test]
    fn renders_seed_storage_volume_xml() {
        assert_eq!(
            seed_volume_xml("fedora-lab-seed.iso", 374_784),
            "<volume type='file'><name>fedora-lab-seed.iso</name><capacity unit='bytes'>374784</capacity><allocation unit='bytes'>0</allocation><target><format type='raw'/></target></volume>"
        );
    }

    #[test]
    fn shutoff_domain_backing_is_recovered_from_storage_metadata() {
        let domain_xml = "<domain><devices><disk type='file' device='disk'><source file='/pool/fedora-lab.rebuild.qcow2'/><target dev='vda'/></disk></devices></domain>";
        let volumes = vec![
            (
                "/pool/fedora-lab.rebuild.qcow2".to_owned(),
                Some("/pool/forge-base-fedora-44.qcow2".to_owned()),
            ),
            ("/pool/forge-base-fedora-44.qcow2".to_owned(), None),
        ];
        assert_eq!(
            active_volume_backing(domain_xml, &volumes).as_deref(),
            Some("/pool/forge-base-fedora-44.qcow2")
        );
        assert!(!domain_xml.contains("backingStore"));
    }

    #[test]
    fn ssh_output_confirms_authentication_user_hostname_and_cloud_init() {
        let output = std::process::Output {
            status: std::process::ExitStatus::from_raw(0),
            stdout: b"status: done\n__FORGE_ID__\nuid=1000(forge) gid=1000(forge)\n__FORGE_HOSTNAME__\nfedora-lab\n".to_vec(),
            stderr: vec![],
        };
        let observation = parse_ssh_observation(&output);
        assert_eq!(
            observation.status,
            forge_provisioning::SshStatus::Authenticated
        );
        assert_eq!(
            observation.cloud_init,
            forge_provisioning::CloudInitStatus::Done
        );
        assert!(observation.forge_user_confirmed);
        assert_eq!(observation.hostname.as_deref(), Some("fedora-lab"));
    }

    #[test]
    fn ssh_permission_denied_is_not_authentication_success() {
        let output = std::process::Output {
            status: std::process::ExitStatus::from_raw(255 << 8),
            stdout: vec![],
            stderr: b"forge@host: Permission denied (publickey).".to_vec(),
        };
        let observation = parse_ssh_observation(&output);
        assert_eq!(
            observation.status,
            forge_provisioning::SshStatus::AuthenticationFailed
        );
        assert_eq!(
            observation.cloud_init,
            forge_provisioning::CloudInitStatus::Unknown
        );
        assert!(!observation.forge_user_confirmed);
    }
}
