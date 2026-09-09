Name:           forge
Version:        2.5.0
Release:        1
Summary:        Persistent KVM/QEMU/libvirt VM lifecycle manager

License:        Apache-2.0
URL:            https://github.com/gogu-glogowski/Forge-v2
Source0:        %{name}-%{version}.tar.gz

# Forge V2.5 is accepted and released for the x86_64 Fedora/KVM host path.
ExclusiveArch:  x86_64

BuildRequires:  cargo
BuildRequires:  rust
BuildRequires:  gcc
BuildRequires:  pkgconfig(libvirt)
BuildRequires:  pkgconfig(libvirt-qemu)

# These programs are invoked by supported V2.5 image and storage operations.
# libvirt and libvirt-qemu shared-library requirements are generated from the
# ELF binary by RPM's normal dependency generator.
Requires:       curl
Requires:       gnupg2
Requires:       gnupg2-verify
Requires:       qemu-img
Requires:       tar
Requires:       xz
Requires:       7zip

%description
Forge is a Fedora-first management layer for persistent KVM/QEMU/libvirt VMs.
It verifies image provenance, records durable ownership of VM generations, and
fails closed when identity or destructive ownership cannot be proven exactly.

This package installs only the forge CLI. It does not create libvirt networks
or storage pools, alter SELinux or firewalld, install PolicyKit rules, or
include VM images, runtime state, or user data.

%prep
%autosetup

%build
cargo build --release --locked --package forge-cli

%install
install -Dpm 0755 target/release/forge %{buildroot}%{_bindir}/forge

%files
%license LICENSE
%{_bindir}/forge

%changelog
* Wed Sep 09 2026 Forge V2.5.0 Release Team <release@forge.invalid> - 2.5.0-1
- Initial Fedora RPM package for Forge V2.5.0.
