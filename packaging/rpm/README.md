# Forge V2.5.0 Fedora RPM

This directory contains the RPM spec for the released Forge V2.5.0 source
tree. The package is intentionally small: it installs `/usr/bin/forge` and
its license only. It does not contain VM images, ISOs, qcow2 files, Forge
state, libvirt state, caches, or logs.

## Build

Build on Fedora x86_64 with the normal RPM build tools and the build
requirements declared in `forge.spec`:

```bash
sudo dnf install rpm-build cargo rust gcc libvirt-devel
mkdir -p ~/rpmbuild/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
git archive --format=tar.gz --prefix=forge-2.5.0/ v2.5.0 \
  -o ~/rpmbuild/SOURCES/forge-2.5.0.tar.gz
rpmbuild -ba packaging/rpm/forge.spec
```

The binary RPM is written below `~/rpmbuild/RPMS/x86_64/` as
`forge-2.5.0-1.x86_64.rpm`.

The source archive must be made from the immutable `v2.5.0` tag. Packaging
files are maintained in the repository after that tag, so they are supplied to
`rpmbuild` from the checkout rather than expected inside the archive.

## Local installation and removal

Install a locally built or downloaded RPM by path:

```bash
sudo dnf install ./forge-2.5.0-1.x86_64.rpm
forge --help
forge doctor
```

There is no Fedora or COPR repository for this package yet, so `sudo dnf
install forge` is not a supported installation command.

To remove only the package:

```bash
sudo dnf remove forge
```

RPM removal removes `/usr/bin/forge` and package-owned metadata only. Forge
runtime data is user-local and libvirt resources are not package-owned, so the
package does not remove VM images, Forge state, libvirt domains, networks, or
storage pools.

## Host configuration boundary

The RPM does not create or alter libvirt networks, storage pools, SELinux
policy, firewalld rules, PolicyKit rules, users, groups, services, sockets, or
privileged helpers. Prepare the host explicitly as described in
[`docs/FEDORA_SETUP.md`](../../docs/FEDORA_SETUP.md), then use `forge doctor`
to observe readiness. The human first-use workflow is in
[`docs/FORGE_V2_5_QUICKSTART.md`](../../docs/FORGE_V2_5_QUICKSTART.md).
