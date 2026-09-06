# Fedora host setup for Forge V2.5

This file records the **clean-host prerequisites actually verified on Fedora 44** before building Forge V2.5 from source.

The goal is to keep host setup small and explicit. Do not restore historical Forge brokers, helpers, PolicyKit rules, custom sockets, or other experimental host infrastructure unless a current V2.5 feature proves that it is required.

## 1. Update Fedora

```bash
sudo dnf upgrade --refresh
```

Reboot if the update requires it.

## 2. Install the virtualization stack

```bash
sudo dnf install @virtualization
sudo dnf install virt-manager
sudo systemctl enable --now libvirtd
```

Basic clean-host checks:

```bash
virsh -c qemu:///system list --all
virsh -c qemu:///system net-list --all
virsh -c qemu:///system pool-list --all
```

A clean host may legitimately have **zero VMs and zero storage pools**. Do not create a storage pool only to make this check look populated. The standard libvirt `default` network should be available for the current Forge workflow.

## 3. Install build prerequisites

Forge uses the Rust `virt` / `virt-sys` bindings to system libvirt. Building therefore needs the libvirt development files, not only the runtime library.

```bash
sudo dnf install git libvirt-devel
```

Verify that `pkg-config` can see both libvirt interfaces:

```bash
pkg-config --modversion libvirt libvirt-qemu
pkg-config --libs libvirt libvirt-qemu
```

Expected library flags include:

```text
-lvirt-qemu -lvirt
```

### Important: first build attempted before `libvirt-devel`

If `cargo build` was attempted **before** installing `libvirt-devel`, `virt-sys` may already have cached build artifacts from the failed dependency probe. In that case, installing `libvirt-devel` alone may still leave linker errors such as:

```text
undefined symbol: virGetLastError
undefined symbol: virDomainGetXMLDesc
undefined symbol: virConnectOpen
```

After installing `libvirt-devel`, force a clean rebuild:

```bash
cargo clean
cargo build
```

This exact clean-host failure and recovery were reproduced during the Fedora 44 V2.5 restart.

## 4. Install Rust

For Forge development, the current setup uses the official `rustup` toolchain manager rather than Fedora's packaged Rust toolchain.

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

Verify:

```bash
rustc --version
cargo --version
rustup --version
```

The default rustup profile supplies the normal development components, including `cargo`, `rustfmt`, and `clippy`.

## 5. Clone Forge V2.5

```bash
cd ~
git clone https://github.com/gogu-glogowski/Forge-v2.git
cd Forge-v2
git fetch --all --tags
git switch v2.5-dev
```

Then perform the first clean-host build:

```bash
cargo build
```

Run the test suite separately:

```bash
cargo test
```

At the clean-host checkpoint documented here, the main build succeeds after the prerequisites above. A historical `forge-guest-mutation` / GME test still depends on old host-specific staging state; GME is outside the V2.5 critical product path and should not be "fixed" by recreating obsolete host infrastructure.

## Host setup rule

Prefer normal Fedora packages and standard libvirt facilities. Forge V2.5 should require as little custom privileged host infrastructure as possible. Rare host-level operations should remain explicit rather than being hidden behind a generic privileged broker.
