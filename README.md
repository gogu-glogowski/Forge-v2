# Forge V2.5

Forge is a Fedora-first Rust management layer for persistent KVM/QEMU/libvirt
VMs. It keeps durable ownership of VM generations, verifies image provenance,
checks backing chains, and fails closed when identity or destructive ownership
cannot be proven exactly.

Forge V2.5 manages these supported primary paths:

- Kali Lab
- Fedora Workstation
- Whonix Gateway
- Whonix Workstation

The current desktop and security profiles are persistent `ManualGuest`s.
Forge does not use guest-exec, SSH/QGA guest management, cloud-init
provisioning, or automatic guest personalization for these paths. V2.5 has no
Disposable mode, GME, custom privileged broker, or helper service.

For Fedora host prerequisites, see [docs/FEDORA_SETUP.md](docs/FEDORA_SETUP.md).
For a simple first-use path, see
[docs/FORGE_V2_5_QUICKSTART.md](docs/FORGE_V2_5_QUICKSTART.md). For detailed
technical and operator guidance, see
[docs/FORGE_V2_5_USER_GUIDE.md](docs/FORGE_V2_5_USER_GUIDE.md).

## Installation from source

Forge V2.5 is distributed from source. On a Fedora host with Rust/Cargo and
the required virtualization stack installed, clone the repository and build the
release binary:

```bash
git clone https://github.com/gogu-glogowski/Forge-v2.git
cd Forge-v2
cargo build --release -p forge-cli
mkdir -p ~/.local/bin
install -m 755 target/release/forge ~/.local/bin/forge
```

Verify that `~/.local/bin` is in your `PATH`, then confirm the installation:

```bash
command -v forge
forge --help
forge doctor
```

If `command -v forge` prints a path such as `~/.local/bin/forge`, the CLI is
ready to use from any directory. Forge V2.5 does not provide an RPM/DNF package.

## Everyday workflow

Start by checking the host and discovering supported profiles and image state:

```bash
forge doctor
forge profile list
forge image list
```

Plan before creating a VM:

```bash
forge vm plan kali-lab kali-1
forge vm create kali-lab kali-1 --dry-run
```

Kali acquisition verifies the official artifact before its prepared base can be
used:

```bash
forge image inspect kali
forge image fetch kali
forge vm create kali-lab kali-1
```

Normal lifecycle operations are profile-driven and operate only on exact
managed identity:

```bash
forge vm start <instance>
forge vm status <instance>
forge vm shutdown <instance>
forge vm clone <source-instance> <target-instance>
forge vm fresh <instance>
forge delete <instance>
```

`forge delete` remains fail-closed: it removes only exact, Forge-owned mutable
resources after durable-state, UUID, storage, and backing-chain validation.
Trusted reusable bases are not disposable generation resources.

## Fedora Workstation

Fedora Workstation preparation is operator-assisted. Forge verifies the
installation source, creates an exact temporary installer topology, and guides
the operator through graphical Anaconda installation. After explicit graphical
confirmation and promotion, the result is a protected canonical reusable base.

```bash
forge image fetch fedora-workstation
forge image prepare fedora-workstation
forge image prepare-start fedora-workstation
# complete Anaconda graphically, then use the displayed preparation boundaries
forge image prepare-promote fedora-workstation
forge vm create fedora-workstation fedora-workstation-1
```

Clones from a promoted Workstation base inherit the contents of the
operator-prepared canonical system. Forge does not create guest accounts,
bootstrap personal settings, update guest packages, or normalize the guest
automatically.

## Whonix

Whonix V2.5 uses one canonical managed pair:

```text
whonix-gateway
whonix-workstation
```

The Gateway and Workstation have an explicit complementary topology. Custom
pair names require an explicit durable pair-binding design and are not
supported in V2.5.

```bash
forge vm create whonix-gateway whonix-gateway
forge vm create whonix-workstation whonix-workstation
forge vm start whonix-gateway
forge vm start whonix-workstation
```

## Inventory and maintenance

`forge image list` is a fast local inventory. Its recorded-verification status
comes from durable metadata and is not a fresh full cryptographic proof; full
verification remains at fetch, preparation, and create boundaries.

Recovery, reconciliation, cleanup, adoption, and legacy Fedora Cloud commands
are maintenance surfaces rather than daily workflow. Use `forge --help` to see
their explicit forms. Legacy Fedora Cloud/NoCloud remains readable only for
compatibility; new V2.5 use should select Fedora Workstation instead.
