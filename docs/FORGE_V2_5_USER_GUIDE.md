# Forge V2.5 User Guide

Forge V2.5 is a Fedora-first Rust manager for a small, security-focused fleet
of persistent KVM/QEMU/libvirt VMs. It verifies image provenance, creates
libvirt storage and domains, records durable ownership, and fails closed when
an identity or destructive-operation proof is incomplete.

Supported V2.5 primary profiles are Kali Lab, Fedora Workstation, Whonix
Gateway, and Whonix Workstation. Their normal lifecycle is persistent and
managed by Forge.

## Product boundary

Forge manages host-side VM lifecycle, trusted/shared bases, writable layers,
and durable ownership. It does not make an untrusted guest safe by itself.

V2.5 deliberately has no Disposable mode, cloud-init path for the supported
ManualGuest profiles, SSH guest provisioning, QGA guest-exec, automatic guest
account creation, automatic guest personalization, GME, or custom privileged
broker/helper. Guest operating-system configuration remains an operator task.

## Before installing

### Required

- A supported Fedora host with hardware virtualization and KVM available.
- System libvirt/QEMU and the normal `qemu:///system` connection.
- The libvirt `default` storage pool, active and backed by an absolute target
  path. Forge uses it for images and VM disks.
- The standard libvirt `default` network for profiles using default NAT.
- Rust/Cargo and `libvirt-devel` to build from source.

Use the verified Fedora host instructions in
[FEDORA_SETUP.md](FEDORA_SETUP.md). A clean host may have no VMs or pools; the
`default` pool is the required exception before the first create. Forge doctor
reports missing or inactive storage but does not create or change it.

### Recommended

- `virt-manager` for graphical installation and normal interactive guest use.
- Enough free space for large upstream archives, prepared images, shared bases,
  and writable VM disks. Image verification and imports can be disk- and
  time-intensive.
- Normal Fedora SELinux and firewall policy. Do not disable either for Forge.

### Optional / host authorization

System libvirt access can invoke normal Fedora PolicyKit authorization. Forge
does not collect passwords, install broad `NOPASSWD` rules, or require a custom
daemon. For a create that needs system authorization, Forge performs its host
authorization preflight before long image verification where possible.

## Install Forge V2.5.0 from source

Forge V2.5.0 is distributed from source, not as an RPM/DNF package.

```bash
git clone https://github.com/gogu-glogowski/Forge-v2.git
cd Forge-v2
git checkout v2.5.0
cargo build --release -p forge-cli
mkdir -p ~/.local/bin
install -m 755 target/release/forge ~/.local/bin/forge
```

Ensure `~/.local/bin` is in `PATH`, then verify the binary:

```bash
command -v forge
forge --help
forge doctor
```

## First-run checks

```bash
forge doctor
forge profile list
forge image list
```

`forge doctor` observes the host. `Ready` or `Degraded` describe the detected
host state; `Unsupported` means the host itself is outside Forge's supported
Fedora contract and remains Unsupported even if storage is also missing.
`Incomplete`, Missing, Inactive, Unusable, or Unavailable storage diagnostics
must be corrected by the operator with normal libvirt administration. Doctor
does not silently provision the host.

Use `forge profile show <profile>` and `forge vm plan <profile> <instance>` to
inspect a profile and a no-mutation instance plan.

## Kali Lab

### Create a Kali VM

```bash
forge image list
forge image inspect kali
forge image fetch kali
forge image inspect kali
forge vm plan kali-lab kali-1
forge vm create kali-lab kali-1 --dry-run
forge vm create kali-lab kali-1
```

The fetch path obtains the official Kali QEMU artifact, validates the detached
checksum signature and authenticated checksums, and publishes a prepared
artifact. Create imports or reuses an exactly proven shared base, then creates
a persistent writable layer for the instance. First acquisition and proof can
take substantial time.

Start and use the VM through Forge and a graphical viewer such as virt-manager:

```bash
forge vm start kali-1
forge vm status kali-1
forge vm shutdown kali-1
```

### Manual work inside Kali

Follow upstream Kali image/login guidance; Forge does not establish or document
default credentials. Inside the guest, the operator chooses or changes
credentials, applies guest updates, installs tools, and configures desktop and
personal settings.

### Clone, Fresh, and delete

```bash
forge vm clone kali-1 kali-2 --dry-run
forge vm clone kali-1 kali-2
forge vm fresh kali-1 --dry-run
forge vm fresh kali-1
forge delete kali-2
```

Clone creates a new persistent VM with a full flattened copy of the source
writable disk; guest identity regeneration is not automated. `fresh` replaces
the active Kali generation from its trusted base; it is neither an in-guest
update nor a shared-base update.

## Fedora Workstation

Fedora Workstation uses an operator-assisted path. Forge proves the official
ISO, owns the temporary host-side preparation state, and promotes an explicitly
verified installation to a protected canonical base. The operator performs the
guest installation and configuration graphically.

### Preparation and promotion

```bash
# [FORGE] Obtain and inspect the official Workstation ISO.
forge image fetch fedora-workstation
forge image inspect fedora-workstation

# [FORGE] Create/resume the preparation transaction and installer domain.
forge image prepare fedora-workstation
forge image prepare-status fedora-workstation
forge image prepare-start fedora-workstation
```

At this point, open the named preparation domain in virt-manager.

```text
[MANUAL — INSIDE VM]
Complete graphical Anaconda onto the existing staging disk. Choose installation
and account settings deliberately. Complete the initial graphical boot you want
the canonical system to contain, then shut the preparation guest down normally
when Forge asks for a shutoff boundary.
```

After installation, Forge prints the next boundary. The normal public sequence
is:

```bash
# [FORGE] After Anaconda completes and the installer domain is shut off.
forge image prepare-confirm-installed fedora-workstation

# [FORGE] This detaches installer media and boots the installed staging disk.
forge image prepare-continue fedora-workstation

# [MANUAL — INSIDE VM]
# Verify the installed graphical Fedora system is running as intended.

# [FORGE] Record the explicit graphical confirmation.
forge image prepare-confirm-graphical fedora-workstation

# [MANUAL — INSIDE VM]
# Shut the preparation guest down normally.

# [FORGE] Promote the proven staging disk to the canonical protected base.
forge image prepare-promote fedora-workstation
forge image prepare-status fedora-workstation
```

At confirmation and promotion Forge prints an exact `qemu-img check` command
for the preparation-owned disk. Run that exact command in another terminal,
inspect its successful result, and enter `CHECKED` only when prompted. Forge
does not run sudo or accept an arbitrary operator path.

Create ordinary persistent Workstation instances only after promotion:

```bash
forge vm plan fedora-workstation fedora-workstation-1
forge vm create fedora-workstation fedora-workstation-1
forge vm start fedora-workstation-1
```

The promoted canonical system is not sanitized by Forge. Normal Workstation
VMs and clones inherit its installed contents, accounts, credentials, GNOME
settings, repositories, and software. Before promotion, intentionally perform
the guest work that should be inherited: Anaconda choices, user/password,
GNOME Initial Setup, language/timezone/preferences, updates, repositories, and
personal software. Forge does not create, remove, or personalize guest users.

If a preparation must be abandoned, use the displayed preparation ID:

```bash
forge image abort fedora-workstation <preparation-id>
```

## Whonix Gateway and Workstation

Whonix is a coordinated persistent pair with explicit Forge-managed topology.
V2.5 enforces these canonical instance identities:

```text
Gateway:     whonix-gateway
Workstation: whonix-workstation
```

Custom-named pairs are not supported. Create the Gateway first, then the
Workstation:

```bash
forge vm plan whonix-gateway whonix-gateway
forge vm create whonix-gateway whonix-gateway
forge vm plan whonix-workstation whonix-workstation
forge vm create whonix-workstation whonix-workstation

forge vm start whonix-gateway
forge vm start whonix-workstation
forge vm status whonix-gateway
forge vm status whonix-workstation
```

Gateway and Workstation bundle acquisition, provenance validation, and large
artifact hashing occur at the appropriate create/preparation boundary; there is
no separate public Whonix `image fetch` command. This can take substantial time.

For shutdown, stop the Workstation before the Gateway when practical:

```bash
forge vm shutdown whonix-workstation
forge vm shutdown whonix-gateway
```

Inside Whonix, complete the upstream first-run and security configuration,
manage credentials, apply guest updates, and set preferences manually. Use
upstream Whonix documentation for security-specific guidance; Forge does not
replace it.

## Normal daily lifecycle

```bash
forge vm list
forge vm status <instance>
forge vm start <instance>
forge vm shutdown <instance>
forge vm stop <instance> --force
forge vm clone <source-instance> <target-instance>
forge vm fresh <instance>
forge delete <instance>
```

`shutdown` is the normal graceful request. `stop --force` is an explicit
power-cut operation and is not an automatic fallback. Clone and Fresh are
supported only where the profile/storage policy accepts them; inspect their
dry-runs first. A clone is an independent persistent target disk; Fresh is a
safe replacement flow from a trusted base, not a distribution update.

## Image and base model

```text
upstream artifact → verification → protected/shared base → writable persistent VM
```

The shared base is infrastructure, not disposable VM state. VM changes belong
to the writable layer. Forge does not silently rewrite existing VMs when an
upstream release or base changes. Fedora Workstation substitutes an
operator-installed, promoted canonical base for the upstream-base stage.

## Manual and automated responsibilities

| Task | Forge | Operator |
|---|---|---|
| Host readiness diagnosis | Observes and reports | Installs/configures host prerequisites |
| Image provenance | Verifies at supported boundaries | Chooses when to acquire/use images |
| Libvirt domains and storage | Creates exact managed resources | Supplies normal host authorization when required |
| VM lifecycle | Plans and executes exact managed actions | Starts graphical viewer and uses guest |
| Fedora Anaconda | Creates preparation boundary | Installs Fedora graphically |
| Guest username/password | Does not manage | Creates and maintains |
| Guest updates/software/personalization | Does not manage | Performs inside guest |
| Recovery | Refuses unsafe inference and exposes commands | Reviews evidence and explicitly confirms recovery |

## Safe delete and recovery

`forge delete <instance>` plans deletion only for the exact Forge-managed
domain UUID and durable resource identities. Shared bases are excluded. If
identity, ownership, storage, backing, or domain state is ambiguous, delete
refuses rather than guessing from names.

For a running VM, inspect first and use force only when a deliberate power-cut
is necessary:

```bash
forge vm status <instance>
forge delete <instance> --force
```

Interrupted initial create is an explicit recovery boundary, not an invitation
to adopt a matching name. Start with a no-mutation plan:

```bash
forge state recover <instance> --dry-run
forge state recover <instance>
```

Use `forge state reconcile <instance>` when status reports a state/domain
mismatch. If image inventory reports Conflict, Orphaned, or Interrupted, do not
rename, delete, or fabricate state manually; inspect the reported condition and
use only the specific recovery command exposed by Forge. For interrupted
Whonix Workstation image preparation, the public recovery surface is:

```bash
forge image recover whonix-workstation --dry-run
forge image recover whonix-workstation
```

## Security model and limitations

Forge is not Qubes OS and does not protect against a compromised host, libvirt,
or hypervisor. It provides host-side ownership, topology, backing, and
lifecycle checks; guest configuration and guest compromise remain operator
responsibilities. Treat shared bases as protected infrastructure. V2.5 has no
Disposable VM mode, automatic guest management, or broad privileged Forge
daemon.

## Quick reference

### Host

```bash
forge doctor
forge profile list
forge profile show <profile>
forge vm plan <profile> <instance>
```

### Images

```bash
forge image list
forge image inspect kali
forge image fetch kali
forge image inspect fedora-workstation
forge image fetch fedora-workstation
```

### VM

```bash
forge vm create <profile> <instance> [--dry-run]
forge vm list
forge vm status <instance>
forge vm start <instance> [--dry-run]
forge vm shutdown <instance> [--dry-run]
forge vm stop <instance> --force [--dry-run]
forge vm clone <source> <target> [--dry-run]
forge vm fresh <instance> [--dry-run]
forge delete <instance> [--force]
```

### Fedora Workstation preparation

```bash
forge image prepare fedora-workstation [--dry-run]
forge image prepare-status fedora-workstation
forge image prepare-start fedora-workstation
forge image prepare-confirm-installed fedora-workstation
forge image prepare-continue fedora-workstation
forge image prepare-confirm-graphical fedora-workstation
forge image prepare-promote fedora-workstation
forge image abort fedora-workstation <preparation-id>
```

### Recovery

```bash
forge state reconcile <instance>
forge state recover <instance> [--dry-run]
forge image recover whonix-workstation [--dry-run]
```
