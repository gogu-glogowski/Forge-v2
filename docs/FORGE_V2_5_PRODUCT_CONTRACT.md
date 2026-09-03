# Forge V2.5 Product Contract

## Status and scope

Forge V2.5 is an incremental usability and automation release built on the accepted Forge V2 safety architecture. It is not a rewrite. The accepted V2 release remains historically immutable at tag `v2.0.0`, peeled commit `b44715c355b513bab54492f9999439c756059b0b`.

This contract defines product intent, safety boundaries, priorities, and implementation order. It does not select final command names or authorize weakening an existing proof boundary. Where command-like terms appear below, they describe user concepts only; their exact CLI spelling and API shape are provisional and require later design.

V2.5 is primarily:

> usability + automation + fast reuse of trusted bases

## 1. V2 invariants that must not regress

All V2.5 design and implementation must preserve these foundations:

- **Durable generations.** Forge records immutable generation identity and durable lifecycle state rather than inferring ownership from names or current shape.
- **Reconciliation.** Durable intent must be compared with fresh libvirt domain and storage observations. A manifest alone is not sufficient proof of current reality.
- **Exact ownership.** Mutation and cleanup require exact, durable ownership evidence. Similar names, matching shapes, or apparent lack of references do not establish ownership.
- **Backing-chain validation.** Every managed overlay must resolve to the exact expected trusted base. Missing, changed, or ambiguous backing relationships fail closed.
- **Cryptographic image provenance.** Profile-specific source authentication and verification remain mandatory. Verification must establish why an artifact is trusted, not merely that bytes match an unauthenticated digest.
- **Fail-closed recovery.** Interrupted or ambiguous operations enter an explicit recovery boundary. Forge must neither infer success nor silently roll back, adopt, promote, or delete resources.
- **Exact UUID/generation lifecycle binding.** Domain UUID, generation ID, pool identity, volume keys and paths, resource roles, and relevant backing relationships remain bound and revalidated at lifecycle boundaries.
- **ManualGuest running-only lifecycle.** Normal ManualGuest start succeeds after preflight, domain start, and a bounded proof that the domain is running. It must not inherit Fedora/NoCloud DHCP, QGA, SSH, cloud-init, hostname, or user requirements.
- **Explicit force-stop.** Graceful stop must not silently escalate to a power cut. Forced stop remains a separate, explicit operation with clear destructive semantics.
- **Whonix enforced topology.** Gateway and Workstation retain exact paired identity. Gateway has its approved uplink and paired UDP link; Workstation has only the complementary UDP endpoint and no alternate uplink.
- **No large image hashing during ordinary runtime lifecycle.** Start, status, stop, and ordinary reconciliation must not repeat expensive full-image verification. They may validate compact, durable evidence and the exact identities and relationships required by their safety boundary.
- **Policy-driven lifecycle.** Profile policy continues to decide provisioning and success requirements. No universal guest readiness assumption may be introduced for convenience.

These invariants constrain every P0 goal below. Usability work may orchestrate existing proof-bearing operations, but it must not bypass them.

## 2. V2.5 primary product goals

### P0 — Shared trusted base reuse

Creating an additional instance from an already verified and prepared base must reuse and prove that exact shared base instead of refusing merely because it exists.

The known V2 user test is:

```text
forge vm create kali-lab kali-2
```

Planning succeeded, but execution refused with:

```text
exact planned volume already exists:
forge-base-kali-2026.2.qcow2
```

The required architecture is:

```text
trusted Kali base
  ├── kali-lab overlay
  ├── kali-2 overlay
  └── additional independent overlays
```

An existing object at the planned shared-base location has only two valid outcomes:

- **REUSE / PROVE:** exact trusted-base identity, provenance evidence, storage identity, format, and other required properties are proven; Forge reuses it as a protected shared dependency.
- **CONFLICT / REFUSE:** the object is wrong, unproven, ambiguous, drifted, or cannot be tied to the required trusted evidence; Forge performs no dependent mutation.

Existence alone is neither proof nor conflict. Reuse must never convert the shared base into disposable ownership of an individual instance or generation.

### P0 — Fresh / reinstall

A normal user must be able to replace an existing managed VM with a fresh generation from an already trusted base without manually composing recovery, rebuild, storage, definition, or state commands.

The high-level operation must:

- preserve fail-closed ownership, reconciliation, backing-chain, and recovery rules;
- prepare and durably own the replacement generation first;
- leave the current working generation intact and active while preparation and proof are incomplete;
- switch persistent domain configuration only through the existing exact identity and topology boundaries;
- publish the replacement as `Active` only after the profile-specific success proof completes;
- retain the previous generation according to policy rather than destroying it during replacement; and
- reuse sufficient trusted evidence to avoid repeating expensive upstream acquisition and verification when the exact existing trusted base can be safely proven.

Any interruption before final publication must remain recoverable and must not cause Forge to guess which generation is active.

### P0 — Persistent clone

Provide a simple user-level operation that creates another independently owned, persistent VM from an existing trusted base/profile. Each clone receives its own instance identity, domain identity, durable generation state, and writable storage. The shared base remains protected and non-disposable.

Phase 2 defines persistent clone as a copy of the source instance's current visible disk state into a new flattened qcow2. The target therefore has no dependency on the source generation-owned overlay; deleting or rebuilding the source cannot invalidate the target. Clone does not mean a sibling-from-base operation, adopting an arbitrary existing domain, or weakening per-instance ownership. The initial supported profile is shutoff, Consistent Kali ManualGuest. Fedora NoCloud and Whonix paired workloads require separate clone designs. Disk cloning does not itself regenerate guest-level machine identity, SSH host keys, hostname, DHCP identifiers, or application state; Forge must report that limitation rather than claim identity independence.

### P0 — Fresh / reinstall transaction contract

Fresh (the provisional user-facing concept; `fresh`, `reinstall`, or another final spelling remains undecided) replaces the Active generation of an existing managed instance with a new generation produced from that instance's durably bound profile and trusted-base policy. It is a reset to profile semantics, not a clone of current guest state, an in-place erase, or a low-level rebuild. Profile resolution must use durable ownership and must refuse missing or ambiguous binding; it must never infer a profile from an instance name or filename.

The baseline preconditions are: Persistent policy, exactly one Active generation, Consistent reconciliation, shutoff domain, no Preparing or recovery-required state, exact active storage identity, and a profile class with an explicitly designed fresh operation. A running source is refused; Forge does not shut it down or perform live replacement. The initial implementation target should be Kali ManualGuest. Fedora requires explicit NoCloud/seed semantics, and Whonix requires pair-aware replacement or a typed refusal; one-sided fresh must not weaken Gateway/Workstation topology or endpoint identity.

Fresh creates a new generation ID, generation-owned writable overlay, profile-required seed, and any required new domain UUID while retaining the stable instance name and profile binding. The old Active generation remains unchanged and authoritative while the replacement is prepared, cryptographically/provenance checked as required, defined, and reconciled. The durable activation commit point is the existing atomic index transition: new generation becomes Active and the old generation becomes Retained in one durable state update. Before that point, failure leaves the old Active authoritative; after it, the new Active is authoritative and automatic reverse rollback is forbidden unless an existing proven primitive can make it atomic.

Phase 3.1 supplies a pure typed Fresh planner and transaction-state model for these rules; it performs no host mutation. It reuses the existing generation index and atomic publication primitive, including the current stable instance domain-UUID convention, and carries exact observed ownership into later execution rather than re-resolving decisions from names. The durable index writer uses a private temporary file, flush/sync, rename, and parent-directory sync, so the returned single-index transition is published all-or-nothing. Stable UUID preservation does not authorize redefining the old domain before the replacement is proven; later execution must define and validate replacement resources first.

Failure before storage mutation has zero mutation. Overlay or seed failure rolls back only resources created by the transaction. After Preparing publication, domain-definition, inspection, or activation interruption is an explicit recovery boundary; Forge must report exact state and must not guess success or delete the old Active. After activation, the old generation is retained and is never automatically deleted. Later cleanup is separate, requires exact retained ownership and unambiguous reconciliation, and must exclude shared bases and dependencies.

For an already proven reusable base, fresh should reuse that base under the Phase 1 proof model: no upstream download, extraction, or base import; provenance verification only at the policy-defined execute boundary; one new generation overlay and any policy-required seed. The new generation must not carry arbitrary writable state from the old generation. Guest identity follows the fresh profile/base policy (including NoCloud or first-use behavior where applicable), unlike RAW persistent clone, which copies disk state and warns about duplicated identities.

The dry-run contract must show the bound profile, current Active generation and reconciliation, trusted-base disposition, planned generation/overlay/seed/domain identity, network identity behavior, guest identity behavior, atomic switch model, old-generation retention, cleanup implications, and `Mutation: false`. A clean completed instance may run fresh again; any Preparing or recovery-required state refuses until explicit recovery completes. Existing retained generations may remain while ownership and reconciliation are unambiguous. No real fresh operation may silently clean the old generation first.

### P0 — Disposable VM

Introduce an explicit disposable lifecycle:

```text
trusted base
  → temporary overlay/domain
  → user session
  → explicit or policy-authorized automatic disposal
```

The trusted base survives. Disposable state must not accidentally become durable persistent ownership, and persistent state must never be treated as disposable by naming convention. The model must define ownership, session identity, shutdown and crash behavior, cleanup proof, retention exceptions, and recovery of interrupted creation or disposal before automatic disposal is enabled.

### P0 — Fedora Workstation

Design a normal Fedora Workstation-oriented managed VM profile for interactive desktop use. The current Fedora Cloud Base profile is technically functional but does not satisfy this intended product experience.

The new profile must retain Fedora supply-chain verification and all applicable V2 generation, ownership, reconciliation, storage, recovery, and lifecycle boundaries. Desktop usability is not permission to downgrade provenance or silently trust installation media.

## 3. User experience

V2 exposes many engineering and administration commands. V2.5 should define a small normal-user surface around concepts equivalent to:

- status and list;
- image and update status;
- start;
- graceful stop;
- explicit force stop;
- fresh or reinstall;
- persistent clone; and
- disposable session.

These are product concepts, not committed command names. CLI vocabulary, flags, confirmation rules, and grouping remain a later design decision.

Advanced operations may remain available but must be clearly classified as maintenance or developer operations. These include recovery, adoption, domain definition, image preparation, rendering, low-level rebuild, cleanup, and internal state operations. High-level workflows should compose the same safe primitives and expose actionable recovery instructions rather than hiding failure.

## 4. Image management

V2.5 should design toward this explicit flow:

```text
detect update
  → inform user
  → user approves acquisition
  → download
  → cryptographically verify
  → prepare trusted base
  → do not automatically replace an existing VM
```

Forge may later support a lightweight periodic version check. It must not silently download images, prepare replacements, change the selected trusted base, rebuild a guest, or replace an existing VM.

The future image inventory should represent Fedora, Kali, and Whonix consistently, including supported upstream version, local acquisition state, cryptographic verification/provenance state, prepared trusted-base state, and whether an update is known. A concept such as `forge image list` is illustrative and provisional.

Preparing or proving an existing base should consume compact durable provenance evidence when safe. Full hashing of large images belongs at acquisition, preparation, explicit verification, or another policy-defined integrity boundary—not ordinary runtime lifecycle.

## 5. SSH and QGA

SSH is not a universal VM-success requirement. Each profile must explicitly classify SSH as one of:

- provisioning;
- observability;
- maintenance; or
- absent.

That classification determines when SSH is required, optional, or not probed. A profile must not inherit SSH readiness merely because another guest family uses it.

QEMU Guest Agent (QGA) is distinct from SSH and receives its own profile policy. ManualGuest status must not emit avoidable QGA errors when the profile does not configure or require QGA. Absence by policy should be represented as not configured or not applicable, not as a failed health check.

## 6. Kali

V2.5 must:

- preserve Kali's fast ManualGuest start and running-only lifecycle boundary;
- implement correct reuse/proof of the shared trusted Kali base for additional instances;
- eliminate reliance on upstream default `kali`/`kali` credentials as the intended steady-state configuration; and
- avoid invasive provisioning unless an explicit Kali profile policy defines and authorizes it.

Credential hygiene needs an intentional first-use or bootstrap design. It must not silently transform ManualGuest into a cloud-init-style managed guest or introduce credential material into durable ownership manifests.

## 7. Whonix

V2.5 must preserve:

- exact Gateway/Workstation pair identity;
- the Gateway's approved uplink;
- the Workstation no-alternate-uplink invariant;
- exact complementary UDP endpoints;
- fast ManualGuest lifecycle; and
- guest-side Tor architecture managed by the Gateway.

Backlog work must investigate the Whonix/KVM PVClock warning against official Whonix KVM requirements. Forge must not suppress the warning unless the cause has been fixed or the configuration has been verified correct and the warning proven inapplicable.

GUI or lifecycle improvements must not add a Workstation NAT, passt, bridge, or other fallback uplink, and must not move guest-side Tor management into Forge.

## 8. GNOME Boxes

V2.5 should evaluate GNOME Boxes as an optional human-friendly console or GUI. Forge remains the management authority and source of intended managed state. The design must not assume Boxes and Forge can freely mutate the same domains.

Research must cover:

- `qemu:///system` versus session behavior and visibility;
- start, stop, save, delete, clone, and other lifecycle mutation;
- persistent and live domain XML mutation;
- storage pool, volume, and backing-chain ownership;
- SPICE and display integration;
- clipboard, shared-folder, USB, and other device exposure; and
- reconciliation and recovery after external GUI operations.

Until compatibility and ownership boundaries are proven, Boxes should be treated as a possible viewer/console, not an alternate management authority.

## 9. Qubes-inspired direction

Forge is not recreating Qubes OS and does not claim Qubes compatibility. Its direction is Qubes-inspired—a “Little Qubes” philosophy centered on:

- small compartmentalized workloads;
- strong separation;
- trusted prepared bases;
- cheap independent clones;
- disposable environments;
- explicit network policy; and
- simple user-facing management backed by auditable state.

This philosophy guides product ergonomics without implying Xen, Qubes templates, qubes, RPC compatibility, or Qubes' full threat model.

## 10. Existing accepted backlog

V2.5 carries forward:

- establish the Fedora signing-key fingerprint or use an independent trusted keyring;
- add explicit Kali preparation recovery;
- narrow the privilege boundary below broad `org.libvirt.unix.manage` where practical;
- clean up ManualGuest QGA status behavior; and
- add host-wide UDP collision preflight or reservation for Whonix.

Backlog status does not waive any existing safety check. Where an item affects a proof boundary, implementation must fail closed until sufficient evidence exists.

## 11. Non-goals

Forge V2.5 does not:

- rewrite Forge from scratch;
- replace KVM/libvirt;
- migrate to Xen;
- create a custom Linux distribution;
- remove or weaken cryptographic verification for speed;
- make GNOME Boxes the source of truth;
- silently auto-update, download, activate, or replace VM images;
- weaken explicit recovery, reconciliation, provenance, topology, or ownership boundaries; or
- introduce malware-analysis-specific host integrations.

Expansion of the disposable or malware-analysis threat model—including host/guest exchange, detonation controls, instrumentation, and containment claims—belongs to a later dedicated design scope. V2.5 must not imply those protections before that work exists.

## 12. Proposed implementation order

The recommended order is:

1. Fix shared trusted-base reuse and prove creation of a second Kali instance.
2. Define and implement user-level persistent clone semantics.
3. Define and implement the fresh/reinstall transaction.
4. Define and implement the disposable model.
5. Add the Fedora Workstation-oriented profile.
6. Simplify and classify the user-facing CLI.
7. Build consistent image inventory and update-status UX.
8. Clean up profile-specific SSH and QGA policy and observability.
9. Complete GNOME Boxes research and define an integration policy.
10. Address the remaining hardening backlog.

Each step must add its own tests and proof obligations without relying on a later step to restore safety. In particular, user-facing syntax should be finalized only after the underlying lifecycle semantics and recovery boundaries are explicit.

## 13. Acceptance principles

A V2.5 feature is acceptable only when:

- normal use is simpler without making maintenance mutations implicit;
- pre-existing trusted artifacts are reused only after exact proof;
- ambiguous or conflicting artifacts produce a refusal with actionable diagnostics;
- the old working generation survives until its replacement is proven and atomically activated;
- shared bases remain protected dependencies, not per-generation cleanup candidates;
- profile-specific readiness does not regress to universal SSH or QGA assumptions;
- external GUI activity cannot silently redefine Forge's ownership or topology; and
- documentation and CLI help distinguish stable user workflows from maintenance/developer operations.

V2.5 succeeds by making the V2 safety machinery pleasant and predictable to use—not by routing around it.

## 14. Fedora Workstation Replacement Architecture

This section is authoritative for Fedora in Forge V2.5. It supersedes earlier
Fedora Cloud Base, NoCloud, cloud-init, seed ISO, mandatory SSH, and mandatory
QGA product assumptions. Those assumptions remain relevant only while reading
and safely retiring legacy state; they are not a compatibility requirement for
the replacement profile. The existing host `fedora-lab` must not be adopted,
converted, deleted, or otherwise mutated as part of this design phase.

### 14.1 Product and source definition

The supported Fedora product is a normal Fedora Workstation x86_64 installation
with GNOME and a graphical login/session. Its installation source is the official
Fedora Workstation x86_64 Live ISO published by the Fedora Project, represented
by a typed source such as `FedoraWorkstationIso { release, compose, arch }`.
Cloud Base, CoreOS, Server, Minimal, containers, and unofficial repacks are not
valid substitutes. `fedora-lab` may remain the stable Forge profile and instance
name after an explicit legacy transition, but the guest product is Fedora
Workstation.

The official source and verification entry points are:

- <https://fedoraproject.org/workstation/download/>;
- <https://fedoraproject.org/security/>; and
- <https://fedoraproject.org/fedora.gpg> for the published Fedora keyring.

The source record binds release, compose/build identity, architecture, exact ISO
filename, byte size, digest, signed CHECKSUM identity, and the expected release
signing-key fingerprint. Forge verifies the CHECKSUM signature using a
project-maintained, independently reviewed trusted keyring or pinned fingerprint,
then verifies the exact ISO digest and identity named by that signed metadata.
A key downloaded beside the ISO is not by itself a trust root. Release keys are
rotated, so trust is explicitly release-bound and reviewed; no implementation
may treat the current website key as an unversioned permanent key. Downloading an
ISO and trusting its pathname is forbidden.

Phase 4.2 binds the initial implementation to Fedora 44 compose 1.7,
`Fedora-Workstation-Live-44-1.7.x86_64.iso`, and the Fedora 44 release-key
fingerprint `36F6 12DC F27F 7D1A 48A8 35E4 DBFC F71C 6D9F 90A6`. The ISO,
signed CHECKSUM, release keyring, authenticated CHECKSUM payload, and typed
provenance metadata use Workstation- and release-specific download-cache names;
none reuse legacy Cloud or prepared-base state. Adding another release requires
an explicit source-policy entry, independent fingerprint review against Fedora's
published security page, and tests proving cross-release evidence cannot match.
The downloaded Fedora keyring supplies key material but is never a TOFU trust
anchor: signature acceptance additionally requires the release-bound pinned
primary fingerprint.

`VerifiedFedoraWorkstationIso` is byte-backed installation-source evidence. It
binds the signed metadata identity, exact byte size and SHA-256 to stable local
file identity and cannot stand in for the future canonical SharedBase. Phase 4.2
inventory therefore reports the canonical base as `Not prepared`.

### 14.2 Installation source is not a shared base

Fedora Workstation has two distinct artifact classes:

```text
verified official Workstation ISO                 installation source
    -> controlled installation
    -> installation-completion proof
    -> versioned normalization
    -> canonical installed Workstation qcow2      trusted SharedBase
    -> per-instance generation overlay            writable instance state
```

The ISO is immutable verified installation media, not a bootable Forge instance
base. The canonical qcow2 is an installed, generalized, cleanly shut down disk
with a durable preparation record linking it to the exact verified ISO,
installer policy and normalization-recipe version. Promotion into the image
store is explicit, collision-intolerant, fully verified at the preparation
boundary, and gives the result `SharedBase` ownership. Forge protects it from
generation cleanup and treats it as logically read-only.

### 14.3 First canonical installation

V2.5 should initially use an operator-assisted interactive installation. Forge
creates a temporary, explicitly preparation-owned installer domain with the
verified Workstation Live ISO and a new blank qcow2 staging disk. The operator
uses the normal graphical Anaconda workflow. Forge does not claim completion
from elapsed time, SSH, cloud-init, or QGA. Promotion requires an explicit
operator completion action while the installer domain is shut off, proof that
the target disk is the exact preparation-owned disk, proof that installer media
is no longer part of the candidate boot topology, a controlled successful boot
and clean shutdown of the installed system, completion of the versioned
normalization procedure, and final storage/provenance inspection.

This choice favors the actual Workstation user experience and a small initial
automation surface. Kickstart remains a legitimate native Fedora installation
technology, but it is not the V2.5 canonical path: Anaconda documents that
Kickstart installation from the Live OS/Live ISO is unsupported and directs
automated installations to boot/netinstall media. Forge must not silently swap
the chosen official Workstation Live ISO for another product merely to automate
installation. A later reproducible builder may use a separately reviewed
official installation source and explicit Kickstart policy, without restoring
NoCloud or changing the resulting Workstation product.

The interactive installer must leave no personal or universal account in the
canonical base. The preferred flow stops before per-user GNOME Initial Setup; if
a temporary builder account is unavoidable, normalization must remove it and
prove its home, credentials, authorization, and secrets absent before promotion.
Root remains locked. Each new instance lets its user choose a local account and
credentials through the normal graphical first-use experience. Forge does not
store plaintext passwords, embed a universal default password, or inherit the
legacy `forge` user.

### 14.4 Canonical-base normalization

Normalization is a versioned, reviewable preparation recipe executed before
promotion, followed by offline/host-side evidence where practical. It must:

- clear `/etc/machine-id` so systemd regenerates it and preserve the compatible
  `/var/lib/dbus/machine-id` relationship;
- remove SSH host keys and leave the SSH server absent or disabled by default;
- reset the hostname to the approved generic first-use state;
- remove persistent NetworkManager MAC/interface bindings, connection UUIDs and
  DHCP client identity that would be unsafe to duplicate;
- remove the saved random seed and other documented per-machine entropy state;
- remove installer media/repository residue, temporary files, crash data, and
  identifying logs/journals while retaining a consistent RPM database;
- remove personal and builder accounts and GNOME per-user first-login state,
  keep root locked, and enable normal first-use account setup;
- complete package transactions, remove locks, and record the installed package
  and normalization-policy identity without silently updating later;
- verify bootloader and filesystem references, a clean shutdown, and SELinux
  labeling (scheduling a relabel when the recipe requires one);
- install and test SPICE desktop integration according to profile policy; and
- record whether QGA is installed/configured without making it a promotion or
  runtime success requirement.

Filesystem UUIDs are not blindly rewritten. A qcow2 backing chain presents one
filesystem to one VM, so a shared filesystem UUID is not by itself a collision;
changing it would also require consistent bootloader and `fstab` updates. Any
future topology that exposes sibling disks together must add a typed UUID policy.
Normalization is intentionally distinct from RAW clone, which copies visible
writable guest identity and cannot claim independent identity.

Phase 4.3 models this as a durable image-store transaction with states
`Planned`, `InstallerReady`, `Installing`, `InstalledPendingProof`,
`InstalledValidated`, `NormalizationRequired`, `Normalized`, `PromotionReady`,
`Promoted`, `Cancelled`, and `RecoveryRequired`. The transaction owns its
temporary domain and sparse, no-backing staging qcow2 independently from normal
instance generations. Process exit, terminal closure, host reboot, or an
operator pause never imply a transition. Installation completion requires an
explicit operator continuation plus exact shutoff/domain/disk/topology,
bootable-system, controlled disk-boot, and clean-shutdown observations.

`FedoraWorkstationNormalizationV1` uses a hybrid method: controlled in-guest
steps for Fedora-aware package, account, GNOME, and SELinux work, followed by
offline read-only inspection for final identity, residue, disk-shape, and clean
shutdown proof. Forge must not mount guest filesystems ad hoc on the host.
Normalization evidence is a private typed value produced only by the complete
checklist; a metadata boolean cannot authorize promotion.

The Phase 4.6 state sequence is `InstalledSystemProven` ->
`NormalizationPlanned` -> `NormalizationRunning` ->
`NormalizationGuestComplete` -> `ShutdownPending` -> `OfflineProofPending` ->
`Normalized`. Every arrow requires newly published evidence bound to the
preparation ID, staging identity, recipe version, and prior evidence. Resume
re-proves the current boundary; a process crash never supplies a missing guest
result or shutdown. Only a guest-requested shutdown followed by libvirt-observed
shutoff qualifies. A forced stop is recovery evidence, never clean-shutdown
evidence.

The canonical product remains Fedora Workstation, not a cloud image. It has no
normal, builder, legacy `forge`, or universally credentialed account; root is
locked under Fedora policy. GNOME Initial Setup and its packaged system defaults
remain available. Normalization removes only user-specific AccountsService and
GNOME completion records whose ownership is proven; an unknown first-use state
fails closed rather than triggering a guessed path deletion.

`/etc/machine-id` is retained as an empty regular file for first-boot generation.
The D-Bus machine-id is absent or the distribution-supported link to it, never a
second persistent identifier. The hostname is the product-level generic value
`localhost` until instance policy supplies another. NetworkManager profiles may
remain only when they are generic autoconnect policy: no preparation MAC,
interface name, connection UUID intended as instance identity, static address,
lease, DHCP DUID/client ID, secret, or preparation hostname may survive.
Filesystem UUIDs are preserved unless a separately typed boot-consistency
transaction proves a replacement.

OpenSSH is not installed or enabled merely for Forge. If it is already part of
the installed package set, all generated host keys must be absent and key
generation must remain Fedora-native on a later start. SPICE desktop integration
is a product capability and may be included when its Fedora package and service
state are proven generic. QGA is a separate lifecycle interface and is included
only after Forge specifies concrete operations, a libvirt channel policy, and a
security boundary; it is not required for display resizing.

The selected package policy is a fully updated Fedora 44 system at preparation
time. A future executor must record repositories, update timestamp, transaction
completion, RPM database consistency, and the complete installed NEVRA manifest
so the result remains auditable and rebuild differences are explicit. Phase 4.6A
does not update anything. SELinux must remain enabled and enforcing. Any recipe
change that can invalidate labels schedules the Fedora-native relabel, boots to
complete it, and proves that no relabel is pending before final shutdown.

Cleanup is bounded: remove proven credentials, tokens, histories, preparation
commands, leases, crash artifacts, temporary files, and identifying journal/log
content; preserve packaged defaults, package caches or logs needed for provenance
unless policy explicitly classifies them. Anaconda files are removed only when
documented as transient output; packaged Anaconda components and ordinary RPM
metadata are not residue by filename alone.

There is currently no proven authenticated in-guest execution channel. Forge
must not substitute SSH, cloud-init, NoCloud, a shared host filesystem, or a
universal credential. Phase 4.6B must first implement and prove a narrowly
owned, preparation-only, deterministic command/evidence channel with no reusable
secret and fail-closed self-removal. Until then execution planning reports
`Unavailable`; a single operator terminal session is an explicit last-resort
fallback, not an implicit automation path.

Phase 4.6B selects a dedicated preparation-only virtio-serial transport with a
fixed target name, paired with a purpose-built guest helper. The transport is
not an executor and carries no authority by itself. The helper accepts only the
versioned `ReadOnlyGuestInventoryProbe` operation in 4.6B; there is no command,
argument-vector, script, or shell field in the protocol. Requests and results
bind preparation ID, domain name/UUID, staging path, recipe, expected durable
state, operation ID, and nonce. A successful transport disconnect or helper exit
is not evidence: only a matching structured completed result can construct the
private inventory-evidence type.

The host operation ledger distinguishes prepared, sent/awaiting-result,
completed, and ambiguous failure. A crash before send is safely unsent. A crash
after send remains ambiguous; future mutating operations may not be repeated.
The read-only inventory can be issued under a new operation ID after explicit
reconciliation, but duplicate requests/results never create a second success.
Durable-state or identity changes invalidate outstanding operations.

The intended helper is `/usr/libexec/forge-preparation-control`, with a transient
unit under `/run/systemd/system/`, transient binding under
`/run/forge-preparation-control/`, and domain channel
`org.majorforge.preparation.0`. It runs under SELinux enforcing, has a fixed
read-only collector allowlist, creates no reusable secret, and must not expose a
generic shell. Before `Normalized`, proof must show the helper, unit, binding,
channel, token/secret residue, and all preparation-specific state absent.

This helper cannot be safely bootstrapped into the already running preparation
with the currently proven architecture: SSH/cloud-init/NoCloud/shared folders
are forbidden, QGA generic execution is deliberately unavailable, and a serial
device alone cannot install a trusted endpoint. Therefore 4.6B implementation
must stop before topology mutation or a real probe unless a separately
authorized, auditable bootstrap supplies the helper. Attaching an unconsumed
transport would not constitute progress or proof.

The Phase 4.6B1 read-only broker checkpoint is proven independently of that
future in-guest channel. The privileged preparation broker forces the direct
libguestfs backend and opens the exact shut-off staging qcow2 read-only. Its
deterministic sequence explicitly launches the appliance, calls `inspect-os`,
requires exactly one framed OS root, preserves Btrfs identities such as
`btrfsvol:/dev/...`, and binds subsequent inspection calls to that exact root.
For the Fedora Workstation 44 x86_64 preparation it proved the Workstation
identity, enforcing SELinux configuration and bounded filesystem layout while
preserving inode, DAC, ACL, SELinux label, timestamps, capacity, backing, dirty
and corrupt state. A clean close publishes one bound
`ProvenPrivilegedOfflineFedoraDiscovery` while durable preparation state remains
`InstalledSystemProven`. This checkpoint grants no write capability, helper
injection, preparation channel, normalization, promotion or canonical-base
authority.

Phase 4.6B2 adds exactly one controlled write capability beyond that read-only
checkpoint: an offline bootstrap transaction whose only accepted target is a
fixed broker-owned synthetic qcow2. The broker fixes the direct backend, host
helper provenance, guest helper/generator/binding paths, canonical binding JSON,
ownership, modes, and SELinux labels; callers cannot supply a shell, argv,
command, backend, disk path, host path, guest path, decoder, encoding, or
artifact identity. Verification requires an exact path set, helper and generator
digests and stats, SELinux labels, and binding bytes transported in structured
frames through broker-selected base64, strictly decoded and compared byte for
byte and by SHA-256 before independent JSON semantic verification. A durable
journal supports verification-only recovery of the same transaction, while a
create-once success ledger and replay refusal permit exactly one completion.
This proves only the synthetic write boundary: real Fedora staging has not been
mutated, the real helper and preparation channel remain absent, and normalization
and canonical-base creation remain unauthorized. One real helper injection is
safe to review only after the Phase 4.6B2 checkpoint; it has not been executed.

The Phase 4.6B3 checkpoint proves the corresponding real offline injection. The
broker keeps `ProtectSystem=strict`; the only additional systemd writable
exception is the exact preparation staging qcow2, never its parent directory or
a caller-selected path. A transaction-bound classifier inspects only the fixed
helper, generator, and binding paths through the direct read-only backend. It
classifies absent, exact, mismatched, inconsistent, and indeterminate states and
derives only deterministic same-transaction resume points; mismatches,
inconsistent sets, identity drift, and unreadable evidence fail closed without
overwrite or journal reset.

The original real transaction completed exactly once after byte, digest,
ownership, mode, SELinux, canonical binding, semantic identity, and exact-path-set
verification. Its journal is `Completed`, its success ledger contains one entry,
durable bootstrap evidence is bound to that same transaction, and replay is
refused. This checkpoint ends offline: the helper is installed but has never
executed, the preparation VM remains shut off, the channel remains absent, no
inventory probe or normalization has run, and no canonical base exists.

After the guest checklist and controlled shutdown, a dedicated read-only image
inspection appliance (not an ad-hoc host mount) verifies OS release/product,
accounts, first-use state, machine/D-Bus/hostname/network/SSH identity, package
manifest and transaction state, SELinux configuration and pending relabel,
filesystem cleanliness, staging capacity/format/backing shape, and a full disk
digest. Its evidence binds the preparation, recipe, source provenance, staging
volume key/path, clean-shutdown event, and inspection-tool version. Only then can
the private-field `NormalizedFedoraWorkstationDisk` be constructed.

Promotion performs an exact copy/import from preparation-owned staging into a
new, collision-free `forge-base-fedora-workstation-<release>-<compose>.qcow2`,
proves its digest, capacity, qcow2/no-backing shape, publishes ISO/install/
recipe/preparation provenance, protects the image-store `SharedBase`, and only
then retires staging. Before provenance publication, staging remains the
recoverable authority and no canonical base is trusted. After publication, the
canonical base remains authoritative and staging cleanup is separate and
idempotent. Protection combines durable SharedBase ownership, deletion and
writable-attachment refusal, exact consumer proof, and compatible filesystem
permissions; `chmod` alone is insufficient.

Phase 4.4 executes only the first resumable portion of that transaction. Forge
publishes one private `Planned` record, creates and proves one sparse 80 GiB
qcow2 with no backing store in the system libvirt image pool, defines one
persistent but shut-off temporary Q35/UEFI installer domain, rereads its
persistent XML, and publishes `InstallerReady` only after exact topology proof.
The domain has the verified Workstation ISO as its sole read-only CDROM, the
staging disk as its sole writable disk, one default-network virtio NIC, SPICE,
virtio-gpu, USB tablet/keyboard, and ICH9 audio. It has no seed, cloud-init,
hostdev, filesystem passthrough, or QGA requirement and autostart is disabled.

The state record binds the preparation ID, exact signed ISO provenance, volume
key/path/shape, domain name/UUID and normalized XML digest, normalization recipe,
and future canonical name. A repeated prepare validates and reports the same
resources rather than allocating another environment. Partial storage/domain
failures retain their last published preparation ownership for explicit
recovery; this executor never performs ambiguous automatic cleanup. Status is
read-only. Continue refuses until a later phase implements explicit operator
confirmation and installed-system proof. Phase 4.4 neither starts Anaconda nor
creates or promotes a canonical base.

Persistent installer topology is proven as requested intent plus resolved
libvirt topology. `Q35` is a machine family request: the libvirt capabilities
inventory must explicitly map the `q35` alias to the concrete machine persisted
by the domain (for the proven host, `pc-q35-10.2`). A name prefix is not machine
family authority. The resolved record retains that alias binding, concrete
machine, UEFI loader/NVRAM paths, NIC MAC, normalized device classifications,
and persistent-XML digest.

Required devices are the single staging disk, single verified ISO CDROM, single
default-network virtio NIC, SPICE graphics, virtio video, USB tablet/keyboard,
ICH9 sound, CPU/memory, UEFI, and boot policy. Narrow libvirt normalization is
accepted only for the observed emulator, qemu-xhci/SATA/PCIe controllers, PS/2
mouse/keyboard, SPICE audio backend, ITCO reset watchdog, and virtio balloon,
with their exact constrained properties. Hostdev, filesystem, channel/QGA, TPM,
RNG, redirection, serial/console, panic, extra storage/network/media, unknown
direct device kinds, alternate host paths, and autostart remain forbidden. No
unknown device is ignored.

### 14.5 Guest observability and first boot

The replacement provisioning/readiness policy is conceptually
`InteractiveWorkstation`, not `CloudInitManaged`. Creation can succeed without
starting the VM once Forge has proven the persistent shutoff domain, exact
generation disk, expected graphics topology, and durable ownership. When the
user starts it, lifecycle success means the expected domain reached `running`;
desktop usability remains an interactive user observation rather than something
Forge pretends to prove through SSH.

SSH is absent or disabled by default. A user may explicitly enable it later as a
maintenance feature, but Forge does not expose it merely for observability and
does not require an SSH login for create, start, installation, or first-boot
success.

QGA is optional management integration. It may provide advisory IP/status data
and optional shutdown assistance when configured, but QGA availability is
separate from installation completion, domain running state, and graphical
desktop usability. ACPI/libvirt graceful shutdown remains available without it.
There is no universal QGA wait and no long readiness timeout inherited from the
legacy Fedora path.

### 14.6 Shared storage, create and Fresh

The canonical base is image-store owned and separate from every instance. The
first `fedora-lab` follows the same warm path as later instances:

```text
prove exact canonical Fedora Workstation SharedBase
    -> create exactly one generation-owned overlay
    -> define one persistent domain
    -> publish one Active generation
```

It does not run Anaconda, attach the ISO, generate a seed, invoke cloud-init,
require SSH, or repeat full installation. The installer staging disk is promoted
to the canonical image-store base first; `fedora-lab` itself never becomes the
SharedBase.

Fedora Workstation Fresh is enabled only after this model is proven. It reuses
the Phase 3 recoverable transaction and creates a new overlay directly from the
instance's bound canonical base: old `Active` remains authoritative until the
single durable switch changes it to `Retained` and changes the new `Preparing`
generation to `Active`. Fresh never launches Anaconda, copies old writable guest
state, boots automatically, or cleans the retained generation automatically.
Reconciliation and recovery remain fail-closed.

Each profile/instance binding records the Fedora release and exact canonical
base provenance identity. Fresh preserves that binding by default. A newer
accepted base is never selected silently.

### 14.7 Clone, disposables and identity

Fedora Workstation clone remains unsupported initially. A RAW clone would copy
machine identity, local users, credentials and application state; a warning is
not sufficient to call the result independent. Enabling clone requires a
guest-aware identity-regeneration design or a deliberately scoped RAW-copy mode
whose risks are explicit.

The base/overlay split is compatible with a future disposable lifecycle:
canonical trusted base, temporary session-owned overlay and domain, then exact
overlay destruction. No Fedora-specific seed or per-instance base mutation may
be introduced that would block that design.

### 14.8 Desktop domain policy

The Workstation domain uses a modern desktop-oriented, normalized topology:

- Q35 and UEFI; Secure Boot is enabled only after firmware/key enrollment and
  reproducibility are proven, otherwise its disabled state is explicit;
- virtio qcow2 system disk and virtio network on the approved network source;
- SPICE display, virtio-gpu video, graphical/input devices and audio suitable
  for GNOME;
- SPICE guest tools for clipboard and dynamic resolution, subject to an explicit
  clipboard policy;
- conservative 3D acceleration disabled by default until render-node access,
  host compatibility and isolation are proven;
- profile-derived memory/vCPU defaults sized for an interactive Workstation,
  with an initial target of four vCPUs and 8 GiB where host policy permits;
- no seed/CD-ROM after installation, no hostdev, no filesystem passthrough, no
  unapproved bridge or alternate NIC, and no unexpected persistent devices; and
- an optional QGA channel only when the profile explicitly enables it.

Persistent normalized topology, autostart policy, storage and network identity
remain Forge-owned and are verified before mutation and after definition.
virt-manager is a supported viewer/console for the system libvirt domain. GNOME
Boxes may later be supported as a viewer where system/session visibility allows,
but neither tool may silently become authoritative over Forge XML, storage or
durable generation state.

### 14.9 Legacy retirement classification and transition

The old architecture is classified as follows:

| Classification | Legacy elements | Direction |
| --- | --- | --- |
| Remove entirely | `FedoraCloudBase`, the Fedora Cloud artifact selector/names, Fedora-only NoCloud and seed authoring, `default_user = forge`, Fedora SSH/cloud-init/QGA readiness probes, Cloud-Base create/rebuild flows and their product tests/help | Delete after legacy-state compatibility is no longer required. |
| Keep as generic infrastructure | atomic downloads/writes, checksum/signature execution, durable provenance, image-store ownership, SharedBase/overlay logic, generation indexes, reconciliation, recovery, cleanup, generic libvirt storage/domain operations and lifecycle | Preserve and make profile-neutral. |
| Reuse for Workstation | reviewed Fedora signing-key/checksum concepts, shared-base proof, recoverable Fresh transaction, Q35/UEFI/virtio/SPICE building blocks | Reuse only through new typed Workstation policy and proof. |
| Replace with Workstation-specific model | Fedora profile/source types, preparation state machine, canonical-base promotion, readiness, normalized domain topology, image inventory, release policy, CLI workflow, tests and docs | Implement according to this section. |

`NoCloudSeed`, `CloudInitManaged`, and legacy manifest fields may temporarily
survive only in an isolated compatibility reader and exact retirement/recovery
path for already-owned legacy state. They must not remain selectable by a new
Fedora profile. Once the legacy host object is retired and no other profile
legitimately uses them, delete the policy variants and generic-looking dead code
rather than preserving it indefinitely. Historical learning documents may remain
clearly historical; current README, CLI help, tests and product documentation
must describe Workstation.

The existing Cloud/NoCloud `fedora-lab` receives a later explicit transition:

1. require it persistent, shut off and unambiguously reconciled, and record its
   exact domain UUID, active/retained generations, overlay, seed, base and state;
2. offer a separately authorized user-data export or retention decision;
3. require explicit confirmation to retire the legacy instance;
4. use exact ownership cleanup to remove only its legacy overlays/seeds and old
   Cloud Base after all references are absent, recording partial failure;
5. undefine the old stable domain only as an explicit retirement action, never
   as adoption or an in-place product conversion; and
6. create the new Workstation `fedora-lab` from the canonical base only after the
   name is free. It is a new product lineage and receives a new durable domain
   UUID; the stable name is reused deliberately, not silently.

Phase 4.0 performs none of these operations.

### 14.10 Inventory, updates and user workflow

Future image inventory separates source and prepared artifacts, for example:

```text
FEDORA WORKSTATION 44 x86_64
Source ISO:     Fedora-Workstation-Live-x86_64-44-<compose>.iso  verified=yes
Canonical base: forge-base-fedora-workstation-44.qcow2          trusted=yes ready=yes
```

Each line also exposes the source/provenance identity, release binding and any
known newer release without presenting Cloud Base as Fedora Workstation. The
update flow is detect, inform, explicit approval, acquire and verify a new ISO,
prepare a separate new canonical base, and leave all Active instances untouched.

Fresh resets the currently bound release. A future explicit upgrade/rebase
operation may bind an instance to a newer accepted canonical base, but Fresh is
not an OS-upgrade command and a major release is never crossed silently.

The intended normal-user workflow is conceptually:

```text
prepare Fedora Workstation image (fetch, verify, install, normalize, promote)
create fedora-workstation fedora-lab
open/start fedora-lab
```

Exact command names remain a later CLI decision. A high-level preparation command
may orchestrate the safe stages, while developer/admin commands expose evidence
and recovery. Users should not need to understand volume imports, backing chains,
XML rendering or provenance-state internals.

### 14.11 Implementation acceptance criteria

Fedora Workstation implementation is acceptable only when all of the following
are proven:

1. only the official Fedora Workstation installation source is selected;
2. the exact ISO has release-bound cryptographic verification through a trusted
   Fedora key policy;
3. Fedora Cloud Base is absent from the supported product path;
4. NoCloud is absent from the supported product path;
5. cloud-init is not a dependency;
6. SSH is not mandatory and is disabled/absent by default;
7. QGA is not mandatory unless a later explicit policy justifies a scoped use;
8. the guest is a normal GNOME Fedora Workstation;
9. an installed, normalized qcow2 is promoted as the protected SharedBase;
10. each persistent instance has a distinct generation-owned overlay;
11. first canonical installation is separate from warm instance creation;
12. repeated create does not reinstall from the ISO;
13. Fresh resets from the bound canonical Workstation base;
14. Fresh does not copy old writable guest state;
15. Forge ownership, normalized topology and durable reconciliation remain exact;
16. cleanup/recovery fail closed and never select the SharedBase;
17. the old legacy `fedora-lab` is not silently mutated or adopted;
18. no Fedora release change occurs without an explicit rebase/upgrade decision;
19. the desktop is usable through virt-manager with the intended SPICE policy;
20. the architecture supports a future base-backed disposable Workstation;
21. canonical normalization prevents duplicated per-machine and user identity;
22. no embedded universal password or plaintext credential enters repository or
    durable Forge state; and
23. tests prove source/type refusal, provenance, normalization evidence, warm
    create, topology, release pinning, Fresh, cleanup and recovery boundaries.

### 14.12 Phase 4 implementation breakdown

1. **Phase 4.1 — typed retirement boundary:** introduce Workstation types and
   refuse new Cloud/NoCloud Fedora work; inventory and isolate legacy schema
   readers without deleting the host object.
2. **Phase 4.2 — official ISO provenance:** implement typed Live ISO acquisition,
   release-key trust, signed CHECKSUM and exact artifact verification.
3. **Phase 4.3 — canonical preparation model:** implement preparation ownership,
   interactive installer state, completion evidence, normalization record and
   atomic SharedBase promotion.
4. **Phase 4.4 — installer preparation executor:** acquire/prove the official
   ISO, create preparation-owned staging, define/prove the shut-off interactive
   installer domain, and stop durably at `InstallerReady`.
5. **Phase 4.5 — first canonical base proof:** perform one authorized installation,
   normalization and image-store promotion with complete evidence.
6. **Phase 4.6 — persistent instance creation:** create the new Workstation
   instance from one overlay after the legacy name transition permits it.
7. **Phase 4.7 — lifecycle and desktop UX:** prove start/stop, graphical use,
   optional integrations and viewer ownership boundaries without SSH/QGA waits.
8. **Phase 4.8 — Workstation Fresh:** bind release/base identity and reuse the
   recoverable Phase 3 transaction with Workstation topology tests.
9. **Phase 4.9 — explicit legacy retirement:** preserve/export as authorized,
   then exactly clean and undefine the old Cloud/NoCloud object; remove remaining
   compatibility-only code after proving no consumers remain.
10. **Phase 4.10 — final acceptance:** exercise inventory, update/pinning,
    repeated creation, Fresh, cleanup/recovery and future-disposable constraints.

No phase may use implementation convenience to reintroduce Cloud Base, NoCloud,
cloud-init, universal credentials, mandatory SSH/QGA, implicit release upgrades,
or silent mutation of the legacy host object.
