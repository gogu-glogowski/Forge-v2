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

Provide a simple user-level operation that creates another independently owned, persistent VM from an existing trusted base/profile. Each clone receives its own instance identity, domain identity, durable generation state, and writable overlay. The shared base remains protected and non-disposable.

Clone does not mean copying or sharing mutable guest state, adopting an arbitrary existing domain, or weakening per-instance ownership. Cloning from an existing VM may use that VM to select a compatible profile and trusted-base identity, but the new instance must remain independently manageable.

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
