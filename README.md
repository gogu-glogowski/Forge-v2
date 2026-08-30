# Forge V2

> **Little Qubes-style virtualization for Fedora — policy-driven, reproducible and auditable.**

Forge is a Rust-based management layer for isolated KVM/QEMU/libvirt virtual machines on a Fedora host.  
The project grew from a simple host-readiness checker into a lifecycle, image, storage, state and topology manager for a small security-focused VM fleet.

**Current release:** `v2.0.0`  
**Release status:** **PASS WITH ACCEPTED LIMITATIONS**

> 🎧 **If you're reading my code and want some background music, press play.**  
> <a href="https://www.youtube.com/embed/S0Zv4IJviUs?list=RDS0Zv4IJviUs&autoplay=1&rel=0" target="_blank" rel="noopener noreferrer">Listen to the YouTube playlist ↗</a>

---

## What Forge manages

The current V2 fleet consists of four persistent managed VM roles:

- **Fedora Lab** — currently based on Fedora Cloud Base; replacement with a normal Fedora Workstation-oriented profile is planned for V2.5.
- **Kali Lab** — persistent ManualGuest based on the verified Kali QEMU image.
- **Whonix Gateway** — isolated Tor gateway.
- **Whonix Workstation** — workstation with a single enforced path through its paired Gateway.

Forge is deliberately more than a wrapper around `virsh`. It keeps durable ownership of VM generations, validates storage/backing relationships, reconciles durable state with libvirt reality, applies profile-driven lifecycle policy and protects important mutation boundaries.

---

## V2 architecture in plain language

Forge V2 provides:

- **Durable generations** — Forge records which exact VM generation is active instead of guessing from filenames or current libvirt state.
- **Reconciliation** — Forge compares its durable state with what actually exists in libvirt and reports whether the instance is consistent.
- **Exact ownership** — lifecycle and destructive operations are bound to the intended instance, generation and domain UUID.
- **Backing-chain validation** — overlays are checked against the expected trusted base image.
- **Image provenance and verification** — image acquisition follows profile-specific verification policy rather than blindly trusting a downloaded file.
- **Policy-driven lifecycle** — different guest classes have different success boundaries. ManualGuest does not inherit Fedora/NoCloud DHCP, QGA, SSH or cloud-init assumptions.
- **Explicit recovery boundaries** — recovery/adoption/cleanup are separate operations rather than hidden side effects.
- **Whonix topology enforcement** — Workstation is designed without an alternate host-side uplink, while Gateway owns the external path.

The design goal is simple: **safe defaults, explicit mutations, fast normal operation, and enough state to prove what Forge is actually managing.**

---

## Quick start

Once the release binary is installed in `$PATH`:

```bash
forge vm list
forge vm status kali-lab
forge state reconcile kali-lab
forge vm start kali-lab
forge vm shutdown kali-lab
```

For a VM that does not respond to graceful shutdown, Forge does **not** silently escalate to a hard power cut:

```bash
forge vm stop kali-lab --force --dry-run
forge vm stop kali-lab --force
```

Force-stop is an explicit, confirmed operation with power-cut semantics.

To inspect the full CLI:

```bash
forge --help
```

---

## Everyday commands

The intended day-to-day surface is small:

```bash
forge vm list
forge vm status <instance>
forge state reconcile <instance>
forge vm start <instance>
forge vm shutdown <instance>
forge vm stop <instance> --force --dry-run
forge vm stop <instance> --force
```

Forge also contains lower-level developer and recovery operations for profiles, planning, image handling, provisioning, rebuilds, cleanup, adoption and state recovery. Those commands exist because the system needs safe maintenance boundaries; they are **not intended to become the normal daily UX**.

---

## Creating an instance

Forge separates a **profile** from an **instance name**.

For example:

```bash
forge vm create kali-lab kali-2 --dry-run
```

means:

> create a new instance named `kali-2` using the `kali-lab` profile.

The dry-run is zero-mutation and shows the planned generation, image policy, storage, domain, network, persistence and first-boot policy before anything is changed.

The V2 create path is deliberately strict. Manual testing after the V2 release exposed an important usability defect when creating an additional Kali instance from an already prepared shared base. This is part of the V2.5 work rather than being hidden as a successful V2 feature.

---

## Runtime characteristics

The V2 lifecycle work removed expensive Fedora/NoCloud observations from ManualGuest startup.

Observed warm-path results during final Whonix runtime validation:

| Operation | Observed time |
|---|---:|
| Whonix Gateway start | ~0.27 s |
| Whonix Workstation start | ~0.20 s |
| Gateway force-stop | ~0.31 s |
| Workstation force-stop | ~0.31 s |
| Reconciliation | ~0.03 s |

ManualGuest startup now stops at the correct boundary:

`preflight → domain start → bounded wait for running → success`

It does not perform DHCP, QGA, SSH, cloud-init, hostname/user checks or large image hashing during that runtime path.

---

## V2 release validation

The accepted V2 release passed:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace` — **231 passed, 0 failed**
- doc-tests
- `git diff --check`
- final persistent VM reconciliation
- Whonix host-side runtime isolation proof

Release checkpoint:

```text
b44715c355b513bab54492f9999439c756059b0b
```

Annotated release tag:

```text
v2.0.0
```

---

## Known V2 limitations

V2 is accepted, but it is not presented as finished consumer software.

Known limitations include:

- Fedora Lab currently uses **Fedora Cloud Base**, which is not the desired interactive desktop experience.
- Guest-side Whonix Tor/connectivity proof remained unobserved during formal host-side isolation validation.
- Some guests can ignore graceful ACPI/libvirt shutdown and reach the 120-second timeout.
- QGA probing can still produce noisy libvirt messages on profiles where the guest agent is absent.
- Creating another Kali instance exposed an over-strict prepared-base/create boundary that needs correction.
- The full CLI exposes more engineering/recovery operations than a normal user should need.
- First/cold provisioning can be expensive even though the accepted warm lifecycle is fast.

These are inputs to V2.5, not reasons to weaken V2's state and safety model.

---

# Forge V2.5 — planned direction

V2.5 is primarily a **usability and automation release built on the V2 safety architecture**.

The intention is not to throw away durable state, reconciliation, provenance or exact ownership. The intention is to hide most of that machinery behind a much smaller human-facing workflow.

## 1. Fedora Workstation profile

Replace the current Fedora Cloud Base-oriented user experience with a proper Fedora Workstation desktop profile suitable for interactive VM use.

## 2. Fast reinstall / refresh

Provide an obvious high-level operation for:

> verify trusted source → create fresh generation → switch safely → boot

A user should not need to manually compose low-level prepare/define/rebuild/state commands for the common “give me a clean machine again” case.

## 3. Cloning

Make creation of additional persistent instances from an already trusted/prepared base cheap and predictable.

Example target UX:

```text
forge clone kali-lab kali-2
```

The exact command/API is not final yet.

## 4. Disposable VMs

Add a first-class disposable mode:

> create → run → use → destroy the disposable generation

The trusted base remains; the disposable working state does not.

This is one of the key steps toward the project's **Little Qubes** operating model.

## 5. Simpler user CLI

Keep the existing engineering surface internally, but expose a small obvious daily workflow around operations such as:

- list/status
- start
- shutdown/stop
- fresh/reinstall
- clone
- disposable
- update/image status

Recovery, adoption and low-level generation operations should remain available as expert/developer tools.

## 6. Image update automation

Forge should be able to check periodically whether newer supported upstream images/releases exist and report that fact without automatically replacing a trusted base.

Desired policy:

> detect → inform → ask → acquire → verify → prepare → activate only through an explicit safe workflow

## 7. Image provenance improvements

Carry forward the V2 backlog:

- Fedora signing-key fingerprint or independent trusted keyring.
- Strong, explicit provenance boundaries for all supported image families.

A hash alone proves that bytes match a particular digest; provenance is about establishing why that digest/source should be trusted in the first place.

## 8. Lifecycle observability cleanup

- Remove unnecessary QGA probing from ManualGuest status paths.
- Reconsider how much SSH observability belongs in normal interactive desktop VM lifecycle.
- Keep SSH only where it provides a concrete management/health benefit rather than treating it as a universal success condition.

## 9. Kali first-use hygiene

Avoid relying on upstream/default credentials as the desired steady-state experience. V2.5 should define an explicit first-use credential/bootstrap policy without turning ManualGuest into an unnecessarily invasive provisioning system.

## 10. GNOME Boxes evaluation

Evaluate GNOME Boxes as an additional human-friendly GUI/viewer while preserving **Forge as the management authority**.

This is an evaluation target, not a statement that Boxes currently owns or manages Forge state. Any integration must first prove that it does not bypass Forge's lifecycle, storage, topology or ownership invariants.

## 11. Whonix operational polish

Preserve the validated Gateway/Workstation topology while improving day-to-day ergonomics and documenting the expected Whonix/Tor workflow more clearly.

## 12. Host/network hardening backlog

Carry forward:

- host-wide UDP port collision preflight/reservation for Whonix;
- further reduction of the privilege boundary below broad `org.libvirt.unix.manage` where practical;
- explicit Kali preparation recovery workflow.

---

## Project philosophy

Forge is not trying to become another general-purpose virtualization GUI.

The long-term idea is closer to a small **Little Qubes-style control plane**:

- trusted prepared bases,
- isolated workloads,
- explicit network policy,
- cheap clones,
- disposable working environments,
- reproducible lifecycle,
- cryptographically grounded image acquisition,
- and a management layer that knows exactly what it owns.

V2 built the safety machinery.

**V2.5 should make that machinery pleasant to use.**

---

## Repository layout

```text
crates/
├── forge-cli
├── forge-core
├── forge-doctor
├── forge-domain
├── forge-hardware
├── forge-host
├── forge-images
├── forge-libvirt
├── forge-profiles
├── forge-provisioning
├── forge-state
└── forge-storage
```

Each directory is a Rust crate with a focused responsibility. `forge-cli` provides the executable interface; the remaining crates separate policy, state, image, storage, host and libvirt concerns so that the project does not collapse into one monolithic implementation.

Additional technical and learning documentation lives under `docs/`.

---

## Status

**Forge V2: released and formally closed.**  
**Forge V2.5: planned — usability, automation, cloning/disposables and operational polish.**
