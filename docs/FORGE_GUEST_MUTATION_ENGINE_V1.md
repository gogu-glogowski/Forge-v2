# Forge Guest Mutation Engine V1

Status: Phase 4.6C-I implementation in progress. The core typed plan,
artifact, logical-destination, session-state and evidence contracts are now
implemented; guestfish session execution and disposable-image acceptance
proof remain subsequent implementation gates. No guest mutation is performed
by this crate.

The short-lived capability/session lifecycle is intentionally reusable as a
future Forge Device/Media Session concept: trusted device identity, bounded
capability, specific target VM, temporary access, detach, and capability
expiration. GME V1 does not implement USB/VFIO/PCI passthrough, physical block
devices, mounting, automount policy, forensic acquisition, serial devices, or
optical-device passthrough.

## Purpose and boundary

Forge Guest Mutation Engine (GME) is a reusable offline Linux guest mutation
facility inside Forge. `forge-preparation-broker` remains the single privileged
boundary. GME is not a generic root filesystem API: an unprivileged request
selects only a trusted plan and transaction identity. The broker resolves the
target disk, guest root, artifacts, policy and backend from trusted Forge state.
Windows is out of scope for V1; Whonix requires paired-target policy.

## Trust model

The broker authenticates the peer with `SO_PEERCRED`, validates a path-free
request, and resolves a private `ResolvedPreparationDiskCapability` from a
trusted preparation/generation record. The capability expires when the bounded
session closes. No persistent writable handle escapes the session. Direct
libguestfs is an implementation detail selected by the broker, never by the
caller.

## Session lifecycle

`GuestMutationSession` has explicit states:

`Planned -> Resolved -> Preflighted -> Discovering -> OpenRw -> Applying ->
Verifying -> Flushed -> Closed -> Evidenced -> Completed`.

Any uncertainty transitions to `RecoveryRequired` or `Failed`; completion is
never inferred from partly matching files. The session verifies the VM is
offline, disk identity and topology, filesystem discovery, preconditions and
postconditions, flushes, closes libguestfs, checks image health, publishes
evidence, then expires the capability.

## Plan contract

`GuestMutationPlan` is immutable and content-addressed. Required fields are:

- format version and deterministic transaction ID;
- target preparation/generation, profile and expected disk/guest identities;
- ordered typed operations;
- trusted artifact identities and provenance references;
- preconditions, postconditions and recovery policy;
- canonical plan digest.

The broker request references a trusted plan ID and transaction ID only. Plan
bytes are loaded from Forge-owned, integrity-protected state; callers cannot
transport mutation instructions.

## Operation language V1

The minimum composable vocabulary is:

- `EnsureDirectory(directory_destination, metadata)`;
- `InstallArtifact(file_destination, artifact)`;
- `RemoveManagedArtifact(destination, expected_identity)`;
- `WriteGeneratedConfig(destination, generator_identity, content_digest)`;
- `SetManagedMetadata(destination, uid_gid_mode_xattrs)`;
- `VerifyArtifact(destination, artifact_identity)`;
- `VerifyAbsent(destination)`.

Destinations are logical IDs resolved by profile policy (for example,
`PreparationHelper`, `PreparationGenerator`, `PreparationBinding`, or a
profile-managed configuration slot), not arbitrary paths. Operations are
ordered, bounded, idempotence is declared, and each has explicit pre/post
predicates and recovery behavior. A plan with 500 operations has the same
privilege boundary as a plan with one operation.

Directory and file destinations are distinct typed IDs. A directory operation
ensures only its directory; a file-producing operation resolves a file target
below a separately resolved parent. Existing directory-at-file or file-at-
directory collisions fail closed.

## Artifact contract

`ArtifactIdentity` contains digest, size, kind and provenance. Artifact bytes
are published into Forge-owned artifact storage, opened read-only, rehashed
before use, and never supplied in the broker request. Temporary material is
private, bounded and removed after clean close. The helper replacement is the
first acceptance artifact: old and new identities are fixed by the preparation
contract.

## Path and filesystem authority

Profile policy maps logical destinations to an allowlisted absolute guest path.
The engine rejects traversal, absolute-path injection, symlink and hardlink
substitution, bind-like topology, filesystem crossing, alternate roots and
normalization ambiguity. Before mutation it resolves and records inode/type and
mount identity; after mutation it rechecks them. A malicious guest filesystem,
TOCTOU change or ambiguous root discovery yields `RecoveryRequired`.

Discovery supports ext4, xfs, btrfs/subvolumes, EFI, separate `/boot`/`/home`,
LVM and multiple filesystems through typed probes. Root selection must be
unique and policy-approved; Fedora Btrfs assumptions remain in the Fedora
profile, not in the core.

## Atomicity and recovery

Forge does not claim filesystem-wide rollback from libguestfs. The preferred
transaction boundary is a disposable qcow2 overlay or staging clone; the
candidate is promoted only after complete verification. Journal states are
`Preparing`, `Applying`, `Verifying`, `Completed`, `RecoveryRequired`, and
`Failed`. A crash after any mutation but before durable completion makes the
candidate ineligible for inference-based resume; Forge either verifies the
exact journal/plan boundary or discards/rebuilds the candidate. Ledger entries
are create-once and transaction-bound, so replay cannot publish twice.

## Metadata and SELinux

The core models uid/gid, mode, xattrs and relevant timestamps without assuming
SELinux. Profiles declare label requirements and relabel policy. Fedora may
require `bin_t`, `lib_t` or other policy labels; profiles that cannot faithfully
verify labels must report the limitation rather than claim success.

## Evidence

`GuestMutationEvidence` records plan/transaction digest, target disk and guest
identity, artifact identities, pre-state, ordered operation outcomes,
post-state metadata/hashes, image-health result, clean-close result and replay
identity. It avoids unnecessary guest content. Journal, evidence and one
success-ledger entry are atomically and durably published.

## Broker authorization

The future operation is `ApplyGuestMutationPlan`. Its request contains only
trusted plan identity, target preparation/generation identity and transaction
identity. `SO_PEERCRED`, fixed broker policy and trusted state resolution remain
mandatory. There is no caller field for disk path, guest root, destination,
bytes, executable, argv, shell, mount, chmod/chown, SELinux command or backend.

## Profile layering

Core GME supplies discovery, capabilities, sessions, typed operations,
artifacts, journaling, recovery and evidence. Fedora, Debian, Ubuntu, Kali and
openSUSE profiles supply logical destinations, package/config policy,
filesystem expectations and SELinux/metadata rules. Whonix supplies a paired
gateway/workstation plan and rejects single-disk assumptions.

## Acceptance tests

1. **Helper migration:** on a disposable qcow2, replace the exact B3 helper
   (`bb546fa9…0ad4a2`, 784624 bytes) with the corrected helper
   (`cfc6ee47…16a5`, 802896 bytes), preserving generator, binding and sentinel;
   prove one bounded session, exact evidence, replay refusal and image health.
2. **Multi-file plan:** apply 5–10 profile-resolved generated/config artifacts
   plus metadata in one session; prove one plan digest, ordered operations,
   unchanged unrelated sentinels, one ledger entry and deterministic recovery.

## Fedora normalization mapping

`FedoraWorkstationNormalizationV1` will compile into a plan of logical
destinations: remove installer residue, ensure managed directories, install
or remove managed artifacts, write generated NetworkManager/GNOME policy,
set declared metadata/labels, and verify identity/network/security predicates.
Normalization remains unexecuted in Phase 4.6C.

## Red-team conclusions

An attacker knowing the socket protocol can submit malformed or replayed
identities, but cannot select a qcow2, guest root, destination, bytes, command
or backend. Symlink/hardlink/path traversal and alternate-root attacks are
blocked by capability-bound resolution and post-verification. Remaining high
risk is trusted Forge-state compromise or a profile-policy defect; both are
outside the unprivileged broker request and require review, digest binding and
fail-closed tests.

## B4/R2 disposition

- Reuse directly: path-free request, trusted preparation resolution, direct
  libguestfs boundary, artifact identity checks, classifier/planner, journal,
  evidence, ledger and replay semantics.
- Generalize: `ResolvedPreparationDiskCapability` and `helper_replacement` into
  GME capability/session/plan/artifact modules.
- Keep as first acceptance path: helper parser contract and B4 helper migration.
- Eventually obsolete: one-file-specific replacement endpoint and duplicated
  B4-only constants after GME acceptance.
- Keep under review: interrupted B4 channel/inventory code; it remains outside
  GME until separately authorized.

## Recommended implementation order

1. Define typed plan, artifact and logical-destination schemas.
2. Refactor the capability/session around the existing direct-libguestfs
   primitive with a fixed operation interpreter.
3. Implement discovery and path/symlink containment tests.
4. Implement qcow2 overlay transaction, journal/recovery and evidence.
5. Port the helper migration acceptance test, then the multi-file test.
6. Add Fedora profile compilation for normalization without executing it.
7. Review and retire the one-file compatibility path only after parity proof.

## Phase 4.6C-I implementation note

The initial `forge-guest-mutation` crate implements the immutable plan and
identity layer with canonical serialization, bounded operation count, logical
destination validation, traversal rejection, and typed evidence/session
states. It intentionally does not yet expose a write handle, guestfish script,
artifact upload API, broker endpoint, or real-image execution path. Those must
be added only together with the capability-bound session and the two genuine
disposable-qcow2 acceptance proofs.

## Phase 4.6C-II execution-core result

The execution core is proven on an ephemeral integration-test qcow2 using a
host-native direct-libguestfs session. The genuine fixture topology is one
single ext4 root. Trusted content-addressed artifact resolution, profile
logical-destination resolution, the bounded one-shot session, exact mutation,
unrelated-sentinel preservation, clean close, session-reuse refusal and image
health were all proven. Real Fedora staging remained untouched. Broader
ext4/xfs/btrfs/LVM topology coverage, candidate transaction/recovery and
durable cross-process evidence remain Phase 4.6C-III work.
