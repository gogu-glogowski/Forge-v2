# GME V1 research archive

## Problem and original requirements

GME was proposed as an offline Linux guest mutation facility for preparation
and normalization. It aimed to apply bounded, typed changes to an offline
staging or candidate image without exposing arbitrary qcow2 paths, guest paths,
bytes, commands, mounts, or backends to an unprivileged caller. The original
requirements included trusted preparation/generation identity, source
immutability, candidate isolation, explicit preconditions and postconditions,
durable evidence, replay resistance, fail-closed recovery, and support for
different Fedora, Debian, Ubuntu, Kali, openSUSE, Btrfs, ext4, XFS and LVM
layouts. Whonix was expected to require paired gateway/workstation policy.

## Proposed architecture

The experiment defined typed plans, logical guest destinations,
content-addressed artifacts, bounded sessions, journals, evidence and a
completion ledger. A session was intended to move through planning, resolution,
preflight, discovery, read/write application, verification, flush, close and
evidence publication. Uncertainty led to recovery or failure; success was never
inferred from a partially matching guest filesystem.

The source image was to remain untouched. A disposable qcow2 candidate or
staging clone was the transaction boundary, with promotion only after complete
verification. This was image-level isolation, not filesystem-wide atomic
rollback. Path containment rules covered traversal, symlink/hardlink
substitution, alternate roots, filesystem crossing and normalization ambiguity.
Metadata and relevant SELinux labels were modeled where a profile could verify
them.

## Evidence and experiments

The execution core and candidate transaction work produced evidence on fresh
single-ext4 ephemeral qcow2 fixtures: source immutability, candidate-only
mutation, bounded operations, unrelated sentinel preservation, image health,
durable journal/evidence, exactly-once ledger publication, deterministic
recovery classification and replay refusal. Those results are limited to the
tested topology and do not prove Fedora staging promotion or broad filesystem
coverage.

The helper migration and multi-file acceptance designs preserved artifacts,
generators, bindings and sentinels in synthetic fixtures. The documented
real-preparation migration was not completed, and no authoritative Fedora
staging image was promoted through GME. The clean-host candidate-binding test
also demonstrated that old experiments assumed host-specific staging state.

## Failure modes and dead ends

- Direct libguestfs/`virt-customize`/supermin appliance inspection was difficult
  to make reliable in the restricted host/sandbox environment and did not
  establish bounded V2.5 proof.
- Fedora Btrfs root subvolume identity, separate filesystems, LVM and richer
  topology defeated assumptions based on a single ext4 root. Hardcoded mount
  logic was not a sufficient authoritative layout model.
- Host privilege and sandbox boundaries made it unsafe to treat a generic
  helper, arbitrary path, or ambient root access as a product interface.
- Synthetic transaction tests passed their stated scope, but they did not
  establish real Fedora helper migration, in-guest bootstrap, normalization, or
  canonical-base authority.
- A serial/virtio transport alone could not bootstrap a trusted guest endpoint;
  SSH, cloud-init, NoCloud, shared folders and generic QGA execution were
  intentionally unavailable.

## V2.5 disposition

GME was removed from active V2.5 because its generic offline mutation scope and
privilege/host-topology machinery were disproportionate to the remaining
product path. V2.5 retains persistent Create, Clone, Fresh, trusted bases and
generations, provenance, durable ownership/state, reconciliation, Kali,
Whonix, Fedora operator-assisted preparation, standard libvirt and forge doctor.
Automatic guest mutation is not required for those paths. The archived passing
fixture results are research evidence, not a production readiness claim.

Security properties worth preserving in future work are typed identity binding,
exact source/candidate separation, no caller-controlled paths or commands,
least privilege, explicit operation scope, durable evidence, replay refusal and
fail-closed ambiguity handling. They must be revalidated against a new threat
model rather than copied from the old implementation.
