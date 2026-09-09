# Preparation broker, helper and verifier archive

## Broker/helper and B1

The preparation-control crate experimented with a privileged broker, a B1
offline helper path, a broker client, and a replacement helper. The broker was
intended to authenticate local peers, resolve a trusted preparation identity,
open the exact shut-off staging image read-only through direct libguestfs, and
publish bounded inspection evidence. B1 also explored a controlled offline
bootstrap transaction for a fixed synthetic image. Requests were designed to
carry trusted identities rather than paths, shell commands or arbitrary argv.

The corresponding domain transport used a preparation-only virtio-serial
channel and framing/replay checks. The planned helper lifecycle included
transient systemd state, a binding under `/run`, SELinux-enforced fixed
allowlists, and cleanup proofs. These mechanisms were experiments and were not
made into a supported V2.5 contract.

## Privilege boundary and staging assumptions

The historical broker evidence required a root-owned, mode `0600` staging image
with a libvirt image SELinux label such as
`system_u:object_r:virt_image_t:s0`. The custom verifier derived a fixed
`/var/lib/libvirt/images/forge-stage-fedora-workstation-44-1.7-<id>.qcow2`
name from a preparation identity, then ran read-only `qemu-img info` and
`qemu-img check`. The PolicyKit/pkexec route was intended to keep the CLI from
choosing arbitrary paths.

The V2.5 decision is simpler: standard libvirt verifies volume identity, key,
path, format, capacity, backing and topology. A rare full integrity proof is
operator-attested with `sudo /usr/bin/qemu-img check -- <exact path>` printed by
Forge. Forge does not execute sudo, change image ownership/mode/ACL/SELinux, or
install a broker/helper/verifier.

## What worked and what did not

Read-only identity and shape checks fit the existing Fedora preparation backend.
The broker’s synthetic and offline fixture checks were useful evidence for
identity binding and fail-closed behavior. They did not justify a permanent
privileged daemon: real guest bootstrap, Fedora/Btrfs layout proof, host
installation, and end-to-end promotion were not established. The extra socket,
unit, PolicyKit action, runtime directories and privilege policy increased
operational surface without being needed by the active V2.5 core.

The following historical names and locations are retained here only as search
and migration context: `/run/forge-preparation-broker`,
`/var/lib/forge-preparation-broker`, `/var/cache/forge-preparation-broker`,
`org.majorforge.preparation.0`, and
`org.majorforge.forge-image-verifier`. They are not active V2.5 interfaces.

## Lessons for future work

Keep the exact identity and fail-closed reasoning. Recheck whether standard
libvirt APIs and explicit operator actions provide the required assurance before
adding a privileged component. Any future privileged component must have a
specific security and product justification, a narrow operation boundary, an
independent recovery model, and host-native evidence.
