# Forge V2.5 pre-reinstall checkpoint

This checkpoint is not a release and makes no final Fedora Workstation
acceptance claim. The Fedora 4.7 flow is only partially operationally proven:
the clean-host canonical-base publication path has not yet been proven.

The current Fedora host will be reinstalled. Acceptance must resume on a clean
host with reproducibility and trust re-established before further conclusions
are drawn. The accumulated host state is not treated as reproducible.

The GME experiment remains deferred. Its retained architecture and findings
are documented, but they are not part of the V2.5 critical path.

Historical update: after this checkpoint was written, GME, the preparation
broker/helper and the custom image verifier/PolicyKit path were removed from the
active V2.5 workspace. The record above is preserved as history; current Fedora
preparation uses standard libvirt identity checks and explicit operator-assisted
qcow2 integrity verification.
