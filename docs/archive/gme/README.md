# GME and preparation infrastructure archive

This directory records the research history of the Forge Guest Mutation Engine
(GME), the preparation broker/helper experiments, and the custom image verifier.
The code was removed from the active Forge V2.5 workspace in Cleanup Phase 1.
Git history remains the source for exact implementation details; these notes
preserve decisions, evidence, limitations, and failure modes for future work.

The archive is not a supported V2.5 interface, deployment guide, or reference
implementation. The V2.5 product uses standard `qemu:///system` libvirt paths,
durable Forge state, and explicit operator assistance for rare full image
integrity checks.

- [GME V1 archive](GME_V1_ARCHIVE.md)
- [Broker/helper archive](BROKER_HELPER_ARCHIVE.md)
- [Forge 3.0 research seed](FORGE_3_0_RESEARCH_SEED.md)
