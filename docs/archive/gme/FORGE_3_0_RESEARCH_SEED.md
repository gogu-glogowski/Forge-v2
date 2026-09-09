# Forge 3.0 research seed

GME V1 is research material, not a reference implementation. Its plans,
evidence and failure modes should inform a new design, but the old crate,
broker, helper, virtio channel and verifier should not be copied mechanically.

Before designing a Forge 3.0 subsystem, revalidate the product requirement,
threat model, supported guest layouts, operator boundaries, recovery semantics
and acceptable proof strength. Start with the smallest standard libvirt and
host mechanisms that satisfy the requirement. Treat offline mutation,
candidate promotion, guest discovery, SELinux metadata and filesystem topology
as separate claims that each need evidence. Prefer explicit identity binding,
source immutability, candidate isolation, bounded operations, durable evidence,
replay refusal and fail-closed recovery. A privileged component needs a
concrete security and product justification and must not become a generic shell
or path broker.

## Ready-to-use agent prompt

> Analyse the GME V1 archive as research material for Forge 3.0. Do not copy
> the existing implementation. Revalidate the requirements, threat model,
> supported filesystem/layout matrix, operator workflow and recovery claims.
> Design a simpler, testable, fail-closed solution from first principles.
> Prefer standard Fedora and libvirt mechanisms over custom privileged
> infrastructure. Every privileged component must have a concrete security and
> product justification, a narrow interface, and host-native evidence. Use the
> archived lessons, evidence and failure modes as hypotheses to test, not as
> requirements. Separate metadata/identity verification, guest discovery,
> mutation, candidate promotion and recovery so each can be removed if V2.5
> or the future product does not need it.
