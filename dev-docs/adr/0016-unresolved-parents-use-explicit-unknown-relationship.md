# ADR-0016: Unresolved dependency parents use an explicit unknown relationship

- **Date:** 2026-07-17
- **Status:** Accepted

Lockfiles can contain a package component whose parent chain cannot be
recovered. Dropping it hides exposure, while labeling the synthetic manifest
edge direct overstates the evidence. Detectors therefore attach the component
root beneath its owning application or manifest with relationship `unknown`;
known descendants remain transitive. Unknown dependencies are ordinary graph
nodes for every pipeline stage. The optional SDK field is additive for
protocol-v1 plugins, and consumers derive direct/transitive for older graphs
that omit it. Debug logs disclose every attached component without turning a
recoverable graph condition into a warning.
