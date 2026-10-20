# ADR-0037: SBOM assertions are typed SDK model fields, not metadata keys

- **Date:** 2026-08-26
- **Revised:** 2026-10-19
- **Status:** Accepted

## Context

The model could not carry most of what SPDX and CycloneDX say about a
component: supplier, originator, description, homepage, external references,
declared versus concluded licenses, typed edges, or anything a document says
about itself. Ingest discarded what it could not place, and
`bomly scan --sbom --format spdx` silently dropped most of the source
document. Carrying assertions through `Dependency.Metadata` under
`bomly.sbom.*` keys failed twenty review rounds on two structural defects:
untyped values cross the plugin boundary without re-clearing any publication
gate, and merge semantics get re-decided at every call site.

## Decision

- Every preserved assertion is a typed, `omitempty` field on the SDK model,
  admitted only because SPDX or CycloneDX defines it, each with its
  validation gate and merge class in its doc comment. The format codecs are
  projections of the model, not extensions to it.
- Validation lives with the type. Codecs re-run normalization on marshal and
  unmarshal, so a value that bypassed a call-site gate is still caught at the
  wire. URL fields share the origin gate family (ADR-0033). Every new parser
  of untrusted input ships with a fuzz target.
- Merge semantics are declared once per field class in the SDK: scalars fill
  gaps, sets union; detection classifies, ingest corrects, enrichment fills
  gaps.
- Usage facts carry their attribution. Scope and relationship are recorded
  per declaration site, reachability as evidence keyed by the module root
  that established it. A conjunctive filter ("reachable, runtime and direct")
  must find its conjuncts on one usage, never on three summaries of one node.
- Edges carry an optional relationship kind (default depends-on), preserved
  through every graph reconstruction.
- Document-level assertions (provenance, lifecycle, serial, sources) attach
  to `GraphEntry`, next to the manifest metadata that identifies the source
  document, so a merged export can state its own identity and link each
  source (ADR-0042).
- `Metadata` remains an escape hatch for component-private data. No
  user-visible feature ships its data as a metadata key.
- Where the model's reading of a format value was disputed (CycloneDX
  `optional`, an absent `scope`), the specification text settled it; that
  rule is general and lives in `AGENTS.md`.

## Rejected

Metadata-key smuggling. A container-level document block: consolidation
combines entries from several documents and would have to merge or discard
their identities.

## Consequences

- The wire stays `bomly.plugin.v1`: all additions are optional fields pinned
  by the SDK's wire-compatibility fixtures.
- The model grows deliberately; each field is contract surface with a stated
  gate.

Enforced by: the SDK's wire fixtures and
`TestWireV1ZeroValuesEmitOnlyDeclaredKeys`.
