# ADR-0037: SBOM assertions are typed SDK model fields, not metadata keys

- **Date:** 2026-08-26
- **Status:** Accepted

## Context

Bomly's name comes from SBOM, yet the SDK model cannot carry most of what the
two major SBOM formats say about a component. Relative to SPDX 2.3 and
CycloneDX 1.5/1.6, `Dependency` and `Package` have no supplier, no
originator/author, no description, no homepage, no generic external
references, no declared-versus-concluded license distinction (`LicenseType`
has exactly one value), and graph edges carry no relationship type. Document
level assertions — provenance, lifecycle, serial number, the primary
component's own facts — have no model home at all.

The consequences are measurable. `ToGraph` (`internal/sbom/graph.go`)
discards CPEs, digests, vulnerabilities, EOL, and every origin URL on ingest
because the graph hop has nowhere to put per-assertion data it cannot trust
blindly; `bomly scan --sbom --format spdx` therefore silently drops most of
what the source document asserted (issue #396). PR #391 tried to close that
gap by smuggling assertions through `Dependency.Metadata` under ad-hoc
`bomly.sbom.*` keys and did not survive review: twenty rounds kept finding
the same two structural defects — untyped metadata values cross the plugin
trust boundary without re-clearing any publication gate, and merge semantics
re-decided at every call site drift apart. The metadata map also does not
survive the JSON wire as typed values, so plugins see `[]any` where the CLI
wrote structs.

## Decision

Every SBOM assertion Bomly preserves is a typed, validated field on the SDK
model. The SDK model is the intermediate representation between SPDX,
CycloneDX, the CLI, detectors, and plugins — rich enough that the format
codecs are projections of it, not extensions to it.

**Component-level fields.** `Dependency` and `Package` (or `Coordinates`
where identity-adjacent) gain optional `omitempty` fields for supplier,
originator, description, homepage, and a typed
`ExternalReference{Type, URL, Comment, Hashes}` list whose type vocabulary
covers both formats' reference categories. `PackageLicense` grows to
distinguish declared from concluded and to carry extracted license text for
`LicenseRef-*` identifiers (issue #410). The digest algorithm set is a
registry aligned with both formats' hash vocabularies rather than two string
constants. Scope gains an SDK-owned mapping to and from the CycloneDX
vocabulary (`required`/`optional`/`excluded`), so the mapping exists in
exactly one place and is exercised in both directions.

**Typed edges.** `DependencyEdge` gains an optional relationship kind
(default depends-on; contains, describes, and the other members both formats
need). Absence means depends-on, so the wire stays additive.

**A document-level carrier.** `GraphContainer` gains a typed document
assertions block (provenance, lifecycle, serial identity, primary-component
assertions), so what a source document says about *itself* survives
ingest → graph → re-export instead of being re-synthesized or lost.

**Validation lives with the type.** Every field that carries untrusted input
validates at the model boundary the way `DependencyOrigin` already does:
custom JSON codecs re-run normalization on both marshal and unmarshal, so a
value that bypassed a call-site gate is still caught at the wire. URL fields
share the credential/local-path gate family from ADR-0033, with asserted
semantics where the source declared the value. Every new parser of untrusted
input ships with a registered fuzz target from its first commit.

**Merge semantics are declared per field class, once.** Scalars fill gaps,
sets union, and contradictions keep distinct occurrences under ADR-0033's
rule — implemented in the SDK's fold/merge helpers, never re-decided at call
sites. The precedence among sources is stated once: detection classifies,
ingest corrects, enrichment fills gaps.

**Metadata becomes an escape hatch again.** The `Metadata` map remains for
genuinely component-private data, with the `bomly.` prefix documented as
reserved. No new user-visible feature may ship its data as a metadata key;
the migration path for a metadata key is a typed field.

## Consequences

- Issue #396 becomes implementable: preservation is adding codec projections
  for fields that already exist, carry their own gates, and merge by declared
  rules — not smuggling and re-gating at every site.
- The wire stays `bomly.plugin.v1`: all additions are optional `omitempty`
  fields, enforced by the existing wire-compatibility tests in the SDK.
  Plugins that ignore the new fields keep working; plugins that want to
  assert supplier or references now can, through the same contract built-ins
  use.
- The model grows. That is the accepted trade-off, and it is bounded: fields
  are admitted because SPDX or CycloneDX defines them, not speculatively, and
  each admission names its validation gate and merge class in the SDK doc
  comment.
- `ToGraph`/`FromDepGraph` shrink from lossy translations into projections,
  and the export-only joins (packages reaching back through `PackageRef` for
  location and origin data) stop being special cases.
- The deliberately deferred items from #396 stay deferred until their own
  adversarial review: ssh VCS locators, metadata-only primary components,
  and supplier-contact privacy.
