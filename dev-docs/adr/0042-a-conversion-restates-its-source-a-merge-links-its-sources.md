# ADR-0042: An exported SBOM has one subject; a conversion restates its source; a merge links its sources

- **Date:** 2026-09-05
- **Revised:** 2026-10-19 (folds ADR-0032)
- **Status:** Accepted

## Context

Both formats give a document exactly one identity and one primary component.
A scan produces many roots (one per manifest or module), and the model can
hold several source documents' assertions. Picking `Roots[0]` as the subject
made two exports of one scan disagree about themselves; minting a fresh
identity on every conversion made `export → ingest → export` drift on each
hop.

## Decision

- When a project root is supplied and the graph does not have exactly one
  root, export synthesizes a primary component named after the project,
  typed `application`, with a `pkg:generic` PURL, depending on every root. Its
  `DocumentRoot-` prefix excludes it on re-ingest. A single natural root
  stays the subject.
- One UUID becomes both the CycloneDX serial number and the SPDX namespace
  nonce, so the two files of one scan correlate.
- The document says only what it knows. Producer metadata comes from the
  `sbom:` config section and is never invented; the project version comes
  from `git describe` on the scanned checkout and is stamped on first-party
  components only; composition is `complete` only for an unfiltered scan
  with no detector warnings.
- The export surface takes the graph already selected for output and the
  prepared entries beside it; the entries carry which document each part
  came from.
- A **conversion that restates its source** (one document in, graph
  unchanged) adopts the source identity in whichever slot the format can
  hold; a caller-pinned identity wins. An export whose graph was filtered,
  enriched or degraded is a merge of one.
- A **merge** mints its own identity and links each source: CycloneDX through
  a `bom` external reference carrying a BOM-Link, SPDX through
  `externalDocumentRefs` with the checksum computed at ingest. Links are read
  back on ingest and re-emitted.
- Document assertions are re-gated on export; a value written onto an entry
  by a plugin never passed a decoder.

## Rejected

`Roots[0]` as the subject; a fresh identity on every conversion.

## Consequences

- `export → ingest → export` is a fixed point for a restating conversion
  within one format, not across formats: CycloneDX cannot hold a non-UUID
  identity.
- A source that reached an entry without passing ingest has no checksum and
  is left unnamed rather than written as an invalid reference.

Enforced by: `TestSingleSourceExportIsAFixedPoint` and
`FuzzDocumentAssertions` in the SDK; the SBOM interoperability check
(ADR-0047).
