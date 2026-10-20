# ADR-0011: Output documents are references; MCP responses are compact projections

- **Date:** 2026-07-08
- **Revised:** 2026-10-19 (folds the output half of ADR-0046)
- **Status:** Accepted

## Context

Scan JSON once embedded a package copy and flat advisory fields inside every
finding. Findings-heavy documents were about ten times larger than the data
they held, and the projection drifted from the model. Separately, MCP tool
results land in an agent's context window, and MCP clients truncate large
results into errors.

## Decision

- `findings[]` mirror `sdk.Finding`: `package_ref` (a PURL),
  `vulnerability_id`, `dependency_refs`. Advisory data lives once in
  `packages[]` and consumers join by PURL, as SARIF always did. `diff`
  carries a `packages[]` union of base and head (head wins) for the same
  join.
- `bomly scan` emits the SDK's `scan.Record` (`bomly.scan.v1`): the three
  collections plus `subject` (repository, ref, commit; never a local path),
  `run` and `verdict`, written through `scan.Encode`. The CLI defines no
  projection types of its own; `diff` and `explain` reuse the same finding
  and package shapes.
- Every collection is written, `[]` when empty.
- Each section carries a digest. The document as a whole changes every run
  (`run.id`, timestamps), so consumers compare section digests.
- MCP tools never return CLI documents. They return `mcp/1` compact
  projections, ranked KEV, severity, EPSS, fixability, hard-capped with
  truncation counters. `bomly_explain` is the bounded drill-down; the CLI is
  the artifact channel. MCP projects canonical remediation and never selects
  actions or versions.
- MCP errors expose stable categories only (validation, target preparation,
  resolution, pipeline, plugin inventory). Raw errors may carry paths, URLs
  or credentials and never cross the protocol boundary.

## Rejected

Embedding package and advisory copies in findings; returning full CLI JSON
over MCP.

## Consequences

- One document shape, owned by the SDK (ADR-0040). The CLI keeps the builders
  that need pipeline context, and the renderers.
- Renaming a finding field is an output-contract break and is treated as one.

Enforced by: `scan/record_test.go` in the SDK;
`TestDocumentCollectionsAreAlwaysArrays`.
