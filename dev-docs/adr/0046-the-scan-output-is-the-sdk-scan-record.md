# ADR-0046: The scan output is the SDK's scan record

- **Date:** 2026-09-24
- **Status:** Accepted

## Context

`bomly scan --format json` emitted a document defined in `internal/output`:
three collections -- manifests, packages, findings -- joined by package URL
(ADR-0006, ADR-0011), each a CLI-local projection of an SDK type with its own
JSON tags, builders and tests. The document carried nothing about the run
that produced it: no subject, no timestamp, no tool version, no verdict; the
verdict lived only in the process exit code.

A second consumer of that document now exists in the SDK's own `scan`
package, which defines it as `scan.Record` under the schema `bomly.scan.v1`
with the envelope the CLI never wrote. Under ADR-0040 a shape two consumers
share belongs in the SDK, and a projection maintained beside it would have
to be kept equal to it by hand -- the drift ADR-0045 ended for the SBOM
codec.

## Decision

`bomly scan` emits `scan.Record`. The CLI builds it from the pipeline's
consolidated manifests, registry and findings, fills `subject` from the
execution target (repository, ref, and the commit the ref resolved to --
never a local path), `run` from the invocation, and `verdict` from the same
count the exit code uses, and writes it through `scan.Encode`, so what is
written is the canonical, digested form.

The projection types are gone. A manifest and its dependencies are
`scan.Manifest` and `scan.Dependency`; a package is `model.Package` as the
registry holds it; a finding is `model.Finding`, referencing its package by
`package_ref`; a license is `model.PackageLicense` and a location
`model.PackageLocation`. The `diff` and `explain` documents keep their own
`schema_version` and adopt the same finding and package shapes. The one
projection the old types did that a type cannot -- backfilling a finding's
severity from its advisory -- is a function, `output.FindingsWithSeverity`,
applied wherever findings enter a document. A package's presentation
identity (`@scope/name` from `org` and `name`) is derived by the renderers,
not written into the document.

## Consequences

- `findings[].package` (an identity block) becomes `findings[].package_ref`
  (the package URL); `packages[].name` and `org` are coordinates, not a
  display name; empty collections are omitted rather than written empty. The
  goldens and generated schemas were regenerated once.
- `subject`, `run`, `verdict`, `policy`, `waivers` and per-section `digests`
  are new optional keys; `findings[].decision` records which resolver settled
  a policy status. Local `--path` scans inside a repository record the
  working tree's HEAD.
- `internal/output` no longer defines the scan document's shape; its guards
  live in the SDK (`scan/record_test.go`). The CLI keeps the builders that
  need pipeline context -- manifest paths relative to the subproject, the
  `Matched` flag from the registry -- and the renderers.
- The scan JSON is stable across runs of the same content: `scan.Encode`
  orders every collection, so a digest over it identifies what was found.
