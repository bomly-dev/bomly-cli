# ADR-0006: The domain model is three collections joined by package URL

- **Date:** 2026-06-04
- **Revised:** 2026-10-19 (folds ADR-0001)
- **Status:** Accepted

## Context

The original model put licenses, vulnerabilities and audit verdicts on the
dependency graph node itself. Fifty occurrences of one package carried fifty
copies of its advisories, every stage synchronized them by hand, and a
finding embedded the data it was about.

## Decision

The SDK model separates three concerns, joined by the canonical package URL:

- The **dependency graph** holds detection-time nodes: identity, scopes,
  locations, relationship, edges. It carries no enrichment. ADR-0041 later
  typed its nodes.
- The **package registry** holds one `Package` per canonical PURL with
  licenses, vulnerabilities, scorecard and end-of-life data. Enrichment is
  written once per package, never per occurrence.
- **Findings** are references: policy fields plus `PackageRef` and, for
  vulnerabilities, `VulnerabilityID`. Consumers follow the references;
  nothing is copied.

Reachability annotates the `Vulnerability` record on the registry package,
not the finding, so `--analyze` is useful without `--audit`. Output resolves
the annotation by (package ref, vulnerability id) when rendering.

`Vulnerability` is OSV-aligned and extended with the matching-stage fields
(CVSS, EPSS, KEV, fixed versions, reachability). Every matcher writes that
one shape.

## Rejected

Graph-mutating enrichment (one copy of the advisories per occurrence) and
findings that embed their package. Both duplicated data and drifted.

## Consequences

- Every renderer joins by PURL; the scan document is this model on the wire
  (ADR-0011).
- Vulnerability consolidation and remediation happen once per package
  (ADR-0022).
- Audit runs without analysis, and analysis without audit.

Enforced by: the SDK model types; `dev-docs/MODELS.md` is the reference.
