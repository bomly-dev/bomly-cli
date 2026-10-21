# ADR-0040: The SDK owns shared meaning; integrations live in their own modules; the CLI keeps orchestration

- **Date:** 2026-08-26
- **Revised:** 2026-10-19 (folds ADR-0029, ADR-0030, ADR-0038, ADR-0045 and the ownership half of ADR-0046)
- **Status:** Accepted

## Context

A month of fixes followed one pattern: behavior about a shared domain object
was implemented where the symptom appeared, in the CLI or one detector, and
drifted from its siblings. The SBOM codec existed four times, the purl-type
table twice with different answers for `pkg:hex`, and the SPDX panic guard
only in the CLI, so plugins wrote unvalidated license strings. "Fix at the
right depth" said to centralize, but not in which repository.

## Decision

- **The SDK (`bomly-sdk`) owns what shared objects mean**: identity,
  coordinates, package URLs, licenses, SBOM assertions, graph and merge
  semantics, validation gates, and the shared helper kits. A change touching
  meaning lands there first; the CLI and plugins consume the release.
  Behavior stays out of the SDK only when it is specific to one consumer by
  nature, not merely unused by others today.
- The SDK holds today: the helper subpackages (`system`, `filecache`,
  `logkit`, `detectorkit`, `matcherkit`, `testkit`); `purlkit` and `spdxkit`
  as the one home for package-URL and SPDX behavior, including the one
  purl-type to ecosystem table; the SBOM codec (`sbom`) and `graphview`; and
  the scan record (`scan`). No package under `internal/` imports the raw purl
  or SPDX libraries, and this repository keeps no shim copies.
- **External-integration components live in their own `bomly-plugin-*`
  repositories**, consumed as ordinary pinned Go modules: the reachability
  analyzers, the OSV, deps.dev, Scorecard and Grype matchers, and the Syft
  detector. Auditors and native detectors stay here.
- **The CLI keeps** presentation, command surface, pipeline orchestration and
  policy wiring: how Bomly uses the model, never what it means. **A plugin
  keeps** one external tool's integration specifics.
- Release order is SDK tag, then plugin releases, then the CLI pin, because
  minimum version selection compiles plugin modules against the CLI's SDK
  pin. When the schedule cannot absorb that, the local fix ships with the SDK
  issue filed and linked from the code.

## Rejected

Nested modules here through a committed `go.work` or `replace` directives:
extra CI machinery, and the `replace` variant broke `go install ...@latest`.
A minimal codec core in the SDK with a richer CLI layer: that produced four
copies.

## Consequences

- An SDK change is slower to ship than an internal patch; that is the price
  of one source of truth.

Enforced by: the `depguard` rule `internal-kits` and the `[purl-type]`
`forbidigo` patterns in `.golangci.yml`; the `purlstring` analyzer in
`internal/tools/guardcheck`; the no-`replace` CI check.
