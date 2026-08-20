# Architecture Decision Records

This directory holds Bomly's architecture decision records (ADRs): one file
per decision, numbered chronologically by the date the decision was first
recorded. Decisions migrated from the old inline decision log in
[`../ARCHITECTURE.md`](../ARCHITECTURE.md) keep their original free-form
prose; new decisions follow the template.

To record a new decision:

1. Copy [`TEMPLATE.md`](TEMPLATE.md) to `NNNN-<kebab-case-title>.md`, using
   the next unused number.
2. Fill in the date, status, and sections.
3. Add a row to the index below.

To revise a decision, add a new ADR that supersedes it and set the old ADR's
status to `Superseded by [ADR-NNNN](NNNN-slug.md)`; do not rewrite history
(typo and clarity fixes are fine).

## Index

| ID | Date | Title | Status |
|----|------|-------|--------|
| ADR-0001 | 2026-05-14 | [Reachability annotates vulnerabilities, not findings](0001-reachability-annotates-vulnerabilities-not-findings.md) | Accepted |
| ADR-0002 | 2026-05-28 | [Scorecard matcher reads precomputed runs, not the library](0002-scorecard-matcher-reads-precomputed-runs-not-the-library.md) | Accepted |
| ADR-0003 | 2026-05-30 | [YAML configuration is nested at the file boundary](0003-yaml-configuration-is-nested-at-the-file-boundary.md) | Accepted |
| ADR-0004 | 2026-05-31 | [Dependency graph benchmarking is hidden and local-only](0004-dependency-graph-benchmarking-is-hidden-and-local-only.md) | Accepted |
| ADR-0005 | 2026-06-01 | [Reachability analyzers derive local hierarchy closures](0005-reachability-analyzers-derive-local-hierarchy-closures.md) | Accepted |
| ADR-0006 | 2026-06-04 | [Three-collection domain model — dependencies, packages, findings](0006-three-collection-domain-model-dependencies-packages-findings.md) | Accepted |
| ADR-0007 | 2026-06-25 | [Package locations are detector-relative today](0007-package-locations-are-detector-relative-today.md) | Accepted |
| ADR-0008 | 2026-07-07 | [Python graph resolution is lockfile-first, validated, and provenance-backed](0008-python-graph-resolution-is-lockfile-first.md) | Accepted |
| ADR-0009 | 2026-07-07 | [Detector fallbacks are loud, annotated degradations](0009-detector-fallbacks-are-loud-annotated-degradations.md) | Accepted |
| ADR-0010 | 2026-07-07 | [Detector logs are request-scoped by subproject](0010-detector-logs-are-request-scoped-by-subproject.md) | Accepted |
| ADR-0011 | 2026-07-08 | [JSON findings are references; MCP responses are compact projections](0011-json-findings-are-references-mcp-responses-compact.md) | Accepted |
| ADR-0012 | 2026-07-13 | [Recursive discovery prunes native multi-module roots per package manager](0012-recursive-discovery-prunes-native-multi-module-roots.md) | Accepted |
| ADR-0013 | 2026-07-14 | [Subprojects and modules are distinct concepts, derived in views](0013-subprojects-and-modules-are-distinct-concepts.md) | Accepted |
| ADR-0014 | 2026-07-14 | [Per-module manifest emission lives in detectors, not consolidation](0014-per-module-manifest-emission-lives-in-detectors.md) | Accepted |
| ADR-0015 | 2026-07-17 | [Registry matching eligibility is an occurrence-level engine boundary](0015-registry-matching-eligibility-is-occurrence-level.md) | Accepted |
| ADR-0016 | 2026-07-17 | [Unresolved dependency parents use an explicit unknown relationship](0016-unresolved-parents-use-explicit-unknown-relationship.md) | Accepted |
| ADR-0017 | 2026-07-17 | [Bun text lockfiles are native; binary lockfiles degrade explicitly](0017-bun-text-lockfiles-are-native-binary-lockfiles-degrade.md) | Accepted |
| ADR-0018 | 2026-07-23 | [Enrichment consolidates alias-equivalent vulnerabilities](0018-enrichment-consolidates-alias-equivalent-vulnerabilities.md) | Accepted |
| ADR-0019 | 2026-07-23 | [Finding policy-status resolution belongs inside audit](0019-finding-policy-status-resolution-belongs-inside-audit.md) | Accepted |
| ADR-0020 | 2026-07-25 | [Repository configuration requires explicit trust](0020-repository-configuration-requires-explicit-trust.md) | Accepted |
| ADR-0021 | 2026-07-25 | [External lookups use `Coordinates.EcosystemName()`, never the bare `Name`](0021-external-lookups-use-coordinates-ecosystemname.md) | Accepted |
| ADR-0022 | 2026-07-25 | [Vulnerability remediation is derived enrichment](0022-vulnerability-remediation-is-derived-enrichment.md) | Accepted |
| ADR-0023 | 2026-07-25 | [Grype OS-package distro comes from the PURL, not pipeline plumbing](0023-grype-os-package-distro-comes-from-the-purl.md) | Accepted |
| ADR-0024 | 2026-07-26 | [One typed detector-warning channel, no CI-readiness stage](0024-one-typed-detector-warning-channel-no-ci-readiness-stage.md) | Accepted |
| ADR-0025 | 2026-07-26 | [The discovery probe attributes a skip reason per candidate](0025-the-discovery-probe-attributes-a-skip-reason-per-candidate.md) | Accepted |
| ADR-0026 | 2026-07-27 | [Untrusted documents have input limits](0026-untrusted-documents-have-input-limits.md) | Accepted |
| ADR-0027 | 2026-07-28 | [Dependency detail changes are canonical diff results](0027-dependency-detail-changes-are-canonical-diff-results.md) | Accepted |
| ADR-0028 | 2026-08-08 | [Startup banner frames are procedural; animation is opt-in; gating is env-var-only](0028-startup-banner-frames-are-procedural.md) | Accepted |
| ADR-0029 | 2026-08-12 | [Shared helper code lives in bomly-sdk subpackages, not CLI-internal packages](0029-shared-helper-code-lives-in-bomly-sdk-subpackages.md) | Accepted |
| ADR-0030 | 2026-08-13 | [External-integration components live in their own repositories, consumed as ordinary Go modules](0030-external-integration-components-live-in-own-repos.md) | Accepted |
| ADR-0031 | 2026-08-13 | [Syft-JSON SBOM ingest is removed; treated as any unsupported format](0031-syft-json-sbom-ingest-is-removed.md) | Accepted |
| ADR-0032 | 2026-08-14 | [SBOM exports carry a synthesized primary component and shared document identity](0032-sbom-exports-carry-synthesized-primary-component.md) | Accepted |
| ADR-0033 | 2026-08-24 | [Package origin is detector-asserted; SBOM export only projects it](0033-package-origin-is-detector-asserted.md) | Accepted |
| ADR-0034 | 2026-08-24 | [Decisions are recorded as individual ADRs](0034-decisions-are-recorded-as-individual-adrs.md) | Accepted |
| ADR-0035 | 2026-08-20 | [Release assurance is a declarative catalog plus a per-check result contract](0035-release-assurance-is-a-catalog-and-a-result-contract.md) | Accepted |
