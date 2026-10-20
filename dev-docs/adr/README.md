# Architecture Decision Records

An ADR records a choice Bomly made between viable alternatives, so the next
person who proposes the other alternative finds the reasoning instead of
re-deriving it. The directory holds 20 live records and the stubs of 28
retired ones; the full text of a retired record is in git history.

## When to write one

Write an ADR only when all three hold:

1. **A real alternative exists** that a competent contributor would propose
   again.
2. **Reversing the choice is expensive**: an output or wire contract, a
   cross-repository boundary, a security or trust boundary, a public claim.
3. **The reason is not visible from the code** or from a guard's failure
   message.

Not an ADR: how a feature is implemented, one ecosystem's or one plugin's
behavior, user-interface or message wording, a bug fix, or anything a code
comment, package doc comment or paragraph in
[`../ARCHITECTURE.md`](../ARCHITECTURE.md) can carry. The test: would
someone rewriting the code from scratch, having read only the ADR, make the
same choice? If the ADR only describes what the code does, it is
documentation, and it goes next to the code.

Before adding a record, check whether a live one already owns the topic and
revise that one instead.

## How to write one

Copy [`TEMPLATE.md`](TEMPLATE.md) to `NNNN-<kebab-case-title>.md` with the
next unused number, and add a row to the index. About 300 words, never more
than about 400. One decision per file. A one-paragraph context, the decision
as present-tense rules, the rejected alternative in a sentence, at most five
consequences, and the test, lint rule or analyzer that enforces it. No
implementation history or pull-request chronology; no per-ecosystem lists;
identifiers only where the reader must go.

## Changing one

- **A decision evolves**: revise the body in place and set `Revised:` in the
  header. Git holds the history. Never append an amendment block.
- **A decision is reversed**: write a new ADR and reduce the old file to a
  three-line stub (title, date, `Superseded by [ADR-NNNN](…)`).
- **A record stops being a decision**: reduce it to a stub whose status says
  `Folded into [ADR-NNNN](…)` or `Retired: <reason>; see <home>`.
- Numbers are never reused. Keep the filename so existing links resolve.

The rule itself is [ADR-0034](0034-decisions-are-recorded-as-individual-adrs.md).

## Live decisions

| ID | Date | Title |
|----|------|-------|
| ADR-0006 | 2026-06-04 | [The domain model is three collections joined by package URL](0006-three-collection-domain-model-dependencies-packages-findings.md) |
| ADR-0011 | 2026-07-08 | [Output documents are references; MCP responses are compact projections](0011-json-findings-are-references-mcp-responses-compact.md) |
| ADR-0013 | 2026-07-14 | [Subprojects and modules are distinct; detectors emit per-module manifests; discovery prunes natively expanded roots](0013-subprojects-and-modules-are-distinct-concepts.md) |
| ADR-0015 | 2026-07-17 | [Registry matching eligibility is a node-level engine boundary](0015-registry-matching-eligibility-is-occurrence-level.md) |
| ADR-0020 | 2026-07-25 | [Repository configuration requires explicit trust; baselines are the one auto-discovered repository input](0020-repository-configuration-requires-explicit-trust.md) |
| ADR-0022 | 2026-07-25 | [Enrichment consolidates aliases and derives remediation](0022-vulnerability-remediation-is-derived-enrichment.md) |
| ADR-0024 | 2026-07-26 | [Detection degrades loudly through one typed warning channel](0024-one-typed-detector-warning-channel-no-ci-readiness-stage.md) |
| ADR-0026 | 2026-07-27 | [Untrusted input is bounded before decoding and parsed strictly](0026-untrusted-documents-have-input-limits.md) |
| ADR-0027 | 2026-07-28 | [Dependency detail changes are canonical diff results](0027-dependency-detail-changes-are-canonical-diff-results.md) |
| ADR-0033 | 2026-08-24 | [Occurrence facts are detector-asserted from explicit evidence, never inferred](0033-package-origin-is-detector-asserted.md) |
| ADR-0034 | 2026-08-24 | [Decisions are recorded as concise ADRs](0034-decisions-are-recorded-as-individual-adrs.md) |
| ADR-0035 | 2026-08-25 | [License emission is classified by validation, not by field](0035-license-emission-is-validated-not-assumed.md) |
| ADR-0037 | 2026-08-26 | [SBOM assertions are typed SDK model fields, not metadata keys](0037-sbom-assertions-are-typed-sdk-model-fields.md) |
| ADR-0040 | 2026-08-26 | [The SDK owns shared meaning; integrations live in their own modules; the CLI keeps orchestration](0040-the-sdk-is-the-default-home-for-behavior.md) |
| ADR-0041 | 2026-08-29 | [Identity is the canonical PURL on typed graph nodes](0041-identity-is-the-canonical-purl-on-typed-nodes.md) |
| ADR-0042 | 2026-09-05 | [An exported SBOM has one subject; a conversion restates its source; a merge links its sources](0042-a-conversion-restates-its-source-a-merge-links-its-sources.md) |
| ADR-0043 | 2026-09-06 | [A scope filter selects on assertions; absence is not one](0043-a-scope-filter-selects-on-assertions.md) |
| ADR-0044 | 2026-09-12 | [A guard must be able to fail and know its reach](0044-a-guard-must-be-able-to-fail-and-know-its-reach.md) |
| ADR-0047 | 2026-10-03 | [Release assurance is a catalog plus a per-check result contract](0047-release-assurance-is-a-catalog-and-a-result-contract.md) |
| ADR-0048 | 2026-10-19 | [OSV stays opt-in; Grype keeps its database fresh](0048-osv-stays-opt-in-and-grype-keeps-its-database-fresh.md) |

## Retired

Each file is a stub naming where the decision lives now. Cleaned up
2026-10-19; the original text is in git history before that date.

| ID | Title | Disposition |
|----|-------|-------------|
| ADR-0001 | [Reachability annotates vulnerabilities, not findings](0001-reachability-annotates-vulnerabilities-not-findings.md) | Folded into ADR-0006 |
| ADR-0002 | [Scorecard matcher reads precomputed runs, not the library](0002-scorecard-matcher-reads-precomputed-runs-not-the-library.md) | Retired: plugin-level, belongs to `bomly-plugin-scorecard-matcher` |
| ADR-0003 | [YAML configuration is nested at the file boundary](0003-yaml-configuration-is-nested-at-the-file-boundary.md) | Folded into ADR-0020 |
| ADR-0004 | [Dependency graph benchmarking is hidden and local-only](0004-dependency-graph-benchmarking-is-hidden-and-local-only.md) | Retired: tooling, see `internal/benchmark` |
| ADR-0005 | [Reachability analyzers derive local hierarchy closures](0005-reachability-analyzers-derive-local-hierarchy-closures.md) | Retired: analyzer internals, see the analyzer repositories |
| ADR-0007 | [Package locations are detector-relative today](0007-package-locations-are-detector-relative-today.md) | Retired: implementation, see `internal/engine/consolidation` |
| ADR-0008 | [Python graph resolution is lockfile-first, validated, and provenance-backed](0008-python-graph-resolution-is-lockfile-first.md) | Retired: one ecosystem, see `internal/detectors/python` |
| ADR-0009 | [Detector fallbacks are loud, annotated degradations](0009-detector-fallbacks-are-loud-annotated-degradations.md) | Folded into ADR-0024 |
| ADR-0010 | [Detector logs are request-scoped by subproject](0010-detector-logs-are-request-scoped-by-subproject.md) | Retired: logging plumbing, see `AGENTS.md` |
| ADR-0012 | [Recursive discovery prunes native multi-module roots per package manager](0012-recursive-discovery-prunes-native-multi-module-roots.md) | Folded into ADR-0013 |
| ADR-0014 | [Per-module manifest emission lives in detectors, not consolidation](0014-per-module-manifest-emission-lives-in-detectors.md) | Folded into ADR-0013, ADR-0015 and ADR-0033 |
| ADR-0016 | [Unresolved dependency parents use an explicit unknown relationship](0016-unresolved-parents-use-explicit-unknown-relationship.md) | Folded into ADR-0033 |
| ADR-0017 | [Bun text lockfiles are native; binary lockfiles degrade explicitly](0017-bun-text-lockfiles-are-native-binary-lockfiles-degrade.md) | Retired: one ecosystem, see `internal/detectors/node/bun` |
| ADR-0018 | [Enrichment consolidates alias-equivalent vulnerabilities](0018-enrichment-consolidates-alias-equivalent-vulnerabilities.md) | Folded into ADR-0022 |
| ADR-0019 | [Finding policy-status resolution belongs inside audit](0019-finding-policy-status-resolution-belongs-inside-audit.md) | Folded into ADR-0020 |
| ADR-0021 | [External lookups use `Coordinates.EcosystemName()`, never the bare `Name`](0021-external-lookups-use-coordinates-ecosystemname.md) | Folded into ADR-0041 |
| ADR-0023 | [Grype OS-package distro comes from the PURL, not pipeline plumbing](0023-grype-os-package-distro-comes-from-the-purl.md) | Retired: plugin-level, belongs to `bomly-plugin-grype-matcher` |
| ADR-0025 | [The discovery probe attributes a skip reason per candidate](0025-the-discovery-probe-attributes-a-skip-reason-per-candidate.md) | Retired: an error message, see `internal/cli/opts/planning_diagnostics.go` |
| ADR-0028 | [Startup banner frames are procedural; animation is opt-in; gating is env-var-only](0028-startup-banner-frames-are-procedural.md) | Retired: user interface, see `internal/cli/render/logo.go` |
| ADR-0029 | [Shared helper code lives in bomly-sdk subpackages, not CLI-internal packages](0029-shared-helper-code-lives-in-bomly-sdk-subpackages.md) | Folded into ADR-0040 |
| ADR-0030 | [External-integration components live in their own repositories, consumed as ordinary Go modules](0030-external-integration-components-live-in-own-repos.md) | Folded into ADR-0040 |
| ADR-0031 | [Syft-JSON SBOM ingest is removed; treated as any unsupported format](0031-syft-json-sbom-ingest-is-removed.md) | Retired: moot, the SDK codec refuses syft-json |
| ADR-0032 | [SBOM exports carry a synthesized primary component and shared document identity](0032-sbom-exports-carry-synthesized-primary-component.md) | Folded into ADR-0042 |
| ADR-0036 | [Dependency identity is content-addressable and SDK-derived](0036-dependency-identity-is-content-addressable.md) | Superseded by ADR-0041 |
| ADR-0038 | [PURL and SPDX behavior have one home in the SDK](0038-purl-and-spdx-behavior-have-one-home-in-the-sdk.md) | Folded into ADR-0040 |
| ADR-0039 | [Both modules build on Go 1.27; untrusted JSON parses strictly](0039-both-modules-build-on-go-1-27.md) | Folded into ADR-0026 |
| ADR-0045 | [The SDK owns the SBOM codec](0045-the-sdk-owns-the-sbom-codec.md) | Folded into ADR-0040 |
| ADR-0046 | [The scan output is the SDK's scan record](0046-the-scan-output-is-the-sdk-scan-record.md) | Folded into ADR-0011 and ADR-0040 |
