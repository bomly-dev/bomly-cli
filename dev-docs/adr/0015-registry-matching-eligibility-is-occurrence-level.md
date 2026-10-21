# ADR-0015: Registry matching eligibility is a node-level engine boundary

- **Date:** 2026-07-17
- **Revised:** 2026-10-19 (folds the first-party rule of ADR-0014; narrowed to the node by ADR-0041)
- **Status:** Accepted

## Context

Detection keeps everything it sees: the project's own modules, workspace
links, path and git sources, published releases. Public advisory and
registry sources know only published releases. Querying them for a
workspace member that happens to share a name with a real npm package would
adopt that package's advisories.

## Decision

Immediately before matchers run, the engine hands every matcher the same
filtered clone: the registry-match-eligible dependency nodes and the edges
between them. Module and manifest nodes are never matched. Published
registry releases are eligible, including through mirrors; project,
workspace or link, file, git and arbitrary-URL occurrences are not. An
omitted or plugin-defined source stays eligible for wire compatibility.
Application type alone is not an ownership signal: an imported SBOM's
application component remains matchable unless its source says otherwise.
Relationship `unknown` does not affect eligibility.

Nodes fold by canonical PURL (ADR-0041), so eligibility is decided per node:
a folded node is eligible when any folded witness was, because withholding
enrichment from a PURL that a registry release uses would hide
vulnerabilities.

The full registry stays shared so enrichment is deduplicated by PURL.
Analysis and audit receive the complete graph. Targeted matching of an
ineligible occurrence short-circuits rather than widening to other packages.

## Rejected

Letting each matcher decide (built-in and external matchers would disagree).
Filtering the SBOM handed to external Grype: that document is also the
user's SBOM, where first-party components must stay visible, so first-party
matches are dropped on the way back instead.

## Consequences

- First-party packages stay in `packages[]` and SBOMs, unenriched.
- External matcher plugins inherit the rule without implementing it.

Enforced by: `internal/engine/match_eligibility_test.go`.
