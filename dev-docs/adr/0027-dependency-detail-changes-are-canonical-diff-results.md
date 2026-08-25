# ADR-0027: Dependency detail changes are canonical diff results

- **Date:** 2026-07-28
- **Status:** Accepted

`sdk.Compare` classifies package version changes separately from changes to an
occurrence's dependency relationship, source, or registry-matching
eligibility. The same occurrence may appear in both lists when both kinds of
change happened. Keeping these as parallel results avoids treating a move from
direct to transitive, registry to Git, or eligible to ineligible as a package
addition or removal.

Each transition keeps before and after evidence and an ordered list of changed
fields. Explicit detector relationships win. For older protocol-v1 graphs that
omit the relationship, the classifier derives direct or transitive from graph
edges and uses unknown when the graph cannot prove either. Exact and trusted
fuzzy identity matches call the same SDK classifier. Output code only projects
that result; it does not repeat the policy.

Manifest results preserve duplicate occurrences. The global JSON and MCP
views deduplicate only identical evidence and use stable ordering and bounded
MCP truncation. Diff package enrichment still uses the head-side registry, so
reporting a detail change does not replace current vulnerability or
remediation data.

The SDK also classifies the small set of transitions that need extra review:
a source moving to Git or a URL, and a loss of vulnerability-check coverage.
Text, Markdown, and TUI use this classifier for styling and plain-language
reasons. The structured transition remains unchanged; the review label is a
presentation aid and has no effect on exit status.

When diff auditing is enabled, `internal/engine/diff` passes a deep copy of the
canonical transitions only to the head-side audit request. The existing
package auditor turns Git and URL source moves into warnings and may enforce
configured source types. The existing vulnerability auditor turns covered to
not-covered transitions into warning-severity coverage findings and applies
the existing severity `--fail-on` constraints. Auditors do not infer these
changes from the focused audit graphs, and no new pipeline stage is introduced.
