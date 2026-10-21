# ADR-0027: Dependency detail changes are canonical diff results

- **Date:** 2026-07-28
- **Revised:** 2026-10-19
- **Status:** Accepted

## Context

A dependency can change without changing version: direct to transitive,
registry to Git, eligible to ineligible for matching. Reporting those as
additions and removals misstates what happened; ignoring them hides a
provenance change a reviewer should see.

## Decision

`sdk.Compare` classifies version changes and detail changes as parallel
results; one occurrence may appear in both. Each transition keeps before and
after evidence and the ordered list of changed fields. Explicit detector
relationships win; for graphs that omit one, the classifier derives direct
or transitive from edges and reports `unknown` when it cannot. Output code
projects that result and never repeats the policy.

The SDK also labels the transitions that deserve review: a source moving to
Git or a URL, and a loss of vulnerability-check coverage. The label styles
text, Markdown and TUI output and has no effect on exit status.

When diff auditing is enabled, the head-side audit receives a copy of the
transitions. The package auditor turns source moves into warnings; the
vulnerability auditor turns coverage loss into warning-severity findings
under the existing `--fail-on` rules. Auditors infer nothing from the audit
graphs, and no stage is added. Diff package enrichment uses the head-side
registry.

## Rejected

Folding detail changes into add and remove; a per-renderer heuristic.

## Consequences

- Manifest-level results preserve duplicate occurrences; the global JSON and
  MCP views deduplicate identical evidence and bound MCP output.

Enforced by: `TestRun_PassesCanonicalDetailChangesOnlyToHeadAudit` in
`internal/engine/diff`; `TestBuildDiffResponseReportsDependencyDetailTransitions`
and `TestProjectedDependencyDetailReviewReasonsMatchCanonicalTransition` in
`internal/output`; the `Compare` tests in the SDK.
