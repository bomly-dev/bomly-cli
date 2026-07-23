# Finding Baselines

Finding baselines let a project keep known package findings visible without
letting those findings fail an audit. Bomly automatically looks for
`.bomly/baseline.json` when `scan`, `diff`, or `explain` runs against a project.
A matching finding is still emitted with the same package, advisory, severity,
and reasons, but its existing `disposition` field is set to `suppressed`.

## Create and maintain a baseline

Baseline creation runs the normal audited project pipeline and therefore
requires explicit enrichment:

```bash
bomly baseline create --enrich
bomly baseline inspect
```

Creation refuses to overwrite an existing file. `baseline update --enrich`
accepts current new or changed findings while retaining historical entries.
`baseline prune --enrich` removes accepted entries absent from a complete
current audit and never accepts new findings. All writes use a temporary file
and atomic replacement. Lifecycle commands are limited to writable local
filesystem projects and refuse to mutate a baseline when the scan reports
degraded detector, matcher, analyzer, or auditor coverage.

## Selection

The shared `--baseline` option accepts:

- `auto` (default): use `.bomly/baseline.json` when present;
- `none`: disable baseline consumption;
- a relative or absolute path: require that baseline file.

A relative path is resolved from the project root. During a Git diff it is
resolved independently in the materialized base and head trees, so each side
uses the baseline committed with that project state. The merge base selected by
Bomly Guard is simply the diff's base tree.

Container targets have no reliable project root, so they require an absolute
baseline path. For a standalone SBOM file, automatic discovery starts beside
the file; an explicit path is recommended when the baseline lives elsewhere.

```yaml
policy:
  baseline: auto
```

## Identity and portability

Entries identify the full package PURL (including version), finding kind,
auditor, and either advisory identifiers or a stable policy rule. They do not
contain dependency node IDs, manifest paths, subproject names, project names,
or mutable finding prose.

A baseline can therefore be copied to another project and suppresses the same
finding for the same package version there. It does not automatically suppress
the finding after a package version changes. Advisory aliases are retained so
equivalent identifiers can match across enrichment sources.

Severity, failing disposition, and reachability state are recorded as safety
bounds. An escalation remains unsuppressed until `baseline update` explicitly
accepts it.

## Output and automation

Baselines do not add report sections or collections. Findings remain in their
normal scan, explain, and diff locations. JSON and MCP use the existing
`disposition` field; text and Markdown keep their finding tables; SARIF keeps
the result at a non-gating note level; and Bomly Guard continues consuming the
ordinary diff output and exit status.

Baseline failures do not hide pipeline diagnostics. A malformed explicitly
selected file fails before the audit runs.
