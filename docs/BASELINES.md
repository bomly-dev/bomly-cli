# Finding Baselines

Finding baselines let a project keep known package findings visible without
letting those findings fail an audit. Bomly automatically looks for
`.bomly/baseline.json` when `scan`, `diff`, or `explain` runs against a project.
A matching finding is still emitted with the same package, advisory, severity,
and reasons, but its policy status becomes `suppressed`. For compatibility,
machine-readable output continues to call this field `disposition`.

## Create and maintain a baseline

Baseline creation runs the normal audited project pipeline and therefore
requires explicit enrichment:

```bash
bomly baseline create --enrich
bomly baseline inspect
bomly baseline inspect --path ../another-project
```

Creation refuses to overwrite an existing file. `baseline update --enrich`
accepts current new or changed findings while retaining historical entries.
`baseline prune --enrich` removes accepted entries absent from a complete
current audit and never accepts new findings. All writes use a temporary file
and atomic replacement. Lifecycle commands are limited to writable local
filesystem projects and refuse to mutate a baseline when the scan reports
degraded detector, matcher, analyzer, or auditor coverage.
Use `--analyze` for lifecycle commands when the audited CI workflow also uses
reachability analysis. The baseline records that policy state as a safety bound.

## Selection

The shared `--baseline` option accepts:

- `auto` (default): use `.bomly/baseline.json` when present;
- `none`: disable baseline consumption;
- a relative or absolute path: require that baseline file.

A relative path is resolved from the project root. During a Git diff it is
resolved independently in the materialized base and head trees, so each side
uses the baseline committed with that project state. The merge base selected by
Bomly Guard is simply the diff's base tree.

Automatic discovery is disabled for `--url` targets because the downloaded
repository is not a trusted policy source. Use an explicit absolute baseline
path to apply your own policy, or `--baseline none` to make that intent clear.
At `-v`, Bomly logs the baseline path and entry count when a policy is loaded.

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

```json
{
  "schema_version": "bomly.finding-baseline/v1",
  "entries": [
    {
      "package_ref": "pkg:npm/example@1.0.0",
      "kind": "package",
      "auditor": "package",
      "rule_id": "denied-package",
      "severity": "high",
      "policy_status": "fail"
    }
  ]
}
```

Structured findings expose `rule_id`, so a non-vulnerability entry can be
reviewed or authored without relying on mutable finding titles.

Severity, failing policy status, and reachability state are recorded as safety
bounds. An escalation remains unsuppressed until `baseline update` explicitly
accepts it. A safer reachability result remains accepted: for example, a
finding recorded as `unknown` stays suppressed if analysis later proves it
`unreachable`, but becomes gating if analysis reports it `reachable`.

## Output and automation

Baselines do not add report sections or collections. Findings remain in their
normal scan, explain, and diff locations. JSON and MCP retain the existing
`disposition` machine field; text, Markdown, and the TUI call it the policy
status; SARIF marks the result as externally suppressed at note level; and
Bomly Guard continues consuming the ordinary diff output and exit status.

Baseline failures do not hide pipeline diagnostics. A malformed explicitly
selected file fails before the audit runs. An automatically discovered baseline
is loaded only for audited commands, so a malformed file cannot break a plain
inventory scan; audited commands fail closed rather than silently ignoring it.
