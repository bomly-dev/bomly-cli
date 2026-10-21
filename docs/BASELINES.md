# Finding baselines

A baseline records the findings a project has decided to live with, so an audit keeps reporting them but stops failing on them. Use one when you want to turn on a CI gate today without first fixing every existing finding. This page explains how to create and maintain a baseline, how Bomly finds it, and what it records.

## Quick start

Record today's findings, then confirm the gate passes:

```bash
bomly baseline create --enrich
bomly scan --enrich --audit --fail-on high
echo $?   # 0
```

The findings are still printed. Their policy status becomes `suppressed` instead of gating (`policy_status` in JSON). Commit `.bomly/baseline.json` so CI and teammates share the same accepted set. New findings still fail the gate.

## Commands

The baseline commands run the normal audited pipeline, so they need `--enrich`. Add `--analyze` when the CI workflow that consumes the baseline uses reachability too, so the recorded state matches.

| Command | What it does |
| --- | --- |
| `bomly baseline create --enrich` | Writes `.bomly/baseline.json` from the current findings. Refuses to overwrite an existing file |
| `bomly baseline update --enrich` | Adds new or changed findings and keeps existing entries |
| `bomly baseline prune --enrich` | Removes entries no longer found by a complete audit. Never adds findings |
| `bomly baseline inspect [--path <dir>]` | Prints the baseline a project would use |

Writes go to a temporary file first and then replace the baseline in one step. The write commands work only on a writable local project. They refuse to change the baseline when the scan reports reduced detector, matcher, analyzer, or auditor coverage, because a partial scan would record a partial truth.

## How Bomly finds the baseline

`scan`, `diff`, and `explain` look for `.bomly/baseline.json` at the project root. The `--baseline` option (config key `policy.baseline`) controls this:

| Value | Effect |
| --- | --- |
| `auto` (default) | Use `.bomly/baseline.json` when present |
| `none` | Ignore any baseline |
| A path | Require that file. A relative path is resolved from the project root |

Each side of a Git diff uses the baseline committed in its own tree, so a `bomly diff` or a Bomly Guard review applies the baseline as it existed at the base and at the head. A `--url` target uses the baseline committed in the cloned repository. A container image has no project root, so it needs an absolute baseline path. For a standalone SBOM file, discovery starts beside the file.

At `-v`, Bomly logs every baseline it found with its path, entry count, and selection mode, and the audit summary reports how many findings the baseline accepted.

## What a baseline records

Each entry identifies a finding by the full package URL (PURL, including the version), the finding kind, the auditor, and either the advisory identifiers or a stable rule ID. Entries contain no dependency node IDs, manifest paths, subproject names, or finding text. That makes a baseline portable: copied to another project, it suppresses the same finding for the same package version there. It does not carry over after the package version changes.

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

Structured findings expose `rule_id`, so a non-vulnerability entry can be written by hand without relying on finding titles. Advisory aliases are kept so equivalent identifiers match across enrichment sources.

Severity, policy status, and reachability are recorded as the state you accepted. A finding that got worse is not suppressed until `baseline update` accepts the new state. A finding that got safer stays suppressed: a finding recorded as `unknown` stays suppressed if analysis later proves it `unreachable`, but gates again if analysis reports it `reachable`.

## Output

A baseline adds no sections or collections to any report. Findings stay where they always are. JSON and MCP expose `policy_status`; text, Markdown, and the TUI show the policy status; SARIF marks the result as externally suppressed at note level; Bomly Guard keeps reading the ordinary diff output and exit code.

A malformed baseline you selected explicitly fails the command before the audit runs. An automatically discovered baseline is loaded only for audited commands, so a malformed file cannot break a plain inventory scan, and an audited command stops with an error rather than ignoring it. Bomly rejects baseline files larger than 16 MiB and documents with more than 10,000 entries. If `.bomly` or `baseline.json` is a symbolic link, automatic discovery warns and behaves as if there were no baseline; an explicit `--baseline <path>` may point anywhere. [Security and trust boundaries](SECURITY.md) has the detail.

## See also

- [Auditors](AUDITORS.md) — how policy status is decided
- [Bomly Guard](BOMLY_GUARD.md) — baselines in pull request reviews
- [diff command](commands/diff.md) — which findings a diff audits
