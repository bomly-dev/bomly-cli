# Auditors

Auditors evaluate a dependency graph against policy and produce findings. They are how a scan becomes a pass/fail signal in CI.

Auditors run **after** detectors and matchers. They never make network calls of their own — they only look at the data that detectors put on the graph and matchers attached to it. To audit fresh vulnerability data, combine `--enrich` with `--audit`:

```bash
bomly scan --enrich --audit --fail-on high
```

The CLI requires `--enrich` with `--audit`. Auditors themselves do not make
network calls; the selected matchers decide whether enrichment uses the
network.

## Built-in auditors

| Auditor | Checks | Policy flags |
| --- | --- | --- |
| [`vulnerability`](auditors/vulnerability.md) | Enriched advisories and vulnerability-check coverage loss | `--fail-on`, `--allow-vulnerability-id` |
| [`license`](auditors/license.md) | Package licenses vs. allow/deny SPDX policy | `--allow-license`, `--deny-license`, `--license-exempt-package` |
| [`package`](auditors/package.md) | Denied packages, typosquatted names, and source changes | `--deny-package`, `--deny-group`, `--protected-package`, `--typosquat-threshold`, `--typosquat-mode`, `--deny-dependency-source-change` |

Select a subset with the `--auditors` selector (e.g. `--auditors license`). See the [per-auditor reference](auditors/) for options, examples, and limitations. Auditors are also a plugin extension point — for a worked example of an external auditor, see the [Meme Dependency Auditor](https://github.com/bomly-dev/bomly-plugin-meme-auditor).

## When auditors run

- `bomly scan --audit` evaluates the full graph.
- `bomly explain --audit` evaluates the dependency-path context for a single package.
- `bomly diff --audit` classifies introduced, resolved, and persisted findings between two graphs.

## Findings

A finding is Bomly's normalized record of a policy match. Every finding has:

| Field | Meaning |
| --- | --- |
| ID | Identifier of the underlying signal (e.g. `CVE-2024-12345`, `GHSA-xxxx-yyyy-zzzz`) |
| Kind | What kind of finding (vulnerability, license, lifecycle) |
| Severity | `critical` / `high` / `medium` / `low` / `unknown` |
| Package | The package name, version, and PURL it applies to |
| Title | Human-readable summary |
| Reasons | Why the finding matched policy (e.g. severity threshold, reachable symbol) |
| Source | Which matcher produced the underlying data |

Text output (`--format text`, default) groups findings by package and severity. JSON (`--json` or `--format json`) exposes the full shape for automation. SARIF 2.1.0 (`--format sarif`) emits a static-analysis report any tool that consumes SARIF can ingest.

`--format sarif` **requires** `--audit`. A SARIF document only makes sense when there are findings.

## Severity grammar

Severity levels in precedence order, lowest to highest:

```text
unknown  <  low  <  medium  <  high  <  critical
```

The `any` token matches every severity, including `unknown`.

## `--fail-on`

`--fail-on` controls vulnerability findings by severity, reachability,
or known exploitation. It also provides the diff-only `coverage-loss`
gate. Other policy flags, such as
`--deny-package` and `--deny-dependency-source-change`, can create
failing findings directly.

It accepts these tokens:

| Token | Matches |
| --- | --- |
| `any` | every finding |
| `low` | findings with severity ≥ low |
| `medium` | findings with severity ≥ medium |
| `high` | findings with severity ≥ high |
| `critical` | findings with severity = critical |
| `reachable` | findings where reachability status is `reachable` (experimental — see [REACHABILITY.md](REACHABILITY.md)) |
| `exploitable` | vulnerability findings marked as known exploited by enrichment data |
| `coverage-loss` | diffs where vulnerability checks covered a dependency on the base side but not the head side |

Repeat advisory constraints to AND them together. `coverage-loss` is an
independent diff gate, so combining it with advisory constraints fails when
either the coverage gate or the complete advisory constraint set matches:

```bash
# Fail on any high or critical finding
bomly scan --enrich --audit --fail-on high

# Fail only when a high-or-above finding is also reachable
bomly scan --enrich --audit --analyze \
  --fail-on high --fail-on reachable

# Fail only on high-or-critical vulnerabilities with known exploitation
bomly scan --enrich --audit \
  --fail-on high --fail-on exploitable

# Fail on high-or-critical vulnerabilities or lost vulnerability coverage
bomly diff --base main --head HEAD --enrich --audit \
  --fail-on high --fail-on coverage-loss
```

Tokens are case-insensitive. An invalid token produces an exit-code 4 (invalid input) with the message:
`unsupported --fail-on value "<x>" (accepted: any, low, medium, high, critical, reachable, exploitable, coverage-loss)`.

## Minimal CI policy

Start with one explicit severity gate:

```bash
bomly scan --enrich --audit --fail-on high
```

This fails on high and critical findings while keeping lower-severity findings
visible in the report. Add license, denied-package, protected-package,
reachability, or exploitability controls only when your team has defined the
corresponding review and exception process. A larger policy is not inherently a
safer policy if nobody owns its exceptions.

## Exit codes from auditors

| Code | Trigger |
| --- | --- |
| 0 | Scan succeeded; no policy match for `--fail-on` |
| 2 | Policy violation — at least one finding matched `--fail-on` |
| 4 | Invalid `--fail-on` value |

See [EXIT_CODES.md](EXIT_CODES.md) for the full table.

## Diff and auditing

`bomly diff --audit` classifies findings between two graphs into three buckets:

- **Introduced** — present in head, absent in base
- **Resolved** — present in base, absent in head
- **Persisted** — present in both

Combine with `--fail-on` to fail PRs that introduce new high-severity findings without complaining about pre-existing ones:

```bash
bomly diff --base main --head HEAD --enrich --audit --fail-on high
```

## Configure with a YAML file

Compliance policy is usually the same across every scan, so set it once in a config file instead of repeating CLI flags. All auditor settings live under the `policy` key:

```yaml
policy:
  fail_on: [high, reachable]              # severity / reachability gates
  allow_vulnerability_ids: [GHSA-xxxx-yyyy-zzzz]
  allow_licenses: [MIT, Apache-2.0, BSD-3-Clause]
  deny_licenses: [GPL-3.0-only]
  license_exempt_packages: [my-internal-lib]
  deny_packages: [event-stream]
  deny_groups: [com.evil]
  deny_dependency_source_changes: [git, url]
  protected_packages: [react, lodash]
  typosquat_threshold: "0.90"
  typosquat_mode: warn                    # warn | fail
  warn_only: false
  baseline: auto                          # auto | none | path
```

Bomly merges configuration from these sources, in increasing precedence:

1. User-level `~/.bomly/config.yaml` — your defaults across every project.
2. `--config <path>` or `BOMLY_CONFIG` — an explicitly trusted file.
3. `BOMLY_*` environment variables.
4. CLI flags.

Repository config files are never loaded automatically. A team may commit
`.bomly/config.yaml`, but each invocation must select it explicitly with
`--config .bomly/config.yaml` or `BOMLY_CONFIG`. When both are set,
`--config` wins. Every key is listed in
[CONFIG_REFERENCE.md](CONFIG_REFERENCE.md).

## Finding baselines

A project may commit `.bomly/baseline.json` to suppress accepted package
findings without removing them from reports. Policy-status resolution is part of
auditing: auditors first emit ordinary findings, then the audit stage marks
compatible entries `suppressed`. It never removes a finding or suppresses
pipeline diagnostics. If automatic discovery finds a symbolic link at the
conventional baseline path, Bomly warns and behaves as though no baseline
exists. An explicit `--baseline <path>` remains a trusted user-selected
path. See [Finding Baselines](BASELINES.md).

## See also

- [Per-auditor reference](auditors/) — options, examples, and limitations for each built-in auditor
- [Exit codes](EXIT_CODES.md) — full table of process exit values
- [Reachability](REACHABILITY.md) — narrowing findings to symbols actually called
- [Output formats](OUTPUT_FORMATS.md) — text, JSON, SARIF rendering details
- [Matchers](MATCHERS.md) — where finding data comes from
