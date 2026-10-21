# Auditors

Auditors evaluate a dependency graph against policy and produce findings. They are how a scan becomes a pass or fail signal in CI.

Auditors run **after** detectors and matchers, and they never make network calls of their own. They only read what detectors put on the graph and what matchers attached to it. The `--audit` flag requires `--enrich` on the command line. The vulnerability auditor needs the vulnerability records that enrichment attaches. The license and package auditors work on data detectors already provide, so for them enrichment only adds coverage.

```bash
bomly scan --enrich --audit --fail-on high
```

## Built-in auditors

| Auditor | Checks | Policy flags |
| --- | --- | --- |
| [`vulnerability`](auditors/vulnerability.md) | Enriched vulnerability advisories | `--fail-on`, `--allow-vulnerability-id` |
| [`license`](auditors/license.md) | Package licenses vs. allow/deny SPDX policy | `--allow-license`, `--deny-license`, `--license-exempt-package` |
| [`package`](auditors/package.md) | Denied packages, typosquatted names, and source changes | `--deny-package`, `--deny-group`, `--protected-package`, `--typosquat-threshold`, `--typosquat-mode`, `--fail-on source-change` |

Select a subset with the `--auditors` [selector](COMMANDS.md#selector-grammar), for example `--auditors license`. See the [per-auditor reference](auditors/) for options, examples, and limitations. Auditors are also a plugin extension point. The [Meme Dependency Auditor](https://github.com/bomly-dev/bomly-plugin-meme-auditor) is a worked example of an external auditor.

## When auditors run

- `bomly scan --audit` evaluates the full graph.
- `bomly explain --audit` evaluates the dependency-path context for a single package.
- `bomly diff --audit` classifies introduced, resolved, and persisted findings between two graphs.

## Findings

A finding is Bomly's normalized record of a policy match. Every finding has:

| Field | Meaning |
| --- | --- |
| ID | Identifier of the underlying signal (for example `CVE-2024-12345` or `GHSA-xxxx-yyyy-zzzz`) |
| Kind | What kind of finding (vulnerability, license, lifecycle) |
| Severity | `critical` / `high` / `medium` / `low` / `unknown` |
| Package | The package name, version, and PURL it applies to |
| Title | Human-readable summary |
| Reasons | Why the finding matched policy (for example a severity threshold or a reachable symbol) |
| Source | Which matcher produced the underlying data |

Text output (`--format text`, the default) groups findings by package and severity. JSON (`--json` or `--format json`) exposes the full shape for automation. SARIF 2.1.0 (`--format sarif`) emits a static-analysis report that any SARIF consumer can read.

`--format sarif` **requires** `--audit`. A SARIF document only makes sense when there are findings.

## Severity grammar

Severity levels in order, lowest to highest:

```text
unknown  <  low  <  medium  <  high  <  critical
```

The `any` token matches every severity, including `unknown`.

## `--fail-on`

`--fail-on` gates vulnerability findings by severity, reachability, or known exploitation. It also provides the diff-only `source-change` gate for package findings. Other policy flags, such as `--deny-package`, create failing findings directly.

It accepts these tokens:

| Token | Matches |
| --- | --- |
| `any` | every finding |
| `low` | findings with severity ≥ low |
| `medium` | findings with severity ≥ medium |
| `high` | findings with severity ≥ high |
| `critical` | findings with severity = critical |
| `reachable` | findings where reachability status is `reachable` (experimental, see [REACHABILITY.md](REACHABILITY.md)) |
| `exploitable` | vulnerability findings marked as known exploited by enrichment data |
| `source-change` | diffs where a dependency changes from a known source to Git or an arbitrary URL |

Repeat vulnerability constraints to combine them with AND. `source-change` is an independent package gate. Combined with vulnerability constraints, the run fails when either the source gate matches or the complete vulnerability constraint set matches. Used by itself, `source-change` leaves vulnerability findings unchanged. It only matches dependency transitions from `bomly diff` and has no effect on `scan` or `explain`.

The examples below show each combination:

```bash
# Fail on any high or critical finding
bomly scan --enrich --audit --fail-on high

# Fail only when a high-or-above finding is also reachable
bomly scan --enrich --audit --analyze \
  --fail-on high --fail-on reachable

# Fail only on high-or-critical vulnerabilities with known exploitation
bomly scan --enrich --audit \
  --fail-on high --fail-on exploitable

# Fail on high-or-critical vulnerabilities or dependency source changes
bomly diff --base main --head HEAD --enrich --audit \
  --fail-on high --fail-on source-change
```

Tokens are case-insensitive. An invalid token exits with code 4 (invalid input) and this message:

```text
unsupported --fail-on value "<x>" (accepted: any, low, medium, high, critical, reachable, exploitable, source-change)
```

## Minimal CI policy

Start with one explicit severity gate:

```bash
bomly scan --enrich --audit --fail-on high
```

This fails on high and critical findings while keeping lower-severity findings visible in the report. Add license, denied-package, protected-package, reachability, or exploitability controls only when your team has defined the matching review and exception process. A larger policy is not a safer policy if nobody owns its exceptions.

## Exit codes from auditors

| Code | Trigger |
| --- | --- |
| 0 | Scan succeeded; no policy match for `--fail-on` |
| 2 | Policy violation: at least one finding matched `--fail-on` |
| 4 | Invalid `--fail-on` value |

See [EXIT_CODES.md](EXIT_CODES.md) for the full table.

## Diff and auditing

`bomly diff --audit` sorts findings between two graphs into three buckets:

- **Introduced**: present in head, absent in base.
- **Resolved**: present in base, absent in head.
- **Persisted**: present in both.

The diff audit only inspects packages the change touched, so findings on unchanged packages never appear. That is how pre-existing debt stays out of pull request reviews. `--fail-on` fails on introduced findings and on persisted ones. A persisted finding means the changed package still ships a known issue at its new version:

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
  protected_packages: [react, lodash]
  typosquat_threshold: "0.90"
  typosquat_mode: warn                    # warn | fail
  warn_only: false
  baseline: auto                          # auto | none | path
```

Bomly merges configuration from these sources, in increasing precedence:

1. User-level `~/.bomly/config.yaml`: your defaults across every project.
2. `--config <path>` or `BOMLY_CONFIG`: an explicitly trusted file.
3. `BOMLY_*` environment variables.
4. CLI flags.

Repository config files are never loaded automatically. A team may commit `.bomly/config.yaml`, but each invocation must select it explicitly with `--config .bomly/config.yaml` or `BOMLY_CONFIG`. When both are set, `--config` wins. Every key is listed in [CONFIG_REFERENCE.md](CONFIG_REFERENCE.md).

## Finding baselines

A project may commit `.bomly/baseline.json` to suppress accepted package findings without removing them from reports. Policy-status resolution is part of auditing. Auditors first emit ordinary findings, then the audit stage marks matching entries `suppressed`. It never removes a finding or suppresses pipeline diagnostics. If automatic discovery finds a symbolic link at the conventional baseline path, Bomly warns and behaves as though no baseline exists. An explicit `--baseline <path>` is a trusted path you chose. See [Finding baselines](BASELINES.md).

## See also

- [Per-auditor reference](auditors/): options, examples, and limitations for each built-in auditor
- [Exit codes](EXIT_CODES.md): full table of process exit values
- [Reachability](REACHABILITY.md): narrowing findings to symbols actually called
- [Output formats](OUTPUT_FORMATS.md): text, JSON, SARIF rendering details
- [Matchers](MATCHERS.md): where finding data comes from
