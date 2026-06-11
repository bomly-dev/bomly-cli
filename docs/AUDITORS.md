# Auditors

Auditors evaluate a dependency graph against policy and produce findings. They are how a scan becomes a pass/fail signal in CI.

Auditors run **after** detectors and matchers. They never make network calls of their own — they only look at the data that detectors put on the graph and matchers attached to it. To audit fresh vulnerability data, combine `--enrich` with `--audit`:

```bash
bomly scan --enrich --audit --fail-on high
```

`--audit` alone is useful when you have ingested an SBOM that already carries vulnerability data, or when a matcher ran in a previous step.

## Built-in auditors

| Auditor | Checks | Policy flags |
| --- | --- | --- |
| [`vulnerability`](auditors/vulnerability.md) | Enriched advisories vs. severity / allowlist policy | `--fail-on`, `--allow-vulnerability-id` |
| [`license`](auditors/license.md) | Package licenses vs. allow/deny SPDX policy | `--allow-license`, `--deny-license`, `--license-exempt-package` |
| [`package`](auditors/package.md) | Denied packages and typosquatted names | `--deny-package`, `--deny-group`, `--protected-package`, `--typosquat-threshold`, `--typosquat-mode` |

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

`--fail-on` is the only knob that turns a finding into a non-zero exit code. It accepts one of the severity tokens, or the reachability token `reachable`:

| Token | Matches |
| --- | --- |
| `any` | every finding |
| `low` | findings with severity ≥ low |
| `medium` | findings with severity ≥ medium |
| `high` | findings with severity ≥ high |
| `critical` | findings with severity = critical |
| `reachable` | findings where reachability status is `reachable` (experimental — see [REACHABILITY.md](REACHABILITY.md)) |

Repeat the flag to AND constraints together:

```bash
# Fail on any high or critical finding
bomly scan --enrich --audit --fail-on high

# Fail only when a high-or-above finding is also reachable
bomly scan --enrich --audit --analyze \
  --fail-on high --fail-on reachable
```

Tokens are case-insensitive. An invalid token produces an exit-code 4 (invalid input) with the message:
`unsupported --fail-on value "<x>" (accepted: any, low, medium, high, critical, reachable)`.

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
  protected_packages: [react, lodash]
  typosquat_threshold: "0.90"
  typosquat_mode: warn                    # warn | fail
  warn_only: false
```

Bomly merges configuration from these sources, in increasing precedence:

1. User-level `~/.bomly/config.yaml` — your defaults across every project.
2. Repo-level `<project>/.bomly/config.yaml` — committed policy shared by the team (the usual home for a compliance policy).
3. `--config <path>` — an explicit file.
4. `BOMLY_*` environment variables.
5. CLI flags.

So a checked-in `.bomly/config.yaml` defines the team policy, and a CLI flag still overrides it for a one-off run. Every key is listed in [CONFIG_REFERENCE.md](CONFIG_REFERENCE.md).

## See also

- [Per-auditor reference](auditors/) — options, examples, and limitations for each built-in auditor
- [Exit codes](EXIT_CODES.md) — full table of process exit values
- [Reachability](REACHABILITY.md) — narrowing findings to symbols actually called
- [Output formats](OUTPUT_FORMATS.md) — text, JSON, SARIF rendering details
- [Matchers](MATCHERS.md) — where finding data comes from
