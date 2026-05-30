# Auditors

Auditors evaluate a dependency graph against policy and produce findings. They are how a scan becomes a pass/fail signal in CI.

Auditors run **after** detectors and matchers. They never make network calls of their own — they only look at the data that detectors put on the graph and matchers attached to it. To audit fresh vulnerability data, combine `--enrich` with `--audit`:

```bash
bomly scan --enrich --audit --fail-on high
```

`--audit` alone is useful when you have ingested an SBOM that already carries vulnerability data, or when a matcher ran in a previous step.

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
bomly scan --enrich --audit --reachability \
  --fail-on high --fail-on reachable
```

Tokens are case-insensitive. An invalid token produces an exit-code 4 (invalid input) with the message:
`unsupported --fail-on value "<x>" (accepted: any, low, medium, high, critical, reachable)`.

## `--fail-on-scope`

Use `--fail-on-scope` to restrict which dependency scopes feed into `--fail-on`:

| Scope | Meaning |
| --- | --- |
| `runtime` | Required at runtime (e.g. `dependencies` in npm, non-test scope in Maven) |
| `development` | Build- and test-only (e.g. `devDependencies` in npm, `test` scope in Maven) |
| `unknown` | Detector could not classify the edge |

Without `--fail-on-scope` all scopes count. Common pattern: gate CI on runtime only.

```bash
bomly scan --enrich --audit --fail-on high --fail-on-scope runtime
```

## Exit codes from auditors

| Code | Trigger |
| --- | --- |
| 0 | Scan succeeded; no policy match for `--fail-on` |
| 2 | Policy violation — at least one finding matched `--fail-on` |
| 4 | Invalid `--fail-on` or `--fail-on-scope` value |

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

## See also

- [Exit codes](EXIT_CODES.md) — full table of process exit values
- [Reachability](REACHABILITY.md) — narrowing findings to symbols actually called
- [Output formats](OUTPUT_FORMATS.md) — text, JSON, SARIF rendering details
- [Matchers](MATCHERS.md) — where finding data comes from
