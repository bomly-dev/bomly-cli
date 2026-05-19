# Output Formats

Bomly writes one of four reporting formats and any number of SBOM artifacts in the same run.

## Reporting format: `--format`

| Format | Default for | When to use |
| --- | --- | --- |
| `text` | Local runs, `--interactive` | Reading on a terminal |
| `json` | Automation | Pipelines, custom dashboards, anything consumed by code |
| `markdown` | Reviews | Job summaries, PR comments, and other Markdown surfaces |
| `sarif` | Audit-only | CI security panes, GitHub Security tab, IDE problem markers |

Flag:

```bash
bomly scan --format text     # default
bomly scan --format json
bomly explain lodash --format markdown
bomly diff --base main --head HEAD --format markdown
bomly scan --audit --format sarif
```

Constraints:

- `--format sarif` requires `--audit`. SARIF is a findings format; without an auditor there are no findings.
- `--interactive` forces `--format text`. Passing both is rejected with exit 4.

## `text` — human-readable

The default. Groups packages by ecosystem and edge depth, summarizes finding counts by severity, and links to the explain path for any flagged package. Color and box-drawing are auto-disabled when stdout is not a TTY.

```bash
bomly scan --enrich --audit
```

## `json` — structured

The shape every Bomly subcommand emits. Each command has its own schema:

| Command | Schema |
| --- | --- |
| `bomly scan` | [scan.md](schemas/scan.md) |
| `bomly explain` | [explain.md](schemas/explain.md) |
| `bomly diff` | [diff.md](schemas/diff.md) |

Pipe into `jq` for common queries:

```bash
# Every package with a high-or-critical vulnerability
bomly scan --enrich --format json | jq '
  .packages[]
  | select(.vulnerabilities[]? | .severity == "high" or .severity == "critical")
  | {name, version, ecosystem}
'

# All transitive paths to a specific dependency
bomly explain lodash --format json | jq '.paths[] | .nodes | map(.name) | join(" -> ")'

# New findings introduced by a PR
bomly diff --base main --head HEAD --enrich --audit --format json | jq '.findings.introduced[]'
```

JSON output includes Bomly-specific metadata that standard SBOM formats don't carry: reachability tier/status/confidence, audit reasons, and per-finding source.

## `sarif` — CI security tools

SARIF 2.1.0. Findings only. One result per (rule × package) pair. Includes:

- Finding ID as the rule ID (CVE / GHSA / OSV identifier).
- Severity mapped to SARIF `level` (`error` for critical/high, `warning` for medium, `note` for low/unknown).
- Locations populated with manifest file paths when known.
- Bomly-specific reachability and policy metadata in the `properties` bag.

```bash
bomly scan --enrich --audit --fail-on high --format sarif > bomly.sarif
```

GitHub Code Scanning, Azure DevOps, and most IDE extensions ingest SARIF directly. See [CI integration](CI_INTEGRATION.md) for upload recipes.

## SBOM output: `-o`

Independent of `--format`. You can write any number of SBOM artifacts alongside the reporting output:

```bash
bomly scan --format json \
  -o spdx=sbom.spdx.json \
  -o cyclonedx=sbom.cdx.json
```

Supported targets:

| `-o` value | Format |
| --- | --- |
| `spdx` | SPDX 2.3 JSON |
| `cyclonedx` | CycloneDX 1.6 JSON |

See [SBOM formats](SBOM.md) for the comparison and writing rules.

## Combining outputs

A single scan can produce:

- A human report on stdout.
- A JSON document piped to a file.
- A SARIF document for a CI panel.
- One or more SBOM artifacts.

Example:

```bash
bomly scan --enrich --audit --fail-on high \
  --format sarif \
  -o spdx=sbom.spdx.json \
  -o cyclonedx=sbom.cdx.json \
  > bomly.sarif
```

Detector and matcher work runs once. All outputs derive from the same in-memory graph.

## See also

- [Scan schema](schemas/scan.md) — full JSON shape
- [Explain schema](schemas/explain.md)
- [Diff schema](schemas/diff.md)
- [SBOM formats](SBOM.md) — SPDX vs. CycloneDX
- [Exit codes](EXIT_CODES.md) — how the formats interact with the process exit code
