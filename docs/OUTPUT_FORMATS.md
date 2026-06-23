# Output Formats

Bomly writes one primary stdout output and any number of additional outputs in the same run.

## Primary output: `--format`

Use `--json` as a shortcut for `--format json` when you want structured output quickly.

| Format | Default for | When to use |
| --- | --- | --- |
| `text` | Local runs, `--interactive` | Reading on a terminal |
| `json` | Automation | Pipelines, custom dashboards, anything consumed by code |
| `markdown` | Reviews | Job summaries, PR comments, and other Markdown surfaces |
| `sarif` | Audit-only | CI security panes, GitHub Security tab, IDE problem markers |
| `spdx` | Scan only | SPDX 2.3 JSON SBOMs |
| `cyclonedx` | Scan only | CycloneDX 1.6 JSON SBOMs |

Flag:

```bash
bomly scan --format text     # default
bomly scan --json
bomly explain lodash --format markdown
bomly diff --base main --head HEAD --format markdown
bomly scan --audit --format sarif
bomly scan --format spdx
```

Constraints:

- `--format sarif` requires `--audit`. SARIF is a findings format; without an auditor there are no findings.
- `--format spdx` and `--format cyclonedx` are supported by `scan` only.
- `--interactive` forces `--format text`. Combining it with `--json` or another non-text reporting format is rejected with exit 4.

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

`bomly scan` surfaces the three-collection model (see [Architecture → Domain model](ARCHITECTURE.md#domain-model)):
`manifests[].dependencies` are lean detection-stage nodes (identity, `scopes`,
`depends_on`, `package_ref`); `packages` is the deduplicated matching-stage
registry (licenses, vulnerabilities, scorecard, EOL, CPEs, digests) keyed by
PURL; and `findings` is the reference-style audit output. Resolve a finding or a
dependency to its enrichment by matching `package_ref`/`package.purl` into
`packages`.

Pipe into `jq` for common queries:

```bash
# Every package with a high-or-critical vulnerability
bomly scan --enrich --json | jq '
  .packages[]
  | select(.vulnerabilities[]? | .severity == "high" or .severity == "critical")
  | {name, version, ecosystem}
'

# All transitive paths to a specific dependency
bomly explain lodash --json | jq '.paths[] | .nodes | map(.name) | join(" -> ")'

# New findings introduced by a PR
bomly diff --base main --head HEAD --enrich --audit --json | jq '.findings.introduced[]'
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

## Additional output: `-o`

`-o` uses the same format names as `--format`, plus an optional file path. Use `<format>=<path>` to write to a file, or just `<format>` to write that additional output to stdout.

```bash
bomly scan --json \
  -o text=summary.txt \
  -o markdown=summary.md \
  -o sarif=bomly.sarif \
  -o spdx=sbom.spdx.json \
  -o cyclonedx=sbom.cdx.json
```

Supported targets:

| `-o` value | Format |
| --- | --- |
| `text` | Human-readable terminal report |
| `json` | Structured Bomly JSON report |
| `markdown` | GitHub-flavored Markdown report |
| `sarif` | SARIF 2.1.0 report; requires `--audit` |
| `spdx` | SPDX 2.3 JSON |
| `cyclonedx` | CycloneDX 1.6 JSON |

`spdx` and `cyclonedx` are supported by `scan`. Report formats (`text`, `json`, `markdown`, `sarif`) are supported by report-producing commands. See [SBOM formats](SBOM.md) for the SBOM comparison and writing rules.

## Combining outputs

A single scan can produce:

- A human report on stdout.
- A JSON document piped to a file.
- A SARIF document for a CI panel.
- One or more SBOM artifacts.

Example:

```bash
bomly scan --enrich --audit --fail-on high \
  --json \
  -o markdown=summary.md \
  -o sarif=bomly.sarif \
  -o spdx=sbom.spdx.json \
  -o cyclonedx=sbom.cdx.json \
  > bomly.json
```

Detector and matcher work runs once. All outputs derive from the same in-memory graph.

## See also

- [Scan schema](schemas/scan.md) — full JSON shape
- [Explain schema](schemas/explain.md)
- [Diff schema](schemas/diff.md)
- [SBOM formats](SBOM.md) — SPDX vs. CycloneDX
- [Exit codes](EXIT_CODES.md) — how the formats interact with the process exit code
