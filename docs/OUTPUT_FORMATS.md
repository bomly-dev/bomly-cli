# Output formats

This page explains the formats Bomly can write and how to produce more than one in a single run. Read it when you need output for a script, a CI security panel, or an SBOM pipeline. The field-by-field JSON documentation is on [JSON schemas](SCHEMAS.md).

## Choose a format

Every command writes one primary output to stdout, chosen with `--format`. `--json` is a shortcut for `--format json`.

| Format | What it is | Use it for | Available on |
| --- | --- | --- | --- |
| `text` | The human-readable report (default) | Reading on a terminal | `scan`, `explain`, `diff` |
| `json` | The structured document | Scripts, dashboards, anything read by code | `scan`, `explain`, `diff` |
| `markdown` | A GitHub-flavored Markdown report | Job summaries and PR comments | `scan`, `explain`, `diff` |
| `sarif` | SARIF 2.1.0, findings only | GitHub code scanning, Azure DevOps, IDE problem markers. Requires `--audit` | `scan`, `diff` |
| `spdx` | An SPDX 2.3 JSON SBOM | Compliance and supply-chain exchange | `scan` |
| `cyclonedx` | A CycloneDX 1.7 JSON SBOM | Vulnerability-management tools | `scan` |

```bash
bomly scan --json
bomly explain lodash --format markdown
bomly diff --base main --head HEAD --format markdown
bomly scan --enrich --audit --format sarif
bomly scan --format spdx
```

Two combinations are rejected with exit 4: `--format sarif` without `--audit` (SARIF carries findings, and without an auditor there are none), and `--interactive` with any format other than `text`.

## Write more than one output: `-o`

`-o <format>=<path>` writes an additional output to a file. `-o <format>` without a path writes it to stdout, so at most one `-o` may omit the path. `-o` is repeatable, and every output comes from the same scan, so detectors and matchers run once.

```bash
bomly scan --enrich --audit --fail-on high \
  --format text \
  -o json=bomly.json \
  -o sarif=bomly.sarif \
  -o spdx=sbom.spdx.json \
  -o cyclonedx=sbom.cdx.json
```

When every `-o` names a file and you set no `--format`, a successful run writes the files and prints nothing. Add `--format text` (or any other format) when you also want stdout output. Paths are relative to the current directory. `sarif` still requires `--audit`, and the SBOM formats are still `scan` only.

## `text`

The default report groups packages by ecosystem, lists direct dependencies first, counts findings by severity, and names the fix for each flagged package. With `--enrich` it adds a one-line fix summary that counts only concrete fix suggestions; packages that need manual review or have no fix do not count. Color and box-drawing characters are turned off when stdout is not a terminal.

```bash
bomly scan --enrich --audit
```

```text
✓ 68 packages in 1 manifest   (1 direct, 67 transitive · runtime 68, dev 0)

✓ Enriched via Grype, deps.dev License Matcher

✓ 7 fix suggestions for 7 of 7 vulnerable packages.
  Run again with --format json to see remediation details.

Top-level dependencies
  NAME      VERSION   LICENSE   SCOPE     VULNS
  express   4.19.2    MIT       runtime   1L

Findings
  [HIGH]      GHSA-37ch-88jc-xwx2  path-to-regexp@0.1.7
  [HIGH]      GHSA-9wv6-86v2-598j  path-to-regexp@0.1.7
  [HIGH]      GHSA-qwcr-r2fm-qrc7  body-parser@1.20.2
  [HIGH]      GHSA-rhx6-c78j-4q9w  path-to-regexp@0.1.7
```

The Markdown report has the same content plus the complete fix-suggestion table.

## `json`

Each command has its own document and schema: [scan](schemas/scan.md), [explain](schemas/explain.md), and [diff](schemas/diff.md). [JSON schemas](SCHEMAS.md) explains the shared shape: the dependency graph per manifest, one deduplicated `packages` list with the enrichment data, and `findings` that point back to packages by package URL (PURL). JSON also carries data the SBOM formats cannot hold, such as reachability status and confidence, audit reasons, and the source of each finding.

Common `jq` queries:

```bash
# Every package with a high or critical vulnerability
bomly scan --enrich --json | jq '
  .packages[]
  | select(.vulnerabilities[]? | .parsed_severity == "high" or .parsed_severity == "critical")
  | {name, version, ecosystem}
'

# Every path to one dependency
bomly explain lodash --json | jq '.paths[] | .nodes | map(.name) | join(" -> ")'

# New findings introduced by a PR
bomly diff --base main --head HEAD --enrich --audit --json | jq '.findings.introduced[]'
```

The first query on a project that pins `express@4.19.2` starts like this:

```json
{
  "name": "body-parser",
  "version": "1.20.2",
  "ecosystem": "npm"
}
{
  "name": "path-to-regexp",
  "version": "0.1.7",
  "ecosystem": "npm"
}
```

`bomly explain` returns every path from a root to the target, not only the shortest, in a stable order, and marks cyclic paths. `bomly diff` classifies each finding as introduced, resolved, or persisted by its advisory and package identity, so a version bump that keeps a finding shows it as persisted. See the [diff command](commands/diff.md#what-counts-as-a-change) for how dependency changes are classified.

## `sarif`

SARIF 2.1.0 holds findings only, one result per rule and package pair. The rule ID is the advisory identifier (CVE, GHSA, or OSV). Severity maps to the SARIF `level`: `error` for critical and high, `warning` for medium, `note` for low and unknown. Each result points at the lockfile line that pins the vulnerable version, so code-scanning annotations land somewhere you can act on. Reachability and policy data go in the `properties` bag.

```bash
bomly scan --enrich --audit --fail-on high --format sarif > bomly.sarif
```

<details>
<summary>Sample result (one finding, properties trimmed)</summary>

```json
{
  "ruleId": "GHSA-m6fv-jmcg-4jfg",
  "level": "error",
  "message": {
    "text": "send vulnerable to template injection that can lead to XSS in pkg:npm/send@0.18.0"
  },
  "locations": [
    {
      "physicalLocation": {
        "artifactLocation": { "uri": "package-lock.json" },
        "region": { "startLine": 636 }
      }
    }
  ],
  "properties": {
    "package_ref": "pkg:npm/send@0.18.0",
    "fixed_in": "0.19.0",
    "fix_state": "fixed"
  }
}
```

</details>

[CI integration](CI_INTEGRATION.md) shows how to upload SARIF to GitHub code scanning and other tools.

## `spdx` and `cyclonedx`

Both SBOM formats are written from the same graph. [SBOM formats](SBOM.md) explains which to pick, why license data needs `--enrich`, and how to read and convert SBOMs.

## See also

- [JSON schemas](SCHEMAS.md) — the shared document shape and every field
- [SBOM formats](SBOM.md) — SPDX and CycloneDX
- [Exit codes](EXIT_CODES.md) — the process exit code is independent of the format
