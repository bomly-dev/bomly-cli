# bomly scan

Resolve a target's dependencies into one consolidated graph, then optionally enrich, analyze, audit, and render it. `scan` is the pipeline every other graph command builds on — flags you learn here work the same way on [explain](explain.md) and [diff](diff.md).

## Minimal invocation

```bash
bomly scan
```

Scans the current directory. On a small npm project:

```text
✓ 68 packages in 1 manifest   (1 direct, 67 transitive · runtime 68, dev 0)

Top-level dependencies
  NAME      VERSION   LICENSE   SCOPE     VULNS
  express   4.19.2    MIT       runtime   -
```

No network calls happen here — enrichment columns stay empty until you ask for them.

## Choose a target

One target per invocation:

```bash
bomly scan --path ./services/api          # a specific directory
bomly scan --recursive                    # discover nested subprojects (see --max-depth, --exclude)
bomly scan --url https://github.com/owner/repo --ref v1.2.3   # a remote Git ref
bomly scan --image ghcr.io/example/app:latest                 # a container image
bomly scan --sbom --path ./sbom.cdx.json                      # an existing SBOM
```

[Scan Targets](../SCAN_TARGETS.md) covers each target's semantics and limits.

## Enrich, analyze, audit

The pipeline gates are independent opt-ins that compose:

```bash
# Fetch vulnerability, license, lifecycle, and scorecard data
bomly scan --enrich

# Evaluate policy against enriched data; exit 2 when a finding matches
bomly scan --enrich --audit --fail-on high

# Add reachability analysis and gate only on reachable findings
bomly scan --enrich --audit --analyze --fail-on low --fail-on reachable
```

- `--enrich` is the only flag that turns on matcher network calls ([Network and Privacy](../NETWORK.md)).
- `--audit` evaluates data already present; repeatable `--fail-on` constraints AND together (`any|low|medium|high|critical`, `reachable`, `exploitable`). Policy flags such as `--deny-license`, `--deny-package`, `--allow-vulnerability-id`, and `--baseline` are documented in [Auditors](../AUDITORS.md) and [Finding Baselines](../BASELINES.md).
- `--analyze` is experimental — read [Reachability](../REACHABILITY.md) before gating on it.
- `--warn-only` keeps findings visible but downgrades them so the exit code stays `0`.

## Render output

```bash
bomly scan --json                                   # shortcut for --format json
bomly scan --enrich --audit --fail-on high --format sarif
bomly scan -o spdx=sbom.spdx.json -o cyclonedx=sbom.cdx.json  # extra artifacts alongside the report
bomly scan --interactive                            # open the TUI instead of printing a report
```

`--format` accepts `text`, `json`, `markdown`, `sarif`, `spdx`, `cyclonedx`. See [Output Formats](../OUTPUT_FORMATS.md), [SBOM Formats](../SBOM.md), and [Interactive TUI](../TUI.md).

## Narrow the run

```bash
bomly scan --scope runtime               # drop development dependencies
bomly scan --ecosystems npm,go           # only these ecosystems (+/- grammar supported)
bomly scan --detectors npm-detector      # pin the detector chain (recommended in CI)
bomly scan --install-first               # let detectors install dependencies first (network, opt-in)
```

Pinning `--detectors` makes CI fail loudly instead of silently regenerating a fallback-shaped graph — see [Detectors](../DETECTORS.md) and [CI-readiness warnings](../CI_READINESS.md).

## Exit codes

`0` clean · `2` a finding matched `--fail-on` · `3` a required detector could not produce a graph · `4` invalid flag or target · `5` nothing to evaluate. Full table and CI recipes: [Exit Codes](../EXIT_CODES.md).

## See also

- [Getting Started](../GETTING_STARTED.md) — the five-minute walkthrough
- [Use Cases](../USE_CASES.md) — goal-shaped recipes built on `scan`
- [Config Reference](../CONFIG_REFERENCE.md) — every flag's config key, env var, and default
