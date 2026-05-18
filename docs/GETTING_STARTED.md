# Getting Started

This page walks you from installation to your first useful scan in five minutes.

## Install

If you have Go on `PATH`:

```bash
go install github.com/bomly-dev/bomly-cli/cmd/bomly@latest
```

Otherwise download a prebuilt archive from [GitHub Releases](https://github.com/bomly-dev/bomly-cli/releases) and put `bomly` on your `PATH`. Verify:

```bash
bomly version
```

For the full install matrix — `bomly` vs `bomly-lite`, checksum verification, PowerShell instructions, uninstall — see [Installation](INSTALLATION.md).

## Scan a project

From inside any source tree:

```bash
bomly scan
```

This runs the default pipeline:

1. Discover subprojects (every recognized lockfile or manifest).
2. Run the best detector chain for each subproject.
3. Render a human-readable report.

**Matchers are offline by default** — no `--enrich` means zero outbound enrichment calls. **Detectors** may still invoke their build tool (Go, Maven, Gradle, sbt) which can download packages from package registries. Lockfile-parser detectors (npm, pnpm, yarn, Composer, Bundler, NuGet, GitHub Actions) and SBOM ingest are fully offline. See [Detectors → Network behavior](DETECTORS.md#network-behavior) for the full breakdown.

Pass `--path` to scan a directory other than the current one:

```bash
bomly scan --path ./services/api
```

Pass `--container` to scan a container image:

```bash
bomly scan --container ghcr.io/example/app:latest
```

Pass `--url` (with optional `--ref`) to scan a Git repository without cloning by hand:

```bash
bomly scan --url https://github.com/example/repo --ref v1.2.0
```

See [Scan targets](SCAN_TARGETS.md) for the full target list.

## Add vulnerability and license data

`bomly scan` is offline by default. Pass `--enrich` when you want vulnerability, license, and lifecycle data from public sources:

```bash
bomly scan --enrich
```

This calls OSV, KEV, deps.dev, ClearlyDefined, and endoflife.date. All responses are cached under `~/.bomly/cache/`. See [Matchers](MATCHERS.md) for the per-source list and cache TTLs.

## Generate an SBOM

Use `-o` to write SPDX 2.3 or CycloneDX 1.6:

```bash
bomly scan \
  -o spdx-json=sbom.spdx.json \
  -o cyclonedx-json=sbom.cdx.json
```

`-o` can be passed multiple times. At most one may omit `=<path>` (that one goes to stdout). See [SBOM formats](SBOM.md) for the format comparison.

## Gate CI on a policy

Add `--audit --fail-on <severity>` to turn findings into a non-zero exit code:

```bash
bomly scan --enrich --audit --fail-on high
```

Exit `0` means clean. Exit `2` means at least one finding matched the threshold. Exit `4` means an invalid flag value. See [Exit codes](EXIT_CODES.md).

Common combinations:

```bash
# Fail on high or critical, runtime dependencies only
bomly scan --enrich --audit --fail-on high --fail-on-scope runtime

# Fail only when a high-or-above finding is actually reachable
bomly scan --enrich --audit --reachability --fail-on high --fail-on reachable
```

See [Auditors](AUDITORS.md) for the full grammar and [Reachability](REACHABILITY.md) for what "reachable" means per ecosystem. Reachability is an **experimental** feature; review its limitations before gating CI on it.

## Explain why a package is in the graph

```bash
bomly explain lodash
```

Bomly prints the shortest dependency path that introduced the package, plus alternative paths if there are multiple roots.

## Diff two versions

Compare two Git refs:

```bash
bomly diff --base main --head HEAD
```

Or two SBOM files:

```bash
bomly diff --sbom --base ./old.spdx.json --head ./new.spdx.json
```

Add `--audit --fail-on high` to fail PRs that introduce new high-severity findings without complaining about pre-existing ones.

## Inspect the interactive view

```bash
bomly scan --interactive
```

Opens a terminal UI with tabs for packages, vulnerabilities, licenses, findings, and source. See [TUI](TUI.md) for keybindings.

## What to read next

- [Output formats](OUTPUT_FORMATS.md) — text, JSON, SARIF, SBOM
- [Configuration](CONFIG_REFERENCE.md) — every config key, env var, and flag
- [Troubleshooting](TROUBLESHOOTING.md) — common errors and fixes
- [CI integration](CI_INTEGRATION.md) — GitHub Actions, GitLab, Jenkins recipes
