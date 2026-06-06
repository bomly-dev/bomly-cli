# Bomly Documentation

Start with [Getting Started](GETTING_STARTED.md) if you're new. Otherwise pick the section that matches what you're doing.

## Guides

Task-oriented walkthroughs.

- [Installation](INSTALLATION.md) — install methods, `bomly` vs `bomly-lite`, checksum verification, uninstall
- [Getting Started](GETTING_STARTED.md) — first scan, enrich, audit, diff
- [Scan Targets](SCAN_TARGETS.md) — directories, Git repos, containers, SBOMs
- [Output Formats](OUTPUT_FORMATS.md) — text, JSON, SARIF, SBOM
- [SBOM Formats](SBOM.md) — SPDX vs. CycloneDX, write and ingest
- [CI Integration](CI_INTEGRATION.md) — GitHub Actions, GitLab, Jenkins, Azure, CircleCI
- [Interactive TUI](TUI.md) — keybindings and tabs for `--interactive`
- [Troubleshooting](TROUBLESHOOTING.md) — common errors and fixes

## Concepts

How Bomly thinks about your project.

- [Architecture](ARCHITECTURE.md) — pipeline, runtime model, design boundaries
- [Detectors](DETECTORS.md) — turning project evidence into a dependency graph
- [Matchers](MATCHERS.md) — enriching the graph with vulnerability, license, lifecycle data
- [Auditors](AUDITORS.md) — evaluating the graph against policy
- [Reachability](REACHABILITY.md) — narrowing findings to code your app actually calls
- [Plugins](PLUGINS.md) — install, trust, configure, and package external plugins
- Plugin implementation guides: [detector](plugins/how-to-implement-detector.md), [matcher](plugins/how-to-implement-matcher.md), [auditor](plugins/how-to-implement-auditor.md)
- Example plugin repos: [Bun detector](https://github.com/bomly-dev/bomly-plugin-bun-lock-detector), [ClearlyDefined matcher](https://github.com/bomly-dev/bomly-plugin-clearlydefined-license), [Meme auditor](https://github.com/bomly-dev/bomly-plugin-meme-dependency-auditor)
- [Glossary](GLOSSARY.md) — every term, one sentence each

## Reference

Generated from code. Treat as authoritative.

- [Config Reference](CONFIG_REFERENCE.md) — every config key, env var, default, flag
- [Support Matrix](SUPPORT_MATRIX.md) — every ecosystem and package manager
- [Exit Codes](EXIT_CODES.md) — what each process exit value means
- [Detector Ecosystem Guides](detectors/ecosystems/) — per-ecosystem detector chains
- [Matcher Reference](matchers/) — per-matcher behavior, cache, output
- [JSON Schemas](schemas/scan.md) — scan, explain, diff output shapes

## Project

For contributors and release engineers.

- [CI](CI.md) — Bomly's own internal CI configuration
- [Contributing](../CONTRIBUTING.md) — build setup, code conventions, release process
