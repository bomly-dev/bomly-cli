# Bomly Documentation

Start with [Getting Started](GETTING_STARTED.md) if you're new. Otherwise pick the section that matches what you're doing.

## Guides

Task-oriented walkthroughs.

- [Installation](INSTALLATION.md) — install methods, `bomly` vs `bomly-lite`, checksum verification, uninstall
- [Getting Started](GETTING_STARTED.md) — first scan, enrich, audit, diff
- [Use Cases](USE_CASES.md) — recipes for PR gates, SBOMs, triage, license and offline scans
- [Scan Targets](SCAN_TARGETS.md) — directories, Git repos, containers, SBOMs
- [Output Formats](OUTPUT_FORMATS.md) — text, JSON, SARIF, SBOM
- [SBOM Formats](SBOM.md) — SPDX vs. CycloneDX, write and ingest
- [CI Integration](CI_INTEGRATION.md) — GitHub Actions, GitLab, Jenkins, Azure, CircleCI
- [Bomly Guard](BOMLY_GUARD.md) — the turnkey GitHub Action for PR dependency review
- [Interactive TUI](TUI.md) — keybindings and tabs for `--interactive`
- [Troubleshooting](TROUBLESHOOTING.md) — common errors and fixes

## Concepts

How Bomly thinks about your project.

- [Architecture](ARCHITECTURE.md) — the scan pipeline, domain model, and network behavior
- [Detectors](DETECTORS.md) — turning project evidence into a dependency graph
- [Matchers](MATCHERS.md) — enriching the graph with vulnerability, license, lifecycle data
- [Auditors](AUDITORS.md) — evaluating the graph against policy
- [Reachability](REACHABILITY.md) — narrowing findings to code your app actually calls
- [Plugins](PLUGINS.md) — install, trust, configure, and package external plugins
- [MCP Server](MCP.md) — connect Bomly to Claude Code, Cursor, VS Code, or another MCP client
- Plugin implementation guides: [detector](plugins/how-to-implement-detector.md), [matcher](plugins/how-to-implement-matcher.md), [auditor](plugins/how-to-implement-auditor.md)
- Example plugin repos: [Bun detector](https://github.com/bomly-dev/bomly-plugin-bun-lock-detector), [ClearlyDefined matcher](https://github.com/bomly-dev/bomly-plugin-clearlydefined-matcher), [EOL lifecycle matcher](https://github.com/bomly-dev/bomly-plugin-eol-matcher), [Meme auditor](https://github.com/bomly-dev/bomly-plugin-meme-auditor)
- [Glossary](GLOSSARY.md) — every term, one sentence each

## Reference

Generated from code. Treat as authoritative.

- [Config Reference](CONFIG_REFERENCE.md) — every config key, env var, default, flag
- [Support Matrix](SUPPORT_MATRIX.md) — every ecosystem and package manager
- [Exit Codes](EXIT_CODES.md) — what each process exit value means
- [Detector Ecosystem Guides](detectors/ecosystems/) — per-ecosystem detector chains
- [Matcher Reference](matchers/) — per-matcher behavior, cache, output
- [Auditor Reference](auditors/) — per-auditor options, examples, limitations
- [JSON Schemas](SCHEMAS.md) — scan, explain, diff output shapes

## Project

For contributors and release engineers. These live outside the published docs in [`dev-docs/`](../dev-docs/).

- [Architecture (deep dive)](../dev-docs/ARCHITECTURE.md) — full pipeline, package boundaries, decision log
- [Domain Models](../dev-docs/MODELS.md) — SDK types behind detection, matching, and audit
- [CI](../dev-docs/CI.md) — Bomly's own internal CI configuration
- [Release Checklist](../dev-docs/RELEASE_CHECKLIST.md) — maintainer checklist for publishing tagged releases
- [Contributing](../CONTRIBUTING.md) — build setup, code conventions, release process
