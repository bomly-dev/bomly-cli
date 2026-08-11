# Bomly Documentation

Start with [Getting Started](GETTING_STARTED.md) if you're new. Otherwise pick the section that matches what you're doing. The sections below follow the site navigation groups defined in [`manifest.json`](manifest.json), plus links to a few site pages that live outside the versioned docs (such as the FAQ).

## Getting started

Install Bomly and run your first scan.

- [Getting Started](GETTING_STARTED.md) — first scan, enrich, audit, diff
- [Installation](INSTALLATION.md) — install methods, `bomly` vs `bomly-lite`, checksum verification, uninstall
- [Tutorial](TUTORIAL.md) — from first scan to a CI gate on a real project, with representative output from the workflow
- [Use Cases](USE_CASES.md) — recipes for PR gates, SBOMs, triage, license and offline scans
- [Scan Targets](SCAN_TARGETS.md) — directories, Git repos, containers, SBOMs
- [Output Formats](OUTPUT_FORMATS.md) — text, JSON, SARIF, SBOM
- [SBOM Formats](SBOM.md) — SPDX vs. CycloneDX, write and ingest
- [FAQ](https://bomly.dev/faq) — quick answers on privacy, accounts, tool differences, and first-scan surprises (source: [`faq.json`](faq.json))

## How it works

What Bomly does, and why each piece exists.

- [Commands](COMMANDS.md) — per-command reference for [scan](commands/scan.md), [explain](commands/explain.md), and [diff](commands/diff.md)
- [Detectors](DETECTORS.md) — turning project evidence into a dependency graph
- [Matchers](MATCHERS.md) — enriching the graph with vulnerability, license, lifecycle data
- [Auditors](AUDITORS.md) — evaluating the graph against policy
- [Plugins](PLUGINS.md) — install, trust, configure, and package external plugins
- Plugin implementation guides: [detector](plugins/how-to-implement-detector.md), [matcher](plugins/how-to-implement-matcher.md), [auditor](plugins/how-to-implement-auditor.md)
- Example plugin repos: [Bun detector](https://github.com/bomly-dev/bomly-plugin-bun-lock-detector), [ClearlyDefined matcher](https://github.com/bomly-dev/bomly-plugin-clearlydefined-matcher), [EOL lifecycle matcher](https://github.com/bomly-dev/bomly-plugin-eol-matcher), [Meme auditor](https://github.com/bomly-dev/bomly-plugin-meme-auditor)
- [MCP Server](MCP.md) — connect Bomly to Claude Code, Cursor, VS Code, or another MCP client
- [Bomly Guard](BOMLY_GUARD.md) — the turnkey GitHub Action for PR dependency review

## Operations

Running Bomly in CI and keeping pipelines healthy.

- [Integrations](INTEGRATIONS.md) — CI actions, AI agents, code scanning, install channels, plugins, and the marketplace
- [CI Integration](CI_INTEGRATION.md) — GitHub Actions, GitLab, Jenkins, Azure, CircleCI
- [CI-Readiness Warnings](CI_READINESS.md) — package-manager, lockfile-format, and install-policy mismatches that fail CI on their own
- [Finding Baselines](BASELINES.md) — keep accepted package findings visible without failing audits
- [Troubleshooting](TROUBLESHOOTING.md) — common errors and fixes

## Reference

Specifications, matrices, and design deep dives. The generated pages are regenerated from code by `make generate` — treat those as authoritative.

- [Support Matrix](SUPPORT_MATRIX.md) — every ecosystem and package manager
- [Config Reference](CONFIG_REFERENCE.md) — every config key, env var, default, flag
- [Exit Codes](EXIT_CODES.md) — what each process exit value means
- [Interactive TUI](TUI.md) — keybindings and tabs for `--interactive`
- [JSON Schemas](SCHEMAS.md) — scan, explain, diff output shapes
- [Detector Reference](detectors/) — per-ecosystem detector pages, plus [Syft fallback](detectors/syft.md) for everything else
- [Matcher Reference](matchers/) — per-matcher behavior, cache, output
- [Auditor Reference](auditors/) — per-auditor options, examples, limitations
- [Architecture](ARCHITECTURE.md) — the scan pipeline, domain model, and network behavior
- [Network and Privacy](NETWORK.md) — every network trigger, what it transmits, and how to stay offline
- [Security and Trust Boundaries](SECURITY.md) — permissions, network behavior, plugins, input limits, and residual risks
- [Reproducible Evidence](EVIDENCE.md) — public inputs, commands, results, and limitations behind important behavior claims
- [Glossary](GLOSSARY.md) — every term, one sentence each

## Experimental

Features that are still maturing.

- [Reachability](REACHABILITY.md) — narrowing findings to code your app actually calls

## Project

- [Release Notes](https://github.com/bomly-dev/bomly-cli/releases) — what changed in each version
- [Contributing](../CONTRIBUTING.md) — repository layout, docs conventions, release process
