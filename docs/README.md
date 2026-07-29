# Bomly Documentation

Start with [Getting Started](GETTING_STARTED.md) if you're new. Otherwise pick the section that matches what you're doing. The sections below mirror the groups on the [documentation site](https://bomly.dev/docs), so this index and the site navigation always tell the same story.

## Getting started

Install Bomly and run your first scan.

- [Getting Started](GETTING_STARTED.md) — first scan, enrich, audit, diff
- [Installation](INSTALLATION.md) — install methods, `bomly` vs `bomly-lite`, checksum verification, uninstall
- [Use Cases](USE_CASES.md) — recipes for PR gates, SBOMs, triage, license and offline scans
- [Scan Targets](SCAN_TARGETS.md) — directories, Git repos, containers, SBOMs
- [Output Formats](OUTPUT_FORMATS.md) — text, JSON, SARIF, SBOM
- [SBOM Formats](SBOM.md) — SPDX vs. CycloneDX, write and ingest
- [FAQ](FAQ.md) — quick answers on privacy, accounts, tool differences, and first-scan surprises

## How it works

What Bomly does, and why each piece exists.

- [Architecture](ARCHITECTURE.md) — the scan pipeline, domain model, and network behavior
- [Security and Trust Boundaries](SECURITY.md) — permissions, network behavior, plugins, input limits, and residual risks
- [Detectors](DETECTORS.md) — turning project evidence into a dependency graph
- [Matchers](MATCHERS.md) — enriching the graph with vulnerability, license, lifecycle data
- [Auditors](AUDITORS.md) — evaluating the graph against policy
- [MCP Server](MCP.md) — connect Bomly to Claude Code, Cursor, VS Code, or another MCP client
- [Plugins](PLUGINS.md) — install, trust, configure, and package external plugins
- Plugin implementation guides: [detector](plugins/how-to-implement-detector.md), [matcher](plugins/how-to-implement-matcher.md), [auditor](plugins/how-to-implement-auditor.md)
- Example plugin repos: [Bun detector](https://github.com/bomly-dev/bomly-plugin-bun-lock-detector), [ClearlyDefined matcher](https://github.com/bomly-dev/bomly-plugin-clearlydefined-matcher), [EOL lifecycle matcher](https://github.com/bomly-dev/bomly-plugin-eol-matcher), [Meme auditor](https://github.com/bomly-dev/bomly-plugin-meme-auditor)

## Reference

Specifications and matrices. The generated pages are regenerated from code by `make generate` — treat those as authoritative.

- [Support Matrix](SUPPORT_MATRIX.md) — every ecosystem and package manager
- [Config Reference](CONFIG_REFERENCE.md) — every config key, env var, default, flag
- [Exit Codes](EXIT_CODES.md) — what each process exit value means
- [Interactive TUI](TUI.md) — keybindings and tabs for `--interactive`
- [JSON Schemas](SCHEMAS.md) — scan, explain, diff output shapes
- [Glossary](GLOSSARY.md) — every term, one sentence each
- [Detector Ecosystem Guides](detectors/ecosystems/) — per-ecosystem detector chains
- [Matcher Reference](matchers/) — per-matcher behavior, cache, output
- [Auditor Reference](auditors/) — per-auditor options, examples, limitations

## Operations

Running Bomly in CI and keeping pipelines healthy.

- [CI Integration](CI_INTEGRATION.md) — GitHub Actions, GitLab, Jenkins, Azure, CircleCI
- [CI-Readiness Warnings](CI_READINESS.md) — package-manager, lockfile-format, and install-policy mismatches that fail CI on their own
- [Bomly Guard](BOMLY_GUARD.md) — the turnkey GitHub Action for PR dependency review
- [Finding Baselines](BASELINES.md) — keep accepted package findings visible without failing audits
- [Troubleshooting](TROUBLESHOOTING.md) — common errors and fixes

## Experimental

Features that are still maturing.

- [Reachability](REACHABILITY.md) — narrowing findings to code your app actually calls

## Project

For contributors and release engineers. These live outside the published docs in [`dev-docs/`](../dev-docs/).

- [Release Notes](https://github.com/bomly-dev/bomly-cli/releases) — what changed in each version
- [Architecture (deep dive)](../dev-docs/ARCHITECTURE.md) — full pipeline, package boundaries, decision log
- [Domain Models](../dev-docs/MODELS.md) — SDK types behind detection, matching, and audit
- [CI](../dev-docs/CI.md) — Bomly's own internal CI configuration
- [Security Assurance](../dev-docs/SECURITY_ASSURANCE.md) — trust-boundary controls, regression evidence, and CI permissions
- [Release Checklist](../dev-docs/RELEASE_CHECKLIST.md) — maintainer checklist for publishing tagged releases
- [Contributing](../CONTRIBUTING.md) — build setup, code conventions, release process
