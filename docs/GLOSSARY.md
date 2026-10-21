# Glossary

The terms Bomly uses, one short definition each, with a link to the page that covers the concept. Other pages link here instead of redefining a term.

**Analyzer** — A component that marks each vulnerability as reachable or not from your code. Runs only with `--analyze`. See [Reachability](REACHABILITY.md).

**Auditor** — A component that evaluates the enriched graph against your policy and produces findings. Runs only with `--audit`. See [Auditors](AUDITORS.md).

**Baseline** — A committed file (`.bomly/baseline.json`) that records findings you have accepted, so they are reported but no longer fail an audit. See [Finding baselines](BASELINES.md).

**`bomly` and `bomly-lite`** — The two release binaries. `bomly` has Syft and Grype built in; `bomly-lite` runs the `syft` and `grype` binaries on your `PATH`. Same flags, same output. See [Installation](INSTALLATION.md).

**Built-in** — A component compiled into the Bomly binary. `bomly plugins list` shows built-in and external components together.

**Cache** — The on-disk store at `~/.bomly/cache/` (`%USERPROFILE%\.bomly\cache\` on Windows) for enrichment responses, with one subdirectory and lifetime (TTL) per matcher. A cache failure is a warning, never an error. See [Matchers](MATCHERS.md#cache).

**CRA** — The EU Cyber Resilience Act, whose SBOM expectations the `sbom` config section helps you meet. See [SBOM formats](SBOM.md).

**CVSS** — The Common Vulnerability Scoring System, the numeric severity score an advisory carries.

**Dependency** — One occurrence of a package in a manifest: a node in the detection graph with its scope, its location, and its edges to other dependencies. It points at a package by PURL and does not itself carry license or vulnerability data. See [Architecture](ARCHITECTURE.md#domain-model).

**Detector** — A component that reads project evidence (a lockfile, a manifest, build-tool output, an SBOM) and produces a dependency graph. See [Detectors](DETECTORS.md).

**Detector chain** — The ordered list of detectors Bomly tries for one package manager. The first that is ready and applicable wins; later entries are fallbacks. See [Detectors](DETECTORS.md#detector-chains).

**Ecosystem** — A package universe such as `go`, `npm`, `maven`, or `python`. See the [Support matrix](SUPPORT_MATRIX.md).

**Enrichment** — Looking packages up in vulnerability, license, and lifecycle sources. Happens only with `--enrich`. See [Matchers](MATCHERS.md) and [Network and privacy](NETWORK.md).

**EPSS** — The Exploit Prediction Scoring System, a probability that a vulnerability will be exploited.

**Exit code** — `0` success, `1` execution error, `2` policy violation, `3` resolution failure, `4` invalid input, `5` nothing to evaluate. See [Exit codes](EXIT_CODES.md).

**`--fail-on`** — The audit gate. Vulnerability values are a severity (`any`, `low`, `medium`, `high`, `critical`), `reachable`, and `exploitable`; when repeated, a finding must match all of them. `source-change`, for `bomly diff` only, fails a package whose source changed to Git or a URL. See [Auditors](AUDITORS.md).

**Finding** — A policy result produced by an auditor: an ID, a severity, a package, a title, reasons, and a policy status. A finding points at its package and advisory rather than copying them. See [Auditors](AUDITORS.md).

**KEV** — CISA's Known Exploited Vulnerabilities catalog. The `osv` matcher marks advisories that appear in it, and `--fail-on exploitable` gates on them.

**Lockfile** — The file a package manager writes with the exact resolved versions (`package-lock.json`, `go.sum`, `Gemfile.lock`, and so on). Lockfile detectors read it without running the package manager.

**Manifest** — A file a detector treated as the source of a graph: `go.mod`, `package-lock.json`, `pom.xml`, `Gemfile.lock`, an SBOM. In JSON, each manifest entry carries its dependencies.

**Matcher** — A component that adds vulnerability, license, lifecycle, or health data to packages. Runs only with `--enrich`. See [Matchers](MATCHERS.md).

**MCP** — The Model Context Protocol, which AI coding agents use to call tools. `bomly mcp serve` exposes `scan`, `explain`, and `diff` over it. See [MCP server](MCP.md).

**Module** — A workspace or reactor member that the package manager resolves under one root manifest: an npm, pnpm, or yarn workspace package, a Cargo workspace member, a Maven reactor module. See [Monorepos](MONOREPOS.md).

**Package** — One unique package across the whole scan, identified by its PURL. It owns the enrichment data: licenses, vulnerabilities, fix suggestions, scorecard, end-of-life status. Fifty dependencies on `react@18.2.0` share one package. See [Architecture](ARCHITECTURE.md#domain-model).

**Package manager** — The tool that produced a manifest within an ecosystem: `gomod` in `go`; `npm`, `pnpm`, and `yarn` in `npm`.

**Plugin** — An external program that adds a detector, matcher, auditor, or analyzer. Installed and verified by Bomly, disabled until you enable it. See [Plugins](PLUGINS.md).

**PURL** — A package URL, the standard identifier `pkg:type/namespace/name@version`. Every package Bomly reports has one.

**Reachability** — Whether your code can reach a vulnerable package or function. Status `reachable`, `unreachable`, or `unknown`, at tier `symbol`, `module`, `package`, or `none`. See [Reachability](REACHABILITY.md).

**Remediation** — Bomly's fix guidance for a vulnerable package: fix status, a recommended version when the evidence is complete, and suggested actions. It is read-only; Bomly never edits manifests.

**SARIF** — The Static Analysis Results Interchange Format, the JSON format GitHub code scanning and similar tools read. See [Output formats](OUTPUT_FORMATS.md#sarif).

**SBOM** — A Software Bill of Materials. Bomly writes SPDX 2.3 and CycloneDX 1.7 and reads SPDX 2.3 and CycloneDX 1.4 to 1.7. See [SBOM formats](SBOM.md).

**Scope** — Whether a dependency is `runtime` (needed in production) or `development` (build or test only). `unknown` when the detector cannot tell.

**Selector** — The list form shared by `--detectors`, `--matchers`, `--auditors`, `--analyzers`, and `--ecosystems`: plain names replace the defaults, `+name` adds, `-name` removes. See [Commands](COMMANDS.md#selector-grammar).

**SLSA** — Supply-chain Levels for Software Artifacts, the framework behind the build provenance file every release publishes. See [Installation](INSTALLATION.md#verify-a-release).

**Subproject** — An independent project in a nested directory, found by `--recursive`, with its own detector run. See [Monorepos](MONOREPOS.md).

**Tier** — The precision of a reachability result: `symbol`, `module`, `package`, or `none`. See [Reachability](REACHABILITY.md).

**VEX** — Vulnerability Exploitability eXchange, the CycloneDX `analysis` block that states whether a product is affected by a vulnerability. Bomly reads and writes it. See the [SBOM field reference](SBOM_REFERENCE.md).

**Workspace** — A package manager's way of declaring several packages in one repository (npm workspaces, Cargo workspaces, Maven reactors). Its members are modules.
