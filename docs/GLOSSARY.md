# Glossary

The vocabulary Bomly uses, with one-sentence definitions and pointers to the doc that covers the concept in depth.

## Pipeline stages

**Detector** — Reads project evidence and produces a dependency graph. See [Detectors](DETECTORS.md).

**Matcher** — Enriches the graph with external data (vulnerabilities, licenses, lifecycle). Runs only with `--enrich`. See [Matchers](MATCHERS.md).

**Analyzer** — Annotates vulnerability findings with reachability data. Runs only with `--analyze`. See [Reachability](REACHABILITY.md).

**Auditor** — Evaluates the enriched graph against policy and produces findings. Runs only with `--audit`. See [Auditors](AUDITORS.md).

## Data shapes

**Package** — A resolved component: name, version, ecosystem, PURL, license, source manifest.

**Dependency edge** — A directed relationship between two packages, carrying scope (`runtime`, `development`, `unknown`) and depth.

**Manifest** — A file the detector treated as authoritative for the graph (`go.mod`, `package-lock.json`, `pom.xml`, `Gemfile.lock`, an SBOM, etc.).

**Subproject** — A directory below the scan root that has its own evidence. A monorepo has many subprojects; a single-module project has one.

**Finding** — A policy-evaluated match produced by an auditor. Has an ID, severity, package, title, reasons, and source.

**Reachability** — Whether application code can reach a vulnerable symbol. Status (`reachable` / `unreachable` / `unknown` / `not_applicable`) and tier (`symbol` / `module` / `package` / `none`).

## Plumbing

**Detector chain** — The ordered list Bomly tries for a given package manager. The first is preferred; later entries are fallbacks. See [Detectors](DETECTORS.md#detector-chains).

**Ecosystem** — A package universe (e.g. `go`, `npm`, `maven`, `python`). Bomly's per-ecosystem coverage is in [SUPPORT_MATRIX.md](SUPPORT_MATRIX.md).

**Package manager** — The tool that produced the manifest within an ecosystem (e.g. `gomod` in `go`; `npm`, `pnpm`, `yarn` in `npm`).

**Scope** — Whether an edge is `runtime` (needed in production) or `development` (build- or test-only). `unknown` when the detector cannot classify.

**`+/-` selector grammar** — The syntax used by `--detectors`, `--matchers`, `--auditors`, `--ecosystems`. Bare name filters to only that name; `+name` adds; `-name` removes.

## Network and caching

**Offline-safe** — A run with no `--enrich` makes zero outbound HTTP calls.

**Enrichment** — Network calls to public data sources, gated by `--enrich`. See [Matchers](MATCHERS.md).

**Cache** — On-disk store at `~/.bomly/cache/` (or `%USERPROFILE%\.bomly\cache\` on Windows). One subdirectory per matcher, each with its own TTL. Cache failures are non-fatal.

## CLI and policy

**`--fail-on`** — Severity token (`any` / `low` / `medium` / `high` / `critical`), `reachable`, or `exploitable`. Repeating ANDs constraints together. See [Auditors](AUDITORS.md).

**Exit code** — `0` success, `1` execution error, `2` policy violation, `3` resolution failure, `4` invalid input. See [Exit codes](EXIT_CODES.md).

## SBOM

**SBOM** — Software Bill of Materials. Bomly writes SPDX 2.3 and CycloneDX 1.6 JSON via `-o`, and ingests both via `--sbom`. See [SBOM formats](SBOM.md).

**PURL** — Package URL identifier (`pkg:type/namespace/name@version`). Bomly emits PURLs on every package.

## Plugin

**Plugin** — An external binary that adds a detector, matcher, auditor, or analyzer over Bomly's v1 gRPC protocol. See [Plugins](PLUGINS.md).

**Built-in** — Components compiled into the Bomly binary. Listed by `bomly plugins list`.

**`bomly` vs. `bomly-lite`** — `bomly` ships with Syft and Grype linked in; `bomly-lite` shells out to external `syft` and `grype` on `PATH`. Same flags, same outputs.
