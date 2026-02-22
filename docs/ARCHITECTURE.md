# Bomly Architecture

This document is the single source of truth for Bomly's architecture. It consolidates all prior architecture decision records (ADR-001 through ADR-007) into one reference.

---

## Product Thesis

Bomly is an AI-native dependency intelligence layer. It helps developers make safer dependency decisions at the moment a dependency is selected, introduced, reviewed, or updated.

The core focus is **decision support across the dependency lifecycle** — before and during adoption, not only after software has been assembled. Bomly is centered on explanation, evaluation, and trust rather than on static inventory generation alone.

Bomly is not a generic SBOM export utility, a CVE lookup wrapper, or a compliance reporting portal as its primary identity.

---

## System Architecture

Bomly uses a CLI-first architecture built around a reusable analysis core:

```
Core analysis engine
    → CLI as primary interface
    → thin wrappers for CI, PR, API, and agent surfaces
```

The CLI is the canonical product surface. Internal packages remain modular and composable so that future surfaces (CI actions, PR bots, APIs, agent integrations) invoke the same engine without reimplementing logic.

Major user-facing capabilities are exposed through explicit CLI commands with structured output modes:

| Command | Purpose |
|---------|---------|
| `bomly scan` | Dependency graph output, SBOM generation, vulnerability audit |
| `bomly why` | Dependency path explanation |
| `bomly diff` | Dependency state comparison across Git refs |
| `bomly plugin` | Plugin discovery and management |

---

## Scan Pipeline

The scan engine owns orchestration between CLI commands, detectors, auditors, and plugins. Commands are thin; the engine handles selection, ordering, and execution.

Before any pipeline stage runs, Bomly prepares a single immutable runtime for the selected execution target. Runtime preparation builds the filtered registry once, applies detector, auditor, matcher, and ecosystem selections, indexes the target with that same filtered registry, and records the planned subprojects plus detector chains. `scan`, `diff`, and `explain` all reuse that prepared runtime for resolution, license enrichment, and auditing so discovery and execution cannot drift apart.

Pipeline stages executed in order:

```
1. Subproject Discovery — find package-manager roots under the execution target
2. Pre-Resolve Hooks — install commands, plugin pre-processing
3. Detect — per-ecosystem chain execution with ordering and superseding
4. Consolidate — merge subproject graphs, create synthetic roots
5. Command Processing — scope filtering, path extraction, diffing
6. License Enrichment — surface license data from packages
7. Audit — vulnerability analysis via per-ecosystem auditor chains
8. Post-Resolve Hooks — plugin post-processing, reporting
```

### Execution Target

One CLI execution has exactly one execution target:

- **Filesystem path** — local directory or file; recursive mode discovers subprojects beneath it
- **Container image** — resolved through the Syft-backed detector path
- **Repository URL** — cloned to a temporary directory before detector execution
- **Git diff** — materializes each ref into an isolated temporary checkout

### Subprojects

Package-manager roots found at or under the execution target. Each subproject carries execution-target metadata, a primary package manager when known, the matched package-manager set, and the planned detector chain. Resolution reuses that stored plan rather than recomputing detector selection later, while detector-specific fallbacks still determine which detector actually succeeds at runtime.

Built-in subproject indexing is derived from the canonical package-manager registry in `internal/registry`. Filesystem and SBOM targets use evidence patterns exposed by the filtered registry. Container targets are planned from detector discovery metadata, which is how Syft-backed container scans and container diff/explain flows stay aligned with the same runtime filters used later in execution.

### Consolidated Graph

Built above resolved subproject graphs using synthetic subproject root nodes. Preserves subproject identity in the merged view while letting commands generate single top-level documents.

---

## Detector and Auditor Model

Both detectors and auditors are first-class pipeline roles with shared contracts:

- **Detectors** resolve dependency graphs into Bomly's internal graph model
- **Auditors** consume a resolved graph and return normalized vulnerability findings

### Package Manager Chains

Detectors and auditors are registered per package manager with explicit ordering and superseding rules:

```
PackageManagerChain {
    PackageManager    PackageManager
    Detectors         []ChainedDetector   // ordered by priority
    Auditors          []ChainedAuditor    // ordered by priority
}
```

**Ordering** — detectors run in order within each package manager:
- e.g. npm: native-npm (order=0) → lockfile-npm (order=1) → syft (order=100)

**Superseding** — if detector X supersedes detector Y and X succeeds, Y is skipped:
- e.g. native-npm supersedes syft; if native succeeds, syft is skipped
- Detectors at the same tier run independently and their results merge

### Implementation Categories

| Category | Examples | Priority |
|----------|----------|----------|
| Native | npm, go, maven, gradle, python detectors | Highest |
| Lockfile parser | npm lockfile detector | High |
| Third-party tool | Syft detector, Grype auditor | Low |
| Plugin | External `bomly-*` executables | Lowest |

### Detector Interface

```go
type Detector interface {
    Descriptor() DetectorDescriptor
    ResolveGraph(ctx context.Context, req ResolveGraphRequest) (ResolveGraphResult, error)
}
```

Optional interfaces: `ReadyDetector` (`Ready() bool`) and `ApplicableDetector` (`Applicable() bool`) to gate execution.

### Package Ownership Rules

- `internal/detectors` owns detector-facing contracts and shared detector helpers: `Detector`, `DetectorDescriptor`, `ResolveGraphRequest`, `ResolveGraphResult`, scope helpers, and manifest inference helpers.
- Concrete detector packages under `internal/detectors/*` must not import `internal/scan` or `internal/registry`. They depend on `internal/detectors`, `internal/model`, and local helpers only.
- `internal/model` owns neutral identifiers and support metadata shared across package boundaries, including ecosystems, package managers, detector types, target modes, and support-matrix data.
- `internal/registry` owns support/discovery indexing and built-in scan-registry wiring in `internal/registry/builder.go`. There is no separate `registrybuilder` package.
- `internal/scan` owns orchestration and may import both `internal/detectors` and `internal/registry`, but the dependency must not point back from detectors into scan.

### Auditor Interface

```go
type Auditor interface {
    Descriptor() AuditorDescriptor
    Audit(ctx context.Context, req AuditRequest) (AuditResult, error)
}
```

---

## Build-Tag Toggle (Syft/Grype)

Syft and Grype support two compilation modes controlled by build tags:

| Build Tag | Mode | Behavior |
|-----------|------|----------|
| `bomly_builtin_syft` | Builtin | Links Syft library directly |
| `bomly_builtin_grype` | Builtin | Links Grype library directly |
| (neither) | External | Shells out to `syft`/`grype` CLI binaries |

- `make build` — includes both tags (full binary)
- `make build-lite` — excludes both (smaller binary, requires syft/grype on PATH)

---

## Vulnerability and License Enrichment

Enrichment is triggered by `--audit` on the `scan` command.

### OSV Auditor

- API: `https://api.osv.dev/v1/querybatch` (up to 1000 queries per batch)
- Query: PURL when available; falls back to `{name, ecosystem, version}`
- Cache: JSON files in `~/.bomly/cache/osv/`, SHA-256 keyed, 24h TTL
- Non-fatal: timeouts and errors produce warnings, not failures

### Grype Auditor

- Requires `grype` binary on PATH
- In builtin mode: linked directly via library
- In external mode: shells out to `grype -o json`
- `Ready()` returns false if binary not found; engine skips with warning

### KEV Enrichment

- CISA Known Exploited Vulnerabilities catalog
- Post-processing pass over findings: CVE/alias intersection marks `is_kev: true`
- Non-fatal on download failure

### Licenses

- `Package.Licenses` populated by detectors at scan time
- Surfaced in all output formats, not only SBOMs
- License enrichment via ClearlyDefined and deps.dev

### Caching

```go
cache, _ := enrichment.NewFileCache(dir, 24*time.Hour)
key := enrichment.NewCacheKey(purl, name, ecosystem, version)
```

Cache failures are non-fatal — log a warning and continue.

---

## Plugin System

### Discovery

1. `~/.bomly/plugins/bomly-*` (highest priority)
2. `PATH` scan for `bomly-*`

### Handshake

```bash
bomly-<name> --bomly-plugin-info
```

Returns JSON metadata:

```json
{
  "name": "example",
  "version": "0.1.0",
  "protocol": "v1",
  "commands": [
    {
      "name": "deps",
      "summary": "Print dependency graph",
      "stage": "detect",
      "ecosystems": ["npm"],
      "package_managers": ["npm"],
      "evidence_patterns": ["package.json"],
      "target_kinds": ["filesystem"]
    }
  ]
}
```

The additional detect-command fields are optional in `v1`. They let the core include plugin detectors in runtime planning and auto-discovery. Detect plugins without discovery metadata still register and can run when selected explicitly, but they are not auto-discovered during runtime preparation.

### JSON Envelope Protocol (`bomly-plugin-v1`)

All plugin stages use a typed JSON envelope over stdio:

```json
{
  "protocol": "bomly-plugin-v1",
  "stage": "detect",
  "payload": { ... }
}
```

Supported stages: `pre-resolve`, `detect`, `audit`, `post-resolve`.

All plugins must use the JSON envelope protocol with an explicit `stage` field.

### Execution Environment

| Variable | Value |
|----------|-------|
| `BOMLY_PROTOCOL` | `v1` |
| `BOMLY_CORE_VERSION` | `<semver>` |
| `BOMLY_CWD` | `<absolute path>` |
| `BOMLY_CONFIG` | `<path>` |

### Security Boundary

- Plugins run as subprocesses without elevated privileges
- Core controls environment variables passed to plugins
- Core owns policy, SBOM normalization, and backend integration
- Plugins own ecosystem-specific interrogation

---

## Trust Model

Bomly uses a graph-centered intelligence model with layered trust:

### Layer 1 — Heuristic Risk Analysis

Signals: package age, maintainer concentration, release cadence, naming similarity, download profile, sudden introduction patterns.

### Layer 2 — Provenance and Attestation

Validates artifact origin and integrity: repository identity, build workflow, commit SHA, artifact digest, SBOM linkage.

### Layer 3 — Policy

Converts signals into decision boundaries: attestation requirements, trusted publisher lists, blocking unverifiable artifacts.

AI dependency sanity (hallucinated packages, legitimacy ranking) is part of the same trust model, not a separate product line.

---

## Unified Domain Model (`internal/model`)

All pipeline stages share a single rich schema:

| Type | Purpose |
|------|---------|
| `model.Package` | Universal package identity, locators, provenance, integrity, licensing, metadata |
| `model.Graph` | Index-based adjacency graph of packages with topological operations |
| `model.Vulnerability` | Universal finding type (vulnerability, risk, policy) |
| `model.Container` | Execution target + subproject entries + findings + summaries |
| `model.ScanResult` | Wrapper for scan output |
| `model.DiffResult` | Base/head containers + deltas |
| `model.ExplainResult` | Focused container + paths |

---

## Package Map

| Package | Role |
|---------|------|
| `cmd/bomly` | Entry point — calls `internal/cli.Execute()` |
| `internal/cli` | Cobra root + all commands (scan, why, diff, plugin) |
| `internal/model` | Unified domain types plus neutral package/ecosystem/support identifiers shared across packages |
| `internal/detectors` | Detector contracts, descriptors, requests/results, and detector-only helpers |
| `internal/scan` | Pipeline, engine, consolidation, auditors, matchers, hooks, and orchestration |
| `internal/registry` | Support/discovery registry and built-in scan-registry wiring |
| `internal/detectors/*` | Concrete dependency resolution per ecosystem (gomod, gradle, maven, node, python, sbom, syft) |
| `internal/auditors/*` | Vulnerability analysis (osv, grype, noop) |
| `internal/sbom` | SBOM codec (SPDX 2.3, CycloneDX) |
| `internal/output` | Output rendering (text, JSON, SARIF 2.1.0) |
| `internal/plugin` | Plugin discovery, protocol, handshake, execution |
| `internal/enrichment` | File-backed TTL cache; VEX abstraction |
| `internal/explain` | Dependency path traversal (`why` command) |
| `internal/licenses` | License enrichment (ClearlyDefined, deps.dev) |
| `internal/logging` | Zap console wrapper |
| `internal/testutil` | Test helpers (fake binary builder) |
| `pkg/system` | OS-level helpers |

---

## Decision Log

These decisions were originally captured as separate ADRs and have been consolidated into this document.

| # | Date | Decision | Outcome |
|---|------|----------|---------|
| ADR-001 | 2026-04-02 | Product Thesis and Strategic Scope | Bomly is an AI-native dependency intelligence layer for decision support |
| ADR-002 | 2026-04-02 | CLI-First Product Surface | CLI is the canonical interface; reusable analysis core feeds all surfaces |
| ADR-003 | 2026-04-02 | Dependency Intelligence and Trust Model | Graph-centered intelligence with layered trust (heuristics + provenance + policy) |
| ADR-004 | 2026-04-02 | Developer Experience and Commercial Model | Zero-friction UX first; free intelligence vs. paid governance |
| ADR-005 | 2026-04-06 | Plugin Architecture and Protocol Boundaries | Executable plugins with versioned handshake; JSON envelope protocol |
| ADR-006 | 2026-04-06 | Modular Scan Engine | Ecosystem-based registry with detector/auditor chains, ordering, and superseding |
| ADR-007 | 2026-04-13 | Vulnerability and License Enrichment | OSV + Grype auditors, KEV flagging, file-backed cache, SARIF output |
