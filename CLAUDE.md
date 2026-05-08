# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

Bomly is a customer-facing, security-sensitive dependency intelligence CLI. It scans source trees, SBOMs, Git refs, and container images; explains why dependencies exist; generates SBOMs (SPDX 2.3, CycloneDX); enriches packages with vulnerability/license/EOL data; evaluates policies; and diffs dependency state across Git refs or SBOM files.

## Commands

```sh
make build               # Full CLI with builtin Syft/Grype → bin/bomly
make build-lite          # Lite binary using external syft/grype → bin/bomly-lite
make test                # go test ./...
make smoke               # End-to-end tests (slow, requires network)
make smoke ARGS="-update" # Regenerate golden files
make run ARGS="scan"     # Run the CLI directly
make fmt                 # Format code
make lint                # golangci-lint v1.64.8
make generate            # Regenerate config reference, JSON schemas, support matrix
```

**Always run `make test` after changes.** If you change `internal/config/config.go`, `internal/output/*`, `sdk/catalog.go`, `sdk/support_matrix.go`, or `internal/registry/support.go`, also run `make generate`.

**Go version**: 1.25.8 (pinned — use exactly this to match CI formatting and build behavior).

**Build tags**: `bomly_external_syft` and `bomly_external_grype` switch from builtin libraries to external CLI tools. `make build-lite` uses both tags.

## Architecture

```txt
cmd/bomly/                       Entry point — calls internal/cli.Execute(version)
internal/cli/                    Cobra command wiring (scan, explain, diff, plugin, mcp, version),
                                 options/flags, command-context glue, and output orchestration
internal/cli/render/             CLI presentation layer: ANSI primitives, text helpers
                                 (Wrap/Style/TruncateToWidth/PadRight/ValueOrDash), the startup
                                 logo, and the scan/diff/explain text reports + SBOM writer
                                 (Scan, Diff, Explain, WhyTreeLines,
                                 ParseSBOMOutputSpecs, WriteSBOMDocument)
internal/tui/                    Interactive Bubbletea terminal UI (Run, NewScan, NewDiff,
                                 NewScanNavigator, Model interface). ErrNotATerminal sentinel
                                 lets the cli surface missing-tty as an invalid-input exit
sdk/                             Neutral domain types, ecosystem/package-manager identifiers,
                                 support-matrix data
internal/config/                 Resolved + File: the canonical config schema + YAML shape that
                                 the configref / schemajson / schemadocs generators read
internal/selector/               Generic +/- selector resolver (Resolve, Catalog, ParseCSV,
                                 AppendUnique, Contains, UnknownSelectorError)
internal/progress/               Live spinner + buffered completed-step renderer (Progress, Child)
internal/detectors/              Detector contracts (Detector, DetectorDescriptor, ResolveGraphRequest)
internal/detectors/*             Concrete per-ecosystem detectors (gomod, gradle, maven, npm,
                                 pnpm, yarn, python, ruby, composer, githubactions, sbom, syft)
internal/engine/                 Pipeline core (pipeline.go, engine.go), Registry wrapper, scope,
                                 graph-container helpers, explain orchestration, diff orchestration
internal/engine/consolidation/   Cross-subproject graph consolidation, manifest dedup, enrichment
                                 sync (ConsolidateGraphs, ManifestDedupPriority,
                                 SyncConsolidatedEnrichmentToManifests)
internal/engine/hooks/           Pre-/post-resolve hook contract + executor (Descriptor,
                                 PreResolveHook, PostResolveHook, RunPre, RunPost)
internal/registry/               Support/discovery registry; built-in wiring in builder.go
internal/matchers/*              External enrichment: osv, grype, deps.dev, ClearlyDefined, eol
internal/matchers/cache          File-based cache shared by matchers
internal/auditors/*              Policy evaluators (policy, noop)
internal/sbom/                   SPDX 2.3 / CycloneDX codec
internal/output/                 Text, JSON, SARIF 2.1.0, SBOM rendering + schema generation
internal/engine/diff/            Diff pipeline orchestration and audit delta classification
internal/engine/explain/         Dependency path traversal (explain command)
internal/engine/scan/            Scan command pipeline API
internal/plugin/                 gRPC plugin system (v1 protocol)
internal/testutil/               Test helpers (fake binary builder)
```

**`bomly explain`** is implemented by `newExplainCmd` in `internal/cli/explain_cmd.go`.

**Scan pipeline order**: `runtimePreparation → subprojectDiscovery → preResolveHooks → detect (per-package-manager chains) → scopeFilter → consolidate → match (license enrichment) → audit → postResolveHooks → format`

Runtime preparation is owned by `internal/engine` and is reached through CLI option helpers before pipeline execution. The CLI resolves raw targets and flags but must not discover subprojects with a separate registry.

### Package Boundaries

- `internal/detectors/*` must not import `internal/engine`, `internal/engine/*`, or `internal/registry`.
- `sdk` owns neutral identifiers that would otherwise create import cycles.
- `internal/registry` owns package-manager discovery, support lookups, and built-in wiring in `builder.go`. Do not create a separate `registrybuilder` package.
- `internal/engine` (pipeline core) may import `internal/engine/consolidation`, `internal/engine/hooks`, `internal/engine/explain`, `internal/detectors`, and `internal/registry`.
- `internal/engine` subpackages (`consolidation`, `hooks`, `diff`, `explain`, `scan`) must not import `internal/cli`.
- `internal/config`, `internal/selector`, `internal/progress`, `internal/cli/render`, `internal/tui` must not import `internal/cli`. They are downstream of cobra wiring; cli consumes them, not the reverse.
- `internal/tui` may import `internal/cli/render` (for ANSI primitives, text helpers, and shared sort/format helpers used by both the TUI and the text reports).
- `cmd/bomly/main.go` is the only file outside `internal/cli` that imports `internal/cli`.

Detector registration priority (lower = higher priority): native → lockfile-parser → third-party → plugin.

## Non-Negotiables

- No package-manager installation logic — assume PMs exist.
- Plugin protocol is versioned `v1` (gRPC). Do not break the `Metadata` / role descriptor contract.
- No secrets or credentials in logs, ever.
- Network calls (`--enrich`) permitted only to: `api.osv.dev`, CISA KEV, `api.clearlydefined.io`, `api.deps.dev`, `endoflife.date`. `--audit` evaluates existing data and must not trigger external matcher calls silently.
- Record architecture decisions in `docs/ARCHITECTURE.md`.
- Standard library + Cobra + existing deps only — no new dependencies without discussion.

## Code Conventions

**Errors** — always wrap with context:

```go
return fmt.Errorf("operation context: %w", err)
```

No panics in normal flow. Process-exit handling belongs only in `cmd/bomly/main.go`.

**Logging (Zap)** — nil-check loggers or use `zap.NewNop()`. Prefer one summary log per batch/cache pass over per-item logs. Never log PII, tokens, or credentials.

**Caching** (`internal/matchers/cache`):

```go
cache, _ := audcache.NewFileCache(dir, 24*time.Hour)
key := audcache.NewKey(purl, name, ecosystem, version)  // SHA256
if v, ok := audcache.Get[T](cache, key); ok { ... }
_ = audcache.Set(cache, key, value)
```

Cache failures are non-fatal — log a warning and continue.

**Testing helpers**: `t.TempDir()`, `testutil.BuildGoBinary()`, `httptest.NewServer()`. Shared fake-binary setup lives in `internal/cli/root_test_main_test.go`. No tests may be conditionally skipped without a recorded reason.

## Release

Draft releases are created automatically after merges to `main` based on commit message prefixes:

| Pattern | Result |
| --- | --- |
| `[skip release]` in head commit | No release |
| any non-`feat:` commit | Patch bump |
| `feat:` or `feat(scope):` | Minor bump |
| `type!:` or `BREAKING CHANGE:` | Major bump |

For squash-merges, the squash commit title/body determines the version bump.

## Reference Docs

| Doc | Covers |
| --- | --- |
| `docs/ARCHITECTURE.md` | Full pipeline, detector model, decision log |
| `docs/CI.md` | GitHub Actions, release workflow |
| `docs/CONFIG_REFERENCE.md` | All config keys, env vars, defaults (generated) |
| `docs/SUPPORT_MATRIX.md` | Ecosystem detector coverage (generated) |
| `docs/schemas/` | JSON schemas + human-readable output docs (generated) |
| `docs/PLUGINS.md` | Plugin development guide |
