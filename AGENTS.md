# Agent Instructions — Bomly CLI

Bomly is a **customer-facing, security-sensitive CLI** for dependency intelligence. Audience: professional developers, security managers, and CI workflows. Expect high standards: correct behaviour, clear output, full logging, and no panics.

## Build & Test

```sh
make build               # build both `bin/bomly` (builtin Syft/Grype) and `bin/bomly-lite`
make build-lite          # go build -tags "bomly_external_syft,bomly_external_grype" -o bin/bomly-lite ./cmd/bomly
make test                # go test ./...
make smoke               # end-to-end smoke tests against real repos/containers (slow, needs network)
make smoke ARGS="-update" # regenerate golden files for smoke tests
make run ARGS="scan"    # go run ./cmd/bomly <ARGS>
make generate            # regenerate config reference, JSON schemas, schema docs, and support matrix
```

Always run `make test` after changes. All tests must pass before marking work is done.
If you change `internal/cli/config.go`, `internal/viewmodel/*`, `internal/model/catalog.go`, `internal/model/support_matrix.go`, or `internal/registry/support.go`, also run `make generate`.

## Architecture

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for full detail. Component map:

| Package | Role |
|---------|------|
| `cmd/bomly` | Entry point — calls `internal/cli.Execute()` |
| `internal/cli` | Cobra root + all commands (`scan`, `explain`, `diff`, `plugin`, `version`) |
| `internal/model` | Unified domain types plus neutral package/ecosystem/support identifiers shared across packages |
| `internal/detectors` | Detector contracts, descriptors, requests/results, and detector-only helpers |
| `internal/scan` | Pipeline, engine, consolidation, auditors, matchers, hooks, and orchestration |
| `internal/registry` | Canonical support/discovery registry and built-in scan-registry wiring |
| `internal/detectors/*` | Concrete dependency resolution per ecosystem (gomod, gradle, maven, node, python, sbom, syft) |
| `internal/matchers/*` | External enrichment matchers and shared matcher cache (osv, grype, deps.dev, ClearlyDefined, eol) |
| `internal/auditors/*` | Policy evaluators and audit-only logic (policy, noop) |
| `internal/sbom` | SBOM codec (SPDX 2.3, CycloneDX) |
| `internal/output` | Output rendering (text, JSON, SARIF 2.1.0) |
| `internal/viewmodel` | Structured command payloads and schema generation for `scan`, `diff`, and `explain` |
| `internal/plugin` | Plugin discovery, protocol, handshake, and execution |
| `internal/explain` | Dependency path traversal (`explain` command) |
| `internal/licenses` | Shared license helpers and cache helpers |
| `internal/logging` | Zap console wrapper |
| `internal/testutil` | Test helpers (fake binary builder) |
| `internal/system` | OS-level helpers |

Scan pipeline: `runtimePreparation → subprojectDiscovery → preResolveHooks → detect (per-package-manager chains) → scopeFilter → consolidate → match (license enrichment on the consolidated graph) → commandProcess → audit → postResolveHooks → format`.

Runtime preparation is owned by `internal/scan`: build the filtered registry once, index the execution target with that same registry, and reuse the prepared runtime for `scan`, `diff`, `explain`, license enrichment, and auditing. The CLI resolves raw execution targets and flags, but it must not discover subprojects with a separate registry.

`bomly explain` is implemented by `newExplainCmd` in `internal/cli/why_cmd.go`; the filename has not been renamed.

### Package Boundaries

- `internal/detectors/*` must not import `internal/scan` or `internal/registry`. Concrete detectors depend on `internal/detectors`, `internal/model`, and local helpers only.
- `internal/detectors` owns detector-facing contracts such as `Detector`, `DetectorDescriptor`, `ResolveGraphRequest`, and detector helper functions.
- `internal/model` owns neutral shared identifiers and support metadata that would otherwise create package cycles, including ecosystems, package managers, detector types, and support-matrix data.
- `internal/registry` owns package-manager discovery, support lookups, and built-in registry wiring in `internal/registry/builder.go`. Do not create or reintroduce a separate `registrybuilder` package.
- `internal/scan` may import `internal/detectors` and `internal/registry`, but detector packages must not point back into `internal/scan`. Runtime planning, prepared subprojects, and detector-chain reuse belong in `internal/scan`.

## Non-Negotiables

- **Do not add PM installation logic.** Assume package managers exist.
- **Plugin protocol is versioned `v1`.** Never break the `--bomly-plugin-info` JSON contract.
- **No secrets or credentials in logs.** Ever.
- **Network calls only when explicitly triggered.** OSV (`https://api.osv.dev`), CISA KEV, ClearlyDefined (`https://api.clearlydefined.io`), deps.dev (`https://api.deps.dev`), and endoflife.date are permitted only during explicit enrichment (`--enrich`). `--audit` evaluates whatever vulnerability data is already present on packages and must not silently trigger external matcher calls.
- **Record architecture decisions in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).**
- **Prefer `internal/`.** Add new packages inside `internal/` unless there is a clear public API need.
- **Standard library + Cobra + existing deps only.** Do not add new dependencies without discussion.

## Code Conventions

### Errors
```go
return fmt.Errorf("operation context: %w", err)  // always wrap with context
```
No panics in normal flow. Only `log.Fatal` in `cmd/bomly/main.go`.

### Logging (Zap)
```go
logger.Debug("osv: fetching vuln", zap.String("id", id))
logger.Info("auditor: found findings", zap.Int("count", n))
logger.Warn("cache miss", zap.Error(err))
```
- Loggers may be `nil` — always nil-check or use `zap.NewNop()` as the zero value.
- Prefer compact one-line messages with `fmt.Sprintf(...)` when a log only needs one or two fields.
- Prefer structured zap fields when a log carries several values or benefits from a machine-readable context.
- Log **everything** relevant, but aggregate cache/API activity at the operation level by default. Prefer one summary log for a cache pass, API batch, or enrichment run over per-package hit/miss/request logs unless an individual item is required to explain a warning or error.
- No PII, no tokens, no credentials.

### Caching (`internal/matchers/cache`, `internal/licenses/cache`)
```go
cache, _ := audcache.NewFileCache(dir, 24*time.Hour)
key := audcache.NewKey(purl, name, ecosystem, version)  // SHA256
if v, ok := audcache.Get[T](cache, key); ok { ... }
_ = audcache.Set(cache, key, value)
```
License matchers use the same API shape from `internal/licenses/cache`.
Cache failures are **non-fatal** — log a warning and continue without caching.

### Detector / Auditor Pattern
- Implement `detectors.Detector` for concrete detectors, or `scan.Auditor` / `scan.Matcher` for audit and license stages.
- Detectors may implement `ReadyDetector`, `ApplicableDetector`, and `InstallFirstDetector`; auditors and matchers have parallel `Ready*` / `Applicable*` hooks.
- Register built-ins in `internal/registry/builder.go`, which wires concrete detectors, auditors, matchers, and plugin stages into `scan.Registry`.
- External enrichment is matcher-based; see `internal/matchers/depsdev`, `internal/matchers/clearlydefined`, `internal/matchers/osv`, `internal/matchers/grype`, and `internal/matchers/eol`.
- Priority order (lower = higher priority): native → lockfile-parser → third-party → plugin.

### Terminal Output
- Use `internal/cli/ansi.go` helpers (`ansiStyled`, `ansiWrap`, `stripANSI`) — never raw escape codes inline.
- Interactive TUI uses Bubbletea (`internal/cli/interactive.go`) with the `interactiveModel` interface.
- SARIF output via `internal/output` — do not hand-craft SARIF JSON.

### Plugin Execution
```sh
BOMLY_PROTOCOL=v1
BOMLY_CORE_VERSION=<semver>
BOMLY_CWD=<absolute path>
BOMLY_CONFIG=<path>
```
Core passes these env vars. Plugin discovery: `~/.bomly/plugins/bomly-*` overrides `PATH`.

## Quality Bar

- Every exported type/function has a doc comment.
- Unit tests for new logic; integration tests for new commands.
- Test helpers: `t.TempDir()`, `testutil.BuildGoBinary()`, `httptest.NewServer()`.
- Generated docs are part of the contract: update `docs/CONFIG_REFERENCE.md`, `docs/schemas/*`, and `docs/SUPPORT_MATRIX.md` via `make generate` when their source packages change.
- Fake binaries (npm, go, gradle, plugin) are built in `TestMain` — see `internal/cli/root_test_main_test.go`.
- No test conditionally skipped without a recorded reason.

## Reference Docs

| Doc | Covers |
|-----|--------|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Full architecture: pipeline, detectors, auditors, plugins, trust model, decision log |
| [`docs/CONFIG_REFERENCE.md`](docs/CONFIG_REFERENCE.md) | Generated config reference (all keys, env vars, defaults) |
| [`docs/SUPPORT_MATRIX.md`](docs/SUPPORT_MATRIX.md) | Ecosystem detector coverage |
| `docs/schemas/*.json`, `docs/schemas/*.md` | Generated JSON schemas and human-readable output docs for `scan`, `diff`, and `explain` |
| [`docs/PLUGIN_GUIDE.md`](docs/PLUGIN_GUIDE.md) | Plugin development guide and JSON envelope protocol |
| [`docs/Specs/v1.0.md`](docs/Specs/v1.0.md) | CLI specification and JSON schemas |
| [`docs/Specs/audit-enrichment.md`](docs/Specs/audit-enrichment.md) | OSV/KEV/SARIF implementation |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Development setup, conventions, testing |

