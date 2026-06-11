# Agent Instructions — Bomly CLI

Bomly is a **customer-facing, security-sensitive CLI** for dependency intelligence. Audience: professional developers, security managers, and CI workflows. Expect high standards: correct behavior, clear output, full logging, and no panics.

## Build & Test

```sh
make build               # build both `bin/bomly` (builtin Syft/Grype) and `bin/bomly-lite`
make build-lite          # go build -tags "bomly_external_syft,bomly_external_grype" -o bin/bomly-lite ./cmd/bomly
make test                # go test ./...
make smoke               # end-to-end smoke tests against real repos/containers (slow, needs network)
make smoke ARGS="-update" # regenerate golden files for smoke tests
make benchmark           # run the hidden local dependency-graph benchmark
make benchmark-report    # analyze local benchmark artifacts with Copilot CLI
make run ARGS="scan"    # go run ./cmd/bomly <ARGS>
make generate            # regenerate config reference, JSON schemas, schema docs, and support matrix
```

Always run `make test` after changes. All tests must pass before marking work is done.
If you change `internal/cli/config.go`, `internal/output/*`, `sdk/catalog.go`, `sdk/support_matrix.go`, or `internal/registry/support.go`, also run `make generate`.

### Git Worktrees

Development may happen inside Git worktrees. Always run commands in the active worktree directory.
Do not assume the primary checkout path; use paths relative to the current worktree.
Avoid destructive Git operations that can affect sibling worktrees or shared refs.
Worktrees should be created inside `.github/worktrees/` (mirroring the `.claude/worktrees/` convention).

## Architecture

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for full detail. Component map:

| Package                | Role                                                                                              |
|------------------------|---------------------------------------------------------------------------------------------------|
| `cmd/bomly`            | Entry point — calls `internal/cli.Execute()`                                                      |
| `internal/cli`         | Cobra root + all commands (`scan`, `explain`, `diff`, `plugin`, `version`)                        |
| `sdk`       | Unified domain types: `Dependency` (detection graph nodes), `Package` (PURL-keyed matching artifacts in `PackageRegistry`), `Vulnerability` (OSV-aligned), reference-style `Finding`, plus neutral package/ecosystem/support identifiers. See `docs/MODELS.md`. |
| `internal/detectors`   | Detector contracts, descriptors, requests/results, and detector-only helpers                      |
| `internal/engine`      | Pipeline, engine, consolidation, auditors, matchers, and orchestration                            |
| `internal/registry`    | Canonical support/discovery registry and built-in engine registry wiring                          |
| `internal/detectors/*` | Concrete dependency resolution per ecosystem (gomod, gradle, maven, node, python, sbom, syft)     |
| `internal/matchers/*`  | External enrichment matchers and shared matcher cache (osv, grype, deps.dev, ClearlyDefined, eol, scorecard) |
| `internal/auditors/*`  | Policy evaluators and audit-only logic (policy, noop)                                             |
| `internal/sbom`        | SBOM codec (SPDX 2.3, CycloneDX)                                                                  |
| `internal/benchmark`   | Hidden local dependency-graph benchmark, baseline comparison, scoring, and embedded presets       |
| `internal/output`      | Output rendering plus structured command payloads and schema generation for `scan`, `diff`, `explain`, JSON, and SARIF 2.1.0 |
| `internal/plugin`      | Plugin discovery, protocol, handshake, and execution                                              |
| `internal/engine/diff` | Diff pipeline orchestration and audit delta classification                                        |
| `internal/engine/explain` | Dependency path traversal (`explain` command)                                                  |
| `internal/engine/scan` | Scan command pipeline API                                                                         |
| `internal/matchers`    | External enrichment matchers plus shared matcher cache and enrichment helpers                     |
| `internal/logging`     | Zap console wrapper                                                                               |
| `internal/testutil`    | Test helpers (fake binary builder)                                                                |
| `internal/system`      | OS-level helpers                                                                                  |

Scan pipeline: `runtimePreparation → subprojectDiscovery → detect (per-package-manager chains; resolve + consolidate into one graph) → scopeFilter → match (license enrichment on the consolidated graph) → audit → format`. Consolidation is the tail of the detect stage, not a separate stage.

Runtime preparation is owned by `internal/engine`: build the filtered registry once, index the execution target with that same registry, and reuse the prepared runtime for `scan`, `diff`, `explain`, license enrichment, and auditing. The CLI resolves raw execution targets and flags, but it must not discover subprojects with a separate registry.

`bomly explain` is implemented by `newExplainCmd` in `internal/cli/explain_cmd.go`.

### Package Boundaries

- `internal/detectors/*` must not import `internal/engine` or `internal/registry`. Concrete detectors depend on `internal/detectors`, `sdk`, and local helpers only.
- `internal/detectors` owns detector-facing contracts such as `Detector`, `DetectorDescriptor`, `ResolveGraphRequest`, and detector helper functions.
- `sdk` owns neutral shared identifiers and support metadata that would otherwise create package cycles, including ecosystems, package managers, detector types, and support-matrix data.
- `internal/registry` owns package-manager discovery, support lookups, and built-in registry wiring in `internal/registry/builder.go`. Do not create or reintroduce a separate `registrybuilder` package.
- `internal/engine` may import `internal/detectors` and `internal/registry`, but detector packages must not point back into `internal/engine`. Runtime planning, prepared subprojects, and detector-chain reuse belong in `internal/engine`.

## Non-Negotiable

- **Do not add PM installation logic.** Assume package managers exist.
- **Plugin protocol is versioned `v1`.** External plugins use the SDK/HashiCorp gRPC `Metadata` and role descriptor contract.
- **No secrets or credentials in logs.** Ever.
- **Network calls only when explicitly triggered.** OSV (`https://api.osv.dev`), CISA KEV, ClearlyDefined (`https://api.clearlydefined.io`), deps.dev (`https://api.deps.dev`), endoflife.date (`https://endoflife.date`), and OpenSSF Scorecard (`https://api.scorecard.dev`) are permitted only during explicit enrichment (`--enrich`). `--audit` evaluates whatever vulnerability data is already present on packages and must not silently trigger external matcher calls.
- **Record architecture decisions in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).**
- **Prefer `internal/`.** Add new packages inside `internal/` unless there is a clear public API need.
- **Standard library + Cobra + existing deps only.** Do not add new dependencies without discussion.

## Code Conventions

### Shared Types

- Use canonical shared types directly instead of creating local type aliases or re-exported constants just to rename them. For example, if `internal/output.Format` owns CLI output formats, downstream packages should store and compare `output.Format` / `output.FormatJSON` directly rather than introducing `render.OutputFormat` aliases.

### Errors

```go
return fmt.Errorf("operation context: %w", err)  // always wrap with context
```

No panics in normal flow. Only process-exit handling in `cmd/bomly/main.go`.

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

### Caching (`internal/matchers/cache`)

```go
cache, _ := audcache.NewFileCache(dir, 24*time.Hour)
key := audcache.NewKey(purl, name, ecosystem, version)  // SHA256
if v, ok := audcache.Get[T](cache, key); ok { ... }
_ = audcache.Set(cache, key, value)
```

License and vulnerability matchers share the same cache API from `internal/matchers/cache`.
Cache failures are **non-fatal** — log a warning and continue without caching.

### Detector / Auditor Pattern

- Implement `detectors.Detector` for concrete detectors, or `engine.Auditor` / `engine.Matcher` for audit and license stages.
- Detectors may implement `ReadyDetector`, `ApplicableDetector`, and `InstallFirstDetector`; auditors and matchers have parallel `Ready*` / `Applicable*` hooks.
- Register built-ins in `internal/registry/builder.go`, which wires concrete detectors, auditors, matchers, and plugin stages into `engine.Registry`.
- External enrichment is matcher-based; see `internal/matchers/depsdev`, `internal/matchers/clearlydefined`, `internal/matchers/osv`, `internal/matchers/grype`, `internal/matchers/eol`, and `internal/matchers/scorecard`.
- Detector chains are explicit in `internal/registry/support.go` and `internal/registry/builder.go`; do not infer priority from technique alone.
- Some native detectors are build-tool-backed primaries (`pub-native`, `swiftpm-native`, `sbt-native`) with committed-file fallbacks. Run smoke tests and the local benchmark with `dart`, `swift`, or `sbt` on `PATH` before updating graph-shape expectations for those ecosystems.

### Terminal Output

- Use `internal/cli/render/ansi.go` helpers (`Style`, `Wrap`, `StripANSI`) — never raw escape codes inline.
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
- Fake binaries (npm, go, Gradle, plugin) are built in `TestMain` — see `internal/cli/root_test_main_test.go`.
- No test conditionally skipped without a recorded reason.

## Feature Checklist

When adding a new user-visible feature (new CLI flag, new component class, new pipeline stage, new analyzer, etc.), walk this checklist before requesting review. The surfaces forgotten most often are **MCP**, **plugin command**, and **smoke test**.

### CLI surface

- Flag declared in `internal/cli/opts/flag_options.go` with override propagation in `applyFlagOverrides`.
- Config field added to `internal/config/config.go` `Resolved` (with `doc:`/`env:`/`default:` tags) and the appropriate nested `File` leaf (with `yaml:`, `resolved:`, and legacy flat-key `legacy:` tags plus a pointer-backed shape).
- Flag interactions (requires / conflicts / modifies semantics) get a check in `config.Validate` plus a unit test in `internal/config/validate_test.go`. Error messages must be actionable (`"--audit requires --enrich"`, not `"invalid combination"`).
- If the flag drives a pipeline stage, propagate the value through `internal/cli/opts/options.go`'s `PipelineRequest` builder.
- If the flag accepts a selector list, register an `available<Thing>Options` helper in `flag_options.go` for shell completion.

### MCP

Every new flag on `bomly scan` / `bomly explain` / `bomly diff` must be reachable from the matching MCP tool. AI agents won't get the feature otherwise.

- Add the field to `ScanRequest` / `ExplainRequest` / `DiffRequest` in `internal/mcp/server.go`.
- Register the `mcplib.WithBoolean` / `WithString` argument in `tool_scan.go` / `tool_explain.go` / `tool_diff.go`. Mirror the CLI flag's help text and call out any prerequisite ("requires enrich").
- Wire the field through `mcpOptionsAdapter` in `internal/cli/mcp_cmd.go`. Add it to the `mcpOverrides` struct (so future additions stay one-line) and apply it in `cloneWithOverrides`.

### Plugin command

When adding a new component class (a new sibling of Detector / Matcher / Auditor / Analyzer):

- Add a `PluginKind*` constant in `sdk/plugin.go` and accept it in `sdk/validate.go::ValidateMetadata`.
- Add the descriptor pointer to `internal/plugin/types.go::Manifest` plus a `clone<Kind>Descriptor` helper that deep-copies every slice field.
- In `internal/cli/plugin_cmd.go`:
  - Extend `pluginKindFilter` and add a `--<kind>s` filter flag.
  - Iterate the new descriptors in `builtInPluginInfos`; emit one `PluginInfo` per registered instance.
  - Add a `<kind>PluginInfo` constructor and the matching local clone helper.
  - Extend `pluginInfoEcosystems`, `pluginInfoPackageManagers`, and `pluginInfoFeatures` with the new case.
  - Add a new section to `renderPluginListTables` with sensible columns. If the descriptor exposes axes the existing kinds don't (e.g. analyzers have `SupportedLanguages`), add new columns and corresponding `pluginInfo<X>` / `join<X>` helpers.
  - Update `renderPluginInfo` to emit any new lines when present.

External plugin install/load (gRPC handshake, runtime descriptor fetch) is a separate, larger change and can land in a follow-up PR. Built-in listing is the minimum bar.

### Logging

Analyzers, matchers, auditors, and any new long-running stage must be observable at `-v` (INFO) and debuggable at `-vv` (DEBUG):

- **INFO** at natural boundaries: stage start (with key inputs — module count, item count, runner name, cache enabled), per-major-unit completion (cache hit/miss, counts per outcome, duration), final summary (totals, overall duration).
- **DEBUG** for low-level detail: discovered inputs (module roots, manifest paths), exact command lines including args and working dir, cache key components, byte counts of subprocess output, branch decisions worth reproducing.
- **WARN** for recoverable errors (analyzer failed, cache write failed). Never abort the pipeline for these; degrade and continue.

When invoking subprocesses, the DEBUG line MUST include the binary path, args, and working dir so a user with `-vv` can copy/paste the command to reproduce outside Bomly.

### Caching

If a new analyzer / matcher / detector produces deterministic output for a fixed `(input, schema version)` pair, wrap it with `internal/matchers/cache.FileCache`:

- Cache key folds: schema version (so we can bump and invalidate), input fingerprint (lockfile content hash), runtime version when the underlying tool is sensitive to it, and the runner name when multiple implementations exist.
- Default location: `~/.cache/bomly/<area>/<subarea>/`.
- Default TTL: 24h (matches OSV / EOL).
- Cache failures are non-fatal — log a warning and proceed.
- Expose `CacheDir`, `CacheTTL`, and `DisableCache` fields on the component for tests + opt-out.

### Smoke tests

- Use a **real public repo** pinned to a specific tag or commit SHA via `--url --ref`. Do not add local Go modules / npm packages / etc. under `test/smoke/testdata/`. The only acceptable testdata files are SBOM fixtures and similar non-project inputs.
- The pinned ref must exercise the feature meaningfully. For reachability that means a repo with at least one symbol-tier reachable advisory; for a new ecosystem detector that means a repo whose lockfile actually parses.
- Update `test/smoke/helpers_test.go::normalizeJSON` (or the more specific normalizers it calls) to scrub any new volatile fields (timestamps, line numbers, file paths under temp clone dirs) before they reach goldens.
- Run `make smoke ARGS="-update"` to regenerate goldens. Commit the regenerated `.golden.json` in the same PR.

### Documentation

- `make generate` regenerates `docs/CONFIG_REFERENCE.md`, `docs/schemas/*`, and `docs/SUPPORT_MATRIX.md` from struct tags. Run it whenever `internal/config/config.go`, `internal/output/*`, or `sdk/catalog.go` / `sdk/support_matrix.go` change.
- Add or update a feature page under `docs/` (e.g. `docs/REACHABILITY.md`) with quick-start usage, semantics, ecosystem coverage, output shape, and limitations. Be explicit about safety caveats (e.g. "tier-3 unreachable does not mean safe").
- `docs/ARCHITECTURE.md`: update the pipeline diagram if the stage list changed; add a decision-log entry for non-obvious design choices.
- `CLAUDE.md` and `AGENTS.md`: update the architecture tree and package-boundary list when introducing a new internal package.

## Reference Docs

| Doc                                                    | Covers                                                                                  |
|--------------------------------------------------------|-----------------------------------------------------------------------------------------|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)         | Full architecture: pipeline, detectors, auditors, plugins, trust model, decision log    |
| [`docs/MODELS.md`](docs/MODELS.md)                     | Domain model reference: Dependency, Package, Vulnerability, Finding, PackageRegistry    |
| [`docs/CI.md`](docs/CI.md)                             | CI setup and workflow (GitHub Actions)                                                  |
| [`docs/CONFIG_REFERENCE.md`](docs/CONFIG_REFERENCE.md) | Generated config reference (all keys, env vars, defaults)                               |
| [`docs/SUPPORT_MATRIX.md`](docs/SUPPORT_MATRIX.md)     | Ecosystem detector coverage                                                             |
| `docs/schemas/*.json`, `docs/schemas/*.md`             | Generated JSON schemas and human-readable output docs for `scan`, `diff`, and `explain` |
| [`CONTRIBUTING.md`](CONTRIBUTING.md)                   | Development setup, conventions, testing                                                 |
