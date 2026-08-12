# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Bomly is a **customer-facing, security-sensitive CLI** for dependency intelligence. Audience: professional developers, security managers, and CI workflows. Expect high standards: correct behavior, clear output, full logging, and no panics.

This is the single public repository for the Bomly CLI: the full implementation (`internal/*`), the `cmd/bomly` entry point, user documentation (`docs/`), release automation, install scripts, the npm MCP wrapper, and the binary-driven smoke test suite. One module lives outside this repository:

- **`github.com/bomly-dev/bomly-sdk`** (public, separate repo): the contract both built-in components and external managed plugins implement — domain types, plugin kinds, validation, support metadata. It has its own tests and releases; this repo pins released versions (pseudo-versions only during coordinated cross-repo changes). Any reference to `sdk.<Type>` below means that module. Plugin authors start there, with `docs/PLUGINS.md`, `docs/plugins/`, and the public plugin template repo.

## Build & Test

```sh
make build               # build both `bin/bomly` (builtin Syft/Grype) and `bin/bomly-lite`
make build-lite          # go build -tags "bomly_external_syft,bomly_external_grype" -o bin/bomly-lite ./cmd/bomly
make test                # go test ./...
make smoke               # end-to-end tests driving the built binary (slow, requires network)
make smoke ARGS="-update" # regenerate smoke golden files
make fuzz FUZZTIME=5s    # run every registered fuzz target with a short per-target budget
make benchmark           # run the hidden local dependency-graph benchmark
make benchmark-report    # analyze local benchmark artifacts with Copilot CLI
make evidence            # verify the public evidence catalog (test/evidence/cases.json)
make run ARGS="scan"    # go run ./cmd/bomly <ARGS>
make generate            # regenerate config reference, JSON schemas, schema docs, support matrix, and component docs (binary-driven)
```

Always run `make test` after changes. All tests must pass before marking work is done.
If you change `internal/cli/config.go`, `internal/output/*`, or `internal/registry/support.go`, or bump the pinned `bomly-dev/bomly-sdk` version (its catalog or support-matrix data feeds the generated docs), also run `make generate` and commit the docs drift.

`go.mod` pins released versions and must not contain `replace` directives on main (CI enforces this). The committed `go.work` lists in-repo modules only (root now; `components/*` as waves land). Local cross-repo SDK development: `go work use ../bomly-sdk` (never commit that entry).

### Git Worktrees

Development may happen inside Git worktrees. Always run commands in the active worktree directory.
Do not assume the primary checkout path; use paths relative to the current worktree.
Avoid destructive Git operations that can affect sibling worktrees or shared refs.

## Architecture

See [`dev-docs/ARCHITECTURE.md`](dev-docs/ARCHITECTURE.md) for full detail (the public overview is [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)). Component map:

| Package                | Role                                                                                              |
|------------------------|---------------------------------------------------------------------------------------------------|
| `cmd/bomly`            | Entry point — calls `internal/cli.Execute()`                                                      |
| `internal/cli`         | Cobra root + all commands (`scan`, `explain`, `diff`, `plugin`, `version`)                        |
| `sdk` (external module) | Unified domain types: `Dependency` (detection graph nodes), `Package` (PURL-keyed matching artifacts in `PackageRegistry`), `Vulnerability` (OSV-aligned), reference-style `Finding`, plus neutral package/ecosystem/support identifiers. See `dev-docs/MODELS.md`. |
| `internal/detectors`   | Detector contracts, descriptors, requests/results, and detector-only helpers                      |
| `internal/engine`      | Pipeline, engine, consolidation, auditors, matchers, and orchestration                            |
| `internal/registry`    | Canonical support/discovery registry and built-in engine registry wiring                          |
| `internal/detectors/*` | Concrete dependency resolution per ecosystem (gomod, gradle, maven, node, python, sbom, syft)     |
| `internal/matchers/*`  | External enrichment matchers (osv, grype, deps.dev, scorecard; ClearlyDefined and eol run as external matcher plugins); the shared cache lives in `bomly-sdk/filecache` |
| `internal/auditors/*`  | Policy evaluators and audit-only logic (policy, noop)                                             |
| `internal/analyzers/*` | Built-in reachability analyzers (govulncheck, jsreach)                                            |
| `internal/baseline`    | Portable package-finding baseline codec and audit-integrated policy-status resolver               |
| `internal/remediation` | Canonical vulnerability fix status, version, detector-hint validation, and occurrence suggestions |
| `internal/sbom`        | SBOM codec (SPDX 2.3, CycloneDX)                                                                  |
| `internal/benchmark`   | Hidden local dependency-graph benchmark, baseline comparison, scoring, and embedded presets       |
| `internal/output`      | Output rendering plus structured command payloads and schema generation for `scan`, `diff`, `explain`, JSON, and SARIF 2.1.0 |
| `internal/plugin`      | Plugin discovery, protocol, handshake, and pooled subprocess execution                            |
| `internal/composition` | Build-variant composition: wires the full (builtin Syft/Grype) and lite component sets            |
| `internal/engine/diff` | Diff pipeline orchestration and audit delta classification                                        |
| `internal/engine/explain` | Dependency path traversal (`explain` command)                                                  |
| `internal/engine/scan` | Scan command pipeline API                                                                         |
| `internal/logging`     | Zap console wrapper (subprocess logging helpers live in `bomly-sdk/logkit`)                       |
| `internal/support`     | Docs generation (config reference, schemas, support matrix, component docs) behind the hidden `bomly internal docs-gen` command |

Scan pipeline: `runtimePreparation → subprojectDiscovery (root-only by default; --recursive walks nested dirs) → detect (per-package-manager chains; resolve + consolidate into one graph; detectors may record CI-readiness resolution warnings on manifests) → scopeFilter → match (package enrichment, vulnerability consolidation, and remediation derivation) → analyze (reachability, when --analyze is set) → audit (including finding policy-status resolution) → format`. Consolidation is the tail of the detect stage, and remediation derivation is the tail of enrichment; neither is a separate stage.

Runtime preparation is owned by `internal/engine`: build the filtered registry once, index the execution target with that same registry, and reuse the prepared runtime for `scan`, `diff`, `explain`, license enrichment, and auditing. The CLI resolves raw execution targets and flags, but it must not discover subprojects with a separate registry.

`bomly explain` is implemented by `newExplainCmd` in `internal/cli/explain_cmd.go`.

### Plugin framework

- Component kinds are Detector, Matcher, Auditor, and Analyzer; every built-in implements the same SDK contract an external plugin implements.
- External plugins run through a **pooled subprocess runtime**: one warm subprocess per enabled plugin per command, lazy start, at most one restart on death, always terminated when the command finishes.
- Plugin configuration is **kind-scoped**: `plugins:` config is nested by component kind (detectors / matchers / auditors / analyzers) and keyed by component name; legacy flat plugin-ID keys are accepted with a deprecation warning.
- Per-ecosystem detectors are consolidated packages with host-owned chains — e.g. `internal/detectors/node` hosts the npm/pnpm/yarn/bun sub-detectors, and detector name aliases keep old `--detectors` selections working.
- Build composition lives in `internal/composition` (`composition_full.go` / `composition_lite.go` behind build tags); register new built-ins there and in `internal/registry/builder.go`.

### Component modules (`components/`)

- Shared helper code (bounded filesystem/subprocess ops, file cache, subprocess logging, detector/matcher helpers, test kit) lives in `bomly-sdk` subpackages: `system`, `filecache`, `logkit`, `detectorkit`, `matcherkit`, `testkit`. Do not reintroduce CLI-internal copies.
- Extracted components will live under `components/<kind>/<name>/` as separate Go modules with their own `go.mod`, tagged per module as `components/<kind>/<name>/vX.Y.Z`.
- The committed `go.work` puts the repo in workspace mode for local development; waves add `use ./components/...` entries. Release and pinned builds run with `GOWORK=off` (GoReleaser sets it explicitly; CI's `pinned-build` job verifies the module pins alone still build on pushes to `main`).
- Each extraction wave lands as **one atomic PR**: move the code into its component module, add the `use` entry, and keep the root module compiling in the same change.
- `scripts/release-components.sh` (also `make release-components`) is the release train: component modules version in lockstep with the CLI — after a CLI release tag exists, the script tags every component module at that same version (idempotent; unchanged modules get empty releases by design); `--apply` (ARGS="--apply") creates and pushes the tags and prints the root `go get` pin bumps for the follow-up PR.

### Package Boundaries

- `internal/detectors/*` must not import `internal/engine` or `internal/registry`. Concrete detectors may depend on `internal/detectors` (name constants), the SDK and its helper subpackages (`system` for bounded filesystem and subprocess operations, `detectorkit` for shared detector helpers), and local helpers.
- Built-in analyzers may depend on the SDK and its helper subpackages (`system` for bounded filesystem and subprocess operations, `filecache`, `logkit`), and local helpers. They must not import `internal/engine` or `internal/registry`.
- `internal/detectors` owns detector-facing contracts such as `Detector`, `DetectorDescriptor`, `ResolveGraphRequest`, and detector helper functions.
- The SDK owns neutral shared identifiers and support metadata that would otherwise create package cycles, including ecosystems, package managers, detector types, and support-matrix data.
- `internal/baseline` owns the baseline document and matching implementation. It depends on the SDK policy contracts and must not be imported by `internal/engine`.
- `internal/remediation` owns canonical vulnerability remediation decisions. Detectors may supply validated read-only strategy hints, but they do not choose final actions or versions.
- `internal/registry` owns package-manager discovery, support lookups, and built-in registry wiring in `internal/registry/builder.go`. Do not create or reintroduce a separate `registrybuilder` package.
- `internal/engine` may import `internal/detectors` and `internal/registry`, but detector packages must not point back into `internal/engine`. Runtime planning, prepared subprojects, and detector-chain reuse belong in `internal/engine`.

## Non-Negotiable

- **Do not add PM installation logic.** Assume package managers exist.
- **Plugin protocol is versioned `v1`.** External plugins use the SDK/HashiCorp gRPC `Metadata` and role descriptor contract.
- **No secrets or credentials in logs.** Ever.
- **Matcher network calls require explicit enrichment.** Built-in matchers may contact OSV (`https://api.osv.dev`), CISA KEV, deps.dev (`https://api.deps.dev`), OpenSSF Scorecard (`https://api.scorecard.dev`), and Grype's database service (`https://grype.anchore.io/databases`, plus the archive URL it returns) only during `--enrich`. Installed external matcher plugins such as ClearlyDefined and endoflife.date may contact their documented services during `--enrich`. `--audit` evaluates existing package data and must not trigger matcher calls. Remote Git targets and build-tool detectors have separate, explicit network behavior.
- **Record architecture decisions in [`dev-docs/ARCHITECTURE.md`](dev-docs/ARCHITECTURE.md).** (`docs/ARCHITECTURE.md` is the public, user-facing overview.)
- **Prefer `internal/`.** Add new packages inside `internal/` unless there is a clear public API need; genuinely public contract surface belongs in the SDK module.
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

### Caching (`bomly-sdk/filecache`)

```go
import cache "github.com/bomly-dev/bomly-sdk/filecache"

fc, _ := cache.NewFileCache(dir, 24*time.Hour)
key := cache.NewKey(purl, name, ecosystem, version)  // SHA256
if v, ok := cache.Get[T](fc, key); ok { ... }
_ = cache.Set(fc, key, value)
```

License and vulnerability matchers share the same cache API from `bomly-sdk/filecache`.
Cache failures are **non-fatal** — log a warning and continue without caching.

### Detector / Auditor Pattern

- Implement `detectors.Detector` for concrete detectors, or `engine.Auditor` / `engine.Matcher` for audit and license stages.
- Detectors may implement `ReadyDetector`, `ApplicableDetector`, and `InstallFirstDetector`; auditors and matchers have parallel `Ready*` / `Applicable*` hooks.
- Register built-ins in `internal/registry/builder.go`, which wires concrete detectors, auditors, matchers, and plugin stages into `engine.Registry`.
- External enrichment is matcher-based; see `internal/matchers/depsdev`, `internal/matchers/clearlydefined`, `internal/matchers/osv`, `internal/matchers/grype`, `internal/matchers/eol`, and `internal/matchers/scorecard`.
- Detector chains are explicit in `internal/registry/support.go` and `internal/registry/builder.go`; do not infer priority from technique alone.
- Some native detectors are build-tool-backed primaries (`pub-native`, `swiftpm-native`, `sbt-native`) with committed-file fallbacks. Run the local benchmark and the smoke tests with `dart`, `swift`, or `sbt` on `PATH` before updating graph-shape expectations for those ecosystems.

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
- Test helpers: `t.TempDir()`, `testkit.BuildGoBinary()` (from `bomly-sdk/testkit`), `httptest.NewServer()`.
- Generated docs are part of the contract: update `docs/CONFIG_REFERENCE.md`, `docs/schemas/*`, and `docs/SUPPORT_MATRIX.md` via `make generate` when their source packages change.
- Fake binaries (npm, go, Gradle, plugin) are built in `TestMain` — see `internal/cli/root_test_main_test.go`.
- No test conditionally skipped without a recorded reason.
- Use plain language in documentation and user-facing text. Prefer short, direct sentences; explain necessary technical terms when they first appear.

### Fuzz tests

- Every new or materially changed pure in-process parser for untrusted repository, configuration, baseline, SBOM, plugin, or analyzer data must have a native Go fuzz target. (The SDK's own parsers carry their fuzz targets in the SDK repo.)
- Bound fuzz input before parsing. Use `testkit.MaxFuzzInputSize` (from `bomly-sdk/testkit`) unless the format needs a documented tighter limit.
- Seed valid, malformed, and truncated inputs. Assert that parsing never panics and that repeated parsing has deterministic success or failure; graph producers must also call `testkit.RequireFuzzGraphValid`.
- Register every new fuzz target in `scripts/run-fuzz.sh` so both `make fuzz` and the scheduled `.github/workflows/fuzz.yml` workflow execute it.
- When a parser is command-backed, delegated entirely to the standard library, or otherwise unsuitable for native fuzzing, record the exclusion and reason in `test/assurance/PARSER_FUZZING.md`.
- When fuzz targets or their runner manifest change, run the focused target and `make fuzz FUZZTIME=5s`.

## Smoke tests

Smoke tests (`test/smoke/`, `make smoke`) drive the built binary end-to-end against real public repositories pinned via `--url --ref`:

- Scan cases come from `test/smoke/testdata/scan_targets.json`; keep it in sync with `internal/benchmark/testdata/scan_targets.json` (the benchmark target list) when cases change.
- Pin every scan case's detectors with `--detectors`; normalize volatile fields in `helpers_test.go::normalizeJSON` before goldens.
- Register new tests in both slice matrices (`smoke.yml` and exactly one slice in `update-smoke-goldens.yml`); `go test -run` elements are unanchored regexes — use `$` anchors to keep slice ownership exact.
- `TestExamplePluginFixtureCompiles` runs in `make test` and must keep compiling against the pinned `bomly-dev/bomly-sdk` release; update the fixture source when the SDK contract changes.

## Feature Checklist

When adding a new user-visible feature (new CLI flag, new component class, new pipeline stage, new analyzer, etc.), walk this checklist before requesting review. The surfaces forgotten most often are **MCP**, **plugin command**, and **smoke test**.

If the change adds an input, network client, subprocess, plugin role, output
path, MCP field, or automatically discovered repository file, also complete the
[security assurance review checklist](dev-docs/SECURITY_ASSURANCE.md#review-checklist).

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
- MCP tool responses are compact projections (`internal/mcp/types_compact.go`, schema `mcp/1`), not the CLI JSON documents. If the flag adds response data, decide whether it belongs in the compact shape (respect the size caps and truncation counters) or only in the CLI document.

### Plugin command

When adding a new component class (a new sibling of Detector / Matcher / Auditor / Analyzer):

- Add a `PluginKind*` constant in the SDK's `plugin.go` and accept it in the SDK's `validate.go::ValidateMetadata` (SDK repo change, released and pinned here).
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

If a new analyzer / matcher / detector produces deterministic output for a fixed `(input, schema version)` pair, wrap it with `bomly-sdk/filecache.FileCache`:

- Cache key folds: schema version (so we can bump and invalidate), input fingerprint (lockfile content hash), runtime version when the underlying tool is sensitive to it, and the runner name when multiple implementations exist.
- Default location: `~/.cache/bomly/<area>/<subarea>/`.
- Default TTL: 24h (matches OSV / EOL).
- Cache failures are non-fatal — log a warning and proceed.
- Expose `CacheDir`, `CacheTTL`, and `DisableCache` fields on the component for tests + opt-out.

### Smoke tests

Any new user-visible feature needs a smoke case under `test/smoke/` — follow the golden/normalizer/slice-matrix rules in the Smoke tests section above.

### Documentation

- `make generate` regenerates `docs/CONFIG_REFERENCE.md`, `docs/schemas/*`, `docs/SUPPORT_MATRIX.md`, and the component docs through the built binary. Run it whenever `internal/config/config.go` or `internal/output/*` change, or when the pinned SDK version (catalog / support-matrix data) is bumped.
- Add or update a feature page under `docs/` (e.g. `docs/REACHABILITY.md`) with quick-start usage, semantics, ecosystem coverage, output shape, and limitations. Be explicit about safety caveats (e.g. "tier-3 unreachable does not mean safe").
- `dev-docs/ARCHITECTURE.md`: update the pipeline diagram if the stage list changed; add a decision-log entry for non-obvious design choices. Keep the public `docs/ARCHITECTURE.md` overview in sync when stages change.
- `CLAUDE.md` and `AGENTS.md`: update the architecture tree and package-boundary list when introducing a new internal package.

## Release

Draft releases are created automatically after merges to `main` from commit prefixes: `feat:` → minor, other → patch, `type!:`/`BREAKING CHANGE:` → major, `[skip release]` → none. Squash titles count. Publishing runs GoReleaser with signed checksums and SLSA provenance; see `dev-docs/RELEASE_CHECKLIST.md`.

## Reference Docs

| Doc                                                    | Covers                                                                                  |
|--------------------------------------------------------|-----------------------------------------------------------------------------------------|
| [`dev-docs/ARCHITECTURE.md`](dev-docs/ARCHITECTURE.md) | Full architecture: pipeline, detectors, auditors, plugins, trust model, decision log    |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)         | Public, user-facing architecture overview                                               |
| [`dev-docs/MODELS.md`](dev-docs/MODELS.md)             | Domain model reference: Dependency, Package, Vulnerability, Finding, PackageRegistry    |
| [`dev-docs/CI.md`](dev-docs/CI.md)                     | CI setup and workflow (GitHub Actions)                                                  |
| [`docs/CONFIG_REFERENCE.md`](docs/CONFIG_REFERENCE.md) | Generated config reference (all keys, env vars, defaults)                               |
| [`docs/SUPPORT_MATRIX.md`](docs/SUPPORT_MATRIX.md)     | Ecosystem detector coverage                                                             |
| `docs/schemas/*.json`, `docs/schemas/*.md`             | Generated JSON schemas and human-readable output docs for `scan`, `diff`, and `explain` |
| [`CONTRIBUTING.md`](CONTRIBUTING.md)                   | Development setup, conventions, testing                                                 |
