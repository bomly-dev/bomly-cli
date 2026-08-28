# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Bomly is a **customer-facing, security-sensitive CLI** for dependency intelligence. Audience: professional developers, security managers, and CI workflows. Expect high standards: correct behavior, clear output, full logging, and no panics.

This is the main public repository for the Bomly CLI: the engine, auditors, and native detectors (`internal/*`), the `cmd/bomly` entry point, user documentation (`docs/`), release automation, install scripts, the npm MCP wrapper, and the binary-driven smoke test suite. Two kinds of modules live outside this repository:

- **`github.com/bomly-dev/bomly-sdk`** (public, separate repo): the contract both built-in components and external managed plugins implement — domain types, plugin kinds, validation, support metadata, and the shared helper subpackages (`system`, `filecache`, `logkit`, `detectorkit`, `matcherkit`, `testkit`). It has its own tests and releases; this repo pins released versions. Any reference to `sdk.<Type>` below means that module. Plugin authors start there, with `docs/PLUGINS.md`, `docs/plugins/`, and the public plugin template repo.
- **`github.com/bomly-dev/bomly-plugin-*`** (public, one repo per component): external-integration components consumed as ordinary pinned Go modules — the four reachability analyzers (`govulncheck`, `jsreach`, `pyreach`, `jvmreach`), the `osv` / `depsdev-license` / `scorecard` / `grype` matchers, and the `syft` detector. Their implementations are NOT under `internal/`; changes to them happen in their repos, and Dependabot bumps the pins here. Auditors and all other detectors are Bomly's own logic and stay in this repository.

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

`go.mod` pins released versions and must not contain `replace` directives on main (CI enforces this), so remote `go install github.com/bomly-dev/bomly-cli/cmd/bomly@latest` stays supported. External component modules (`bomly-plugin-*`) are ordinary pinned dependencies bumped by Dependabot. Local cross-repo development: `go work init . ../bomly-sdk` (never commit `go.work`).

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
| `internal/detectors/*` | Concrete native dependency resolution per ecosystem (gomod, gradle, maven, node, python, sbom); the Syft catch-all detector lives in `bomly-plugin-syft-detector` |
| `bomly-plugin-*` (external modules) | External-integration components consumed as pinned Go modules: enrichment matchers (osv, grype, deps.dev license, scorecard), reachability analyzers (govulncheck, jsreach, pyreach, jvmreach), and the Syft detector; ClearlyDefined and eol run as external matcher plugins; the shared cache lives in `bomly-sdk/filecache` |
| `internal/auditors/*`  | Policy evaluators and audit-only logic (policy, noop)                                             |
| `internal/baseline`    | Portable package-finding baseline codec and audit-integrated policy-status resolver               |
| `internal/remediation` | Canonical vulnerability fix status, version, detector-hint validation, and occurrence suggestions |
| `internal/sbom`        | SBOM codec (SPDX 2.3, CycloneDX)                                                                  |
| `internal/licenseexpr` | SPDX license expression parsing and identifier classification (guards the parser's panics)        |
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

### External component modules (`bomly-plugin-*`)

- Shared helper code (bounded filesystem/subprocess ops, file cache, subprocess logging, detector/matcher helpers, test kit) lives in `bomly-sdk` subpackages: `system`, `filecache`, `logkit`, `detectorkit`, `matcherkit`, `testkit`. Do not reintroduce CLI-internal copies.
- External-integration components — the reachability analyzers (`bomly-plugin-{govulncheck,jsreach,pyreach,jvmreach}-analyzer`), the external enrichment matchers (`bomly-plugin-{osv,depsdev-license,scorecard,grype}-matcher`), and the Syft detector (`bomly-plugin-syft-detector`) — live in their own public repositories and are consumed as ordinary Go modules: `require` entries pinned in root `go.mod`, bumped by Dependabot like any other dependency. Each repo carries its own tests, fuzz targets, and releases.
- Each module's `plugin` package exposes the embedded constructor surface (`Config`/`DefaultConfig`/`New`, or a plain struct literal) plus a `Module()` export for managed plugin execution; `internal/composition` and `internal/registry` construct them exactly like the old in-tree packages. The grype and syft modules carry both build-tag variants — the root build's `bomly_external_syft` / `bomly_external_grype` tags select files inside those modules.
- Auditors and native detectors stay CLI-internal (`internal/auditors/*`, `internal/detectors/*`). New external-integration components start from the public plugin template repo, get their own `bomly-plugin-*` repository, and are wired into `internal/composition` (or `internal/registry` for detectors) as a pinned module.
- Descriptor names are the compatibility contract: goldens, detector aliases, and generated docs key on them, so component repos must not rename descriptors without a coordinated CLI change.

### Package Boundaries

- `internal/detectors/*` must not import `internal/engine` or `internal/registry`. Concrete detectors may depend on `internal/detectors` (name constants), the SDK and its helper subpackages (`system` for bounded filesystem and subprocess operations, `detectorkit` for shared detector helpers), and local helpers.
- Built-in reachability analyzers live in their own `bomly-plugin-*-analyzer` repositories, consumed as pinned Go modules. They depend only on the SDK and its helper subpackages (`system`, `filecache`, `logkit`) and must not import any `internal/*` package.
- `internal/detectors` owns detector-facing contracts such as `Detector`, `DetectorDescriptor`, `ResolveGraphRequest`, and detector helper functions.
- The SDK owns neutral shared identifiers and support metadata that would otherwise create package cycles, including ecosystems, package managers, detector types, and support-matrix data.
- `internal/baseline` owns the baseline document and matching implementation. It depends on the SDK policy contracts and must not be imported by `internal/engine`.
- `internal/remediation` owns canonical vulnerability remediation decisions. Detectors may supply validated read-only strategy hints, but they do not choose final actions or versions.
- `internal/licenseexpr` owns all SPDX license expression parsing. The underlying parser panics on some malformed input, and license strings come from untrusted lockfiles and registry APIs, so no other package under `internal/` may import `github.com/github/go-spdx` directly; `TestNoDirectSPDXExpressionUse` enforces this.
- `internal/registry` owns package-manager discovery, support lookups, and built-in registry wiring in `internal/registry/builder.go`. Do not create or reintroduce a separate `registrybuilder` package.
- `internal/engine` may import `internal/detectors` and `internal/registry`, but detector packages must not point back into `internal/engine`. Runtime planning, prepared subprojects, and detector-chain reuse belong in `internal/engine`.

## Non-Negotiable

- **Do not add PM installation logic.** Assume package managers exist.
- **Plugin protocol is versioned `v1`.** External plugins use the SDK/HashiCorp gRPC `Metadata` and role descriptor contract.
- **No secrets or credentials in logs.** Ever.
- **Matcher network calls require explicit enrichment.** Built-in matchers may contact OSV (`https://api.osv.dev`), CISA KEV, deps.dev (`https://api.deps.dev`), OpenSSF Scorecard (`https://api.scorecard.dev`), and Grype's database service (`https://grype.anchore.io/databases`, plus the archive URL it returns) only during `--enrich`. Installed external matcher plugins such as ClearlyDefined and endoflife.date may contact their documented services during `--enrich`. `--audit` evaluates existing package data and must not trigger matcher calls. Remote Git targets and build-tool detectors have separate, explicit network behavior.
- **Record architecture decisions as ADRs in [`dev-docs/adr/`](dev-docs/adr/README.md).** Copy [`dev-docs/adr/TEMPLATE.md`](dev-docs/adr/TEMPLATE.md), take the next number, and add a row to the index. `dev-docs/ARCHITECTURE.md` stays the architecture narrative; `docs/ARCHITECTURE.md` is the public, user-facing overview.
- **Prefer `internal/`.** Add new packages inside `internal/` unless there is a clear public API need; genuinely public contract surface belongs in the SDK module.
- **Standard library + Cobra + existing deps only.** Do not add new dependencies without discussion.

## Code Conventions

### Fix at the right depth

When the same defect can recur at more than one call site, centralize the rule
instead of patching the sites. A fix that has to be remembered will be forgotten,
and the next occurrence is found by a reviewer or a user rather than by the
codebase.

In practice:

- **Two occurrences of one defect is the signal.** The first is a bug; the
  second says the rule has no home. Give it one — a named helper, a shared
  entry point, or an invariant enforced where the data is created — and route
  every site through it.
- **Name the concept, not the mechanics.** `detectors.EnsureNode(g, node)`
  says what the caller is doing — insert or return the existing node; a
  hand-written lookup-then-insert at each site says only what to type, and
  each copy decides duplicate handling differently.
- **Add a guard when the rule can be bypassed by writing it out by hand.**
  `TestNodeInsertionGoesThroughTheSharedHelper` fails if a lookup-then-insert
  reappears anywhere under `internal/`, and `TestExportNeverReadsResolvedURL`
  fails if the export layer touches raw manifest values. A guard is cheap next
  to the review round it replaces.
- **The deepest home for shared meaning is the SDK (ADR-0040).** When a fix
  or feature touches what a shared domain object *means* — identity,
  coordinates, PURLs, licenses, SBOM assertions, graph or merge semantics,
  validation gates — it lands in `bomly-dev/bomly-sdk` first and this repo
  consumes the new release. CLI-level is presentation, command surface, and
  orchestration (how Bomly *uses* the model); plugin-level is one external
  tool's integration specifics. "Only the CLI needs this today" is not a
  reason to keep model behavior local — a single consumer is how every
  drifted copy started. If the release schedule genuinely cannot absorb the
  SDK-first ordering, ship the local fix with the SDK issue already filed
  and linked from the code.
- **Say so when you decline.** If centralizing is genuinely out of scope for
  the change in hand, record why in an ADR under `dev-docs/adr/` and what the
  durable fix would be, so the next person inherits the reasoning rather than
  the symptom.


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
- External enrichment is matcher-based; the osv, deps.dev license, scorecard, and grype matchers live in their own `bomly-plugin-*-matcher` repositories, and ClearlyDefined and endoflife.date run as external matcher plugins.
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
- `dev-docs/ARCHITECTURE.md`: update the pipeline diagram if the stage list changed; keep the public `docs/ARCHITECTURE.md` overview in sync when stages change. Add an ADR under `dev-docs/adr/` for non-obvious design choices (copy `TEMPLATE.md`, next number, index row).
- `CLAUDE.md` and `AGENTS.md`: update the architecture tree and package-boundary list when introducing a new internal package.

## Release

Draft releases are created automatically after merges to `main` from commit prefixes: `feat:` → minor, other → patch, `type!:`/`BREAKING CHANGE:` → major, `[skip release]` → none. Squash titles count. Publishing runs GoReleaser with signed checksums and SLSA provenance; see `dev-docs/RELEASE_CHECKLIST.md`.

## Reference Docs

| Doc                                                    | Covers                                                                                  |
|--------------------------------------------------------|-----------------------------------------------------------------------------------------|
| [`dev-docs/ARCHITECTURE.md`](dev-docs/ARCHITECTURE.md) | Full architecture: pipeline, detectors, auditors, plugins, trust model                  |
| [`dev-docs/adr/`](dev-docs/adr/README.md)              | Architecture decision records — one file per decision, plus template and index          |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)         | Public, user-facing architecture overview                                               |
| [`dev-docs/MODELS.md`](dev-docs/MODELS.md)             | Domain model reference: Dependency, Package, Vulnerability, Finding, PackageRegistry    |
| [`dev-docs/CI.md`](dev-docs/CI.md)                     | CI setup and workflow (GitHub Actions)                                                  |
| [`docs/CONFIG_REFERENCE.md`](docs/CONFIG_REFERENCE.md) | Generated config reference (all keys, env vars, defaults)                               |
| [`docs/SUPPORT_MATRIX.md`](docs/SUPPORT_MATRIX.md)     | Ecosystem detector coverage                                                             |
| `docs/schemas/*.json`, `docs/schemas/*.md`             | Generated JSON schemas and human-readable output docs for `scan`, `diff`, and `explain` |
| [`CONTRIBUTING.md`](CONTRIBUTING.md)                   | Development setup, conventions, testing                                                 |
