# Contributing to Bomly

By participating in this project you agree to abide by the Bomly
[Code of Conduct](https://github.com/bomly-dev/.github/blob/main/CODE_OF_CONDUCT.md).
To report a security vulnerability, follow the
[Security Policy](https://github.com/bomly-dev/.github/blob/main/SECURITY.md)
rather than opening a public issue.

## Development Setup

### Prerequisites

- Go toolchain matching the version declared in `go.mod`
- `make`
- Optional: `syft` and `grype` binaries on `PATH` for external-mode testing

### Build

```bash
make build
make build-lite
make test
make run ARGS="scan"
```

### Build Tags

| Tag | Effect |
| --- | --- |
| `bomly_external_syft` | Use the external `syft` CLI instead of the builtin Syft library |
| `bomly_external_grype` | Use the external `grype` CLI instead of the builtin Grype library |

Without these tags, Bomly builds the default full CLI with builtin Syft and Grype support. `make build-lite` uses the external-mode tags for the smaller alternate binary.

### Repository Layout

```text
cmd/bomly/                  CLI entry point
internal/cli/               Commands, config loading, progress, help
internal/engine/            Runtime preparation, orchestration, consolidation
internal/engine/diff/       Diff orchestration and audit deltas
internal/engine/explain/    Dependency path explanation
internal/engine/scan/       Scan command pipeline API
internal/detectors/         Ecosystem-specific dependency resolution
internal/matchers/          External enrichment matchers and shared matcher cache
internal/analyzers/         Reachability analyzers (govulncheck, jsreach, pyreach, jvmreach)
internal/auditors/          Policy evaluation and finding creation
internal/output/            Text, JSON, SARIF rendering and structured response payloads
internal/sbom/              SPDX and CycloneDX encoding and decoding
internal/registry/          Canonical support and discovery registry
internal/plugin/            Managed external plugins (install, verify, run)
docs/                       Public reference documentation
```

## Code Conventions

### Errors

Always wrap errors with context:

```go
return fmt.Errorf("operation context: %w", err)
```

No panics in normal flow. Only process-exit handling is allowed in `cmd/bomly/main.go`.

### Logging

Use Zap structured logging:

```go
logger.Debug("osv: fetching vuln", zap.String("id", id))
logger.Info("auditor: found findings", zap.Int("count", n))
logger.Warn("cache miss", zap.Error(err))
```

- Loggers may be `nil` - always nil-check or use `zap.NewNop()` as the zero value.
- Prefer one summary log for batch operations over per-item logs.
- Do not log PII, tokens, or credentials.

### Terminal Output

- Use `internal/cli/ansi.go` helpers - never inline raw escape codes.
- Interactive TUI code lives in `internal/cli/interactive.go`.
- SARIF output must go through `internal/output`.

### New Packages

- Prefer `internal/` unless there is a clear public API need.
- Use the standard library, Cobra, and existing dependencies unless a new dependency has been discussed first.

## Testing

### Expectations

- Add unit tests for new logic.
- Add integration tests for new commands and user-visible flows.
- Run `make test` before considering work complete.
- Run `make smoke` if you touched a detector chain, matcher, auditor, or analyzer.
- If you change GitHub Actions workflows or release behavior, update [docs/development/CI.md](docs/development/CI.md) and any affected install guidance in [README.md](README.md).

### Helpers

- `t.TempDir()` for temporary directories
- `testutil.BuildGoBinary()` for fake binaries
- `httptest.NewServer()` for HTTP mocking
- `internal/cli/root_test_main_test.go` for shared fake-binary setup

### Skip Policy

Do not add skipped tests without a recorded reason.

## Documentation

User-facing docs live in [`docs/`](docs/). Most pages are handwritten; some are generated.

Run `make generate` after changing any of:

- `internal/config/config.go` — regenerates `docs/CONFIG_REFERENCE.md`
- `sdk/catalog.go`, `sdk/support_matrix.go`, `internal/registry/support.go` — regenerates `docs/SUPPORT_MATRIX.md` and `docs/detectors/ecosystems/*.md`
- `internal/output/*` or scan/explain/diff response types — regenerates `docs/schemas/*.md`
- `internal/support/component_docs.go` — regenerates `docs/{DETECTORS,MATCHERS,AUDITORS}.md` and `docs/matchers/*.md`

For per-detector and per-matcher prose (Phase 2 hybrid generation), add a Markdown file under `internal/support/prose/{detectors,matchers}/<name>.md` and re-run `make generate`. The generator embeds the prose between the structured fact table and the auto-generated banner.

## Release Bumps

Bomly creates draft releases automatically after merges to `main`. The release workflow reads commit messages since the last `vX.Y.Z` tag and chooses the next version from the final merge history.

| Desired outcome | Commit message pattern | Example | Result |
| --- | --- | --- | --- |
| Skip release | Include `[skip release]` in the head commit message | `docs: update README [skip release]` | No version bump, tag, or release |
| Patch release | Any non-breaking commit that is not `feat:` | `fix: handle empty SBOM input` | `0.2.3` -> `0.2.4` |
| Minor release | `feat:` or `feat(scope):` | `feat: add npm workspace detection` | `0.2.3` -> `0.3.0` |
| Major release | `type!:` or `BREAKING CHANGE:` | `feat!: change JSON output schema` | `0.2.3` -> `1.0.0` |

If a PR is squash-merged, the squash commit title and body are the important inputs. Before merging, make sure the final message contains the intended `feat:`, `feat!:`, `BREAKING CHANGE:`, or `[skip release]` marker.

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the scan pipeline, runtime model, and package boundaries.

## Non-Negotiables

- Do not add package-manager installation logic.
- Do not emit secrets or credentials in logs.
- Only make network-backed matcher calls when explicitly triggered by `--enrich`. `--audit` should evaluate existing package vulnerability data and must not silently trigger external enrichment.
