# Contributing to Bomly

## Development Setup

### Prerequisites

- Go 1.25.8 (pinned in `go.mod`; use that exact toolchain to match CI formatting and build behavior)
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
- If you change GitHub Actions workflows or release behavior, update [docs/CI.md](docs/CI.md) and any affected install guidance in [README.md](README.md).

## Release Bumps

Bomly creates draft releases automatically after merges to `main`. The release workflow reads commit messages since the last `vX.Y.Z` tag and chooses the next version from the final merge history.

| Desired outcome | Commit message pattern | Example | Result |
| --- | --- | --- | --- |
| Skip release | Include `[skip release]` in the head commit message | `docs: update README [skip release]` | No version bump, tag, or release |
| Patch release | Any non-breaking commit that is not `feat:` | `fix: handle empty SBOM input` | `0.2.3` -> `0.2.4` |
| Minor release | `feat:` or `feat(scope):` | `feat: add npm workspace detection` | `0.2.3` -> `0.3.0` |
| Major release | `type!:` or `BREAKING CHANGE:` | `feat!: change JSON output schema` | `0.2.3` -> `1.0.0` |

If a PR is squash-merged, the squash commit title and body are the important inputs. Before merging, make sure the final message contains the intended `feat:`, `feat!:`, `BREAKING CHANGE:`, or `[skip release]` marker.

### Helpers

- `t.TempDir()` for temporary directories
- `testutil.BuildGoBinary()` for fake binaries
- `httptest.NewServer()` for HTTP mocking
- `internal/cli/root_test_main_test.go` for shared fake-binary setup

### Skip Policy

Do not add skipped tests without a recorded reason.

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the scan pipeline, runtime model, and package boundaries.

## Non-Negotiables

- Do not add package-manager installation logic.
- Do not emit secrets or credentials in logs.
- Only make network-backed matcher calls when explicitly triggered by `--enrich`. `--audit` should evaluate existing package vulnerability data and must not silently trigger external enrichment.
