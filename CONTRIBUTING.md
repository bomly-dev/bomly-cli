# Contributing to Bomly

## Development Setup

### Prerequisites

- Go 1.24+ (see `go.mod` for the exact version)
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
| `bomly_builtin_syft` | Link the Syft library directly |
| `bomly_builtin_grype` | Link the Grype library directly |

Without these tags, Bomly shells out to `syft` and `grype` binaries.

## Code Conventions

### Errors

Always wrap errors with context:

```go
return fmt.Errorf("operation context: %w", err)
```

No panics in normal flow. Only `log.Fatal` is allowed in `cmd/bomly/main.go`.

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
- Only make network calls when explicitly triggered by the user-facing workflow, such as `--audit`.
