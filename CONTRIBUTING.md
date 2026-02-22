# Contributing to Bomly

## Development Setup

### Prerequisites

- Go 1.24+ (see `go.mod` for the exact version)
- `make`
- Optional: `syft` and `grype` binaries on PATH (for external mode testing)

### Build

```bash
make build              # Full build with builtin Syft/Grype
make build-lite         # Lightweight build without Syft/Grype libraries
make test               # Run all tests
make run ARGS="scan"    # Run with arguments
```

### Build Tags

| Tag | Effect |
|-----|--------|
| `bomly_builtin_syft` | Link Syft library (default in `make build`) |
| `bomly_builtin_grype` | Link Grype library (default in `make build`) |

Without these tags, Bomly falls back to shelling out to `syft`/`grype` CLI binaries.

---

## Code Conventions

### Errors

Always wrap errors with context:

```go
return fmt.Errorf("operation context: %w", err)
```

No panics in normal flow. Only `log.Fatal` in `cmd/bomly/main.go`.

### Logging

Use Zap structured logging:

```go
logger.Debug("osv: fetching vuln", zap.String("id", id))
logger.Info("auditor: found findings", zap.Int("count", n))
logger.Warn("cache miss", zap.Error(err))
```

- Loggers may be `nil` — always nil-check or use `zap.NewNop()` as the zero value
- Prefer one summary log for batch operations over per-item logs
- No PII, tokens, or credentials in logs

### Terminal Output

- Use `internal/cli/ansi.go` helpers — never raw escape codes
- Interactive TUI uses Bubbletea via `internal/cli/interactive.go`
- SARIF output via `internal/output` — do not hand-craft SARIF JSON

### New Packages

- Prefer `internal/` unless there is a clear public API need
- Standard library + Cobra + existing deps only — do not add new dependencies without discussion

---

## Testing

### Expectations

- Unit tests for all new logic
- Integration tests for new commands
- All tests must pass before marking work done: `make test`

### Helpers

- `t.TempDir()` for temporary directories
- `testutil.BuildGoBinary()` for building fake binaries
- `httptest.NewServer()` for HTTP mocking
- Fake binaries for npm, go, gradle, and plugins are built in `TestMain` — see `internal/cli/root_test_main_test.go`

### Skip Policy

No test should be conditionally skipped without a recorded reason.

---

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full architecture reference, including the scan pipeline, detector/auditor model, plugin system, and decision log.

---

## Non-Negotiables

- **Do not add package manager installation logic.** Assume package managers exist.
- **Plugin protocol is versioned `v1`.** Never break the `--bomly-plugin-info` JSON contract.
- **No secrets or credentials in logs.** Ever.
- **Network calls only when explicitly triggered.** OSV and CISA KEV calls are permitted inside `--audit`. No other unsolicited outbound calls.
