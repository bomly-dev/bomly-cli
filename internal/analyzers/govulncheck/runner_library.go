package govulncheck

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"go.uber.org/zap"
	govulnscan "golang.org/x/vuln/scan"
)

// NewRunner returns the analyzer's Runner implementation, backed by the
// vendored golang.org/x/vuln/scan library. The runner executes
// govulncheck in-process and streams the same JSON output the CLI
// binary would emit, so users never need a govulncheck binary on PATH.
func NewRunner(logger *zap.Logger) Runner {
	return libraryRunner{logger: ensureLogger(logger)}
}

// libraryRunner is the in-process implementation of Runner. The Runner
// interface is preserved (rather than calling api.Build directly from
// the analyzer) so unit tests can inject a fakeRunner for deterministic
// behavior without a real Go toolchain.
type libraryRunner struct {
	logger *zap.Logger
}

func (libraryRunner) Name() string { return "library" }

func (r libraryRunner) Run(ctx context.Context, moduleDir string) (RunnerResult, error) {
	// govulncheck has no Cmd.Dir field; pass -C <dir> instead.
	args := []string{"-json", "-mode=source", "-C", moduleDir, "./..."}
	r.logger.Debug("govulncheck: executing in-process runner",
		zap.String("module_root", moduleDir),
		zap.Strings("args", args))

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := govulnscan.Command(ctx, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return RunnerResult{}, fmt.Errorf("govulncheck start: %w", err)
	}
	waitErr := cmd.Wait()
	r.logger.Debug("govulncheck: in-process runner produced output",
		zap.String("module_root", moduleDir),
		zap.Int("stdout_bytes", stdout.Len()),
		zap.Int("stderr_bytes", stderr.Len()))

	if waitErr != nil {
		// govulncheck.Cmd surfaces "exit status 3" (vulnerabilities
		// found) the same way the binary does. The streaming JSON
		// parser tolerates the trailing data, so try to parse stdout
		// regardless.
		if isVulnsFound(waitErr) && stdout.Len() > 0 {
			r.logger.Debug("govulncheck: vulnerabilities found; parsing stdout",
				zap.String("module_root", moduleDir),
				zap.Int("stdout_bytes", stdout.Len()))
			result, parseErr := parseGovulncheckJSON(stdout.Bytes())
			if parseErr != nil {
				return RunnerResult{}, fmt.Errorf("parse govulncheck output: %w", parseErr)
			}
			return result, nil
		}
		// Surface stderr in the error message so build failures are
		// debuggable from a single log line.
		stderrPreview := truncateStderr(stderr.String(), 512)
		if stderrPreview != "" {
			return RunnerResult{}, fmt.Errorf("govulncheck failed: %w: %s", waitErr, stderrPreview)
		}
		return RunnerResult{}, fmt.Errorf("govulncheck failed: %w", waitErr)
	}

	return parseGovulncheckJSON(stdout.Bytes())
}

// isVulnsFound reports whether the wrapped error is the
// "vulnerabilities found" sentinel govulncheck returns when it discovers
// at least one finding. The error message is the canonical signal; the
// library uses an unexported type so we match on text.
func isVulnsFound(err error) bool {
	if err == nil {
		return false
	}
	type sentinel interface{ Error() string }
	if typed, ok := errors.AsType[sentinel](err); ok {
		msg := typed.Error()
		// govulncheck's "exit code 3" surfaces here as either
		// "exit status 3" (when shelling out to the toolchain) or as
		// the in-process equivalent the library prints.
		if msg == "exit status 3" || msg == "vulnerabilities found" {
			return true
		}
	}
	return false
}

// truncateStderr returns at most n bytes of s with an ellipsis when truncated.
func truncateStderr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
