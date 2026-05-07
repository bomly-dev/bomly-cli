//go:build bomly_external_govulncheck

package govulncheck

import (
	"context"
	"fmt"
	"os/exec"

	"go.uber.org/zap"
)

// NewDefaultRunner returns the runner selected at build time. With the
// bomly_external_govulncheck tag, this is the external runner.
func NewDefaultRunner(logger *zap.Logger) Runner {
	return externalRunner{logger: ensureLogger(logger)}
}

// externalRunner shells out to the `govulncheck` binary.
type externalRunner struct {
	logger *zap.Logger
}

func (externalRunner) Name() string { return "external" }

func (r externalRunner) Run(ctx context.Context, moduleDir string) (RunnerResult, error) {
	bin, err := exec.LookPath("govulncheck")
	if err != nil {
		return RunnerResult{}, fmt.Errorf("govulncheck binary not found on PATH: %w", err)
	}
	cmd := exec.CommandContext(ctx, bin, "-json", "./...")
	cmd.Dir = moduleDir
	stdout, err := cmd.Output()
	if err != nil {
		// Some govulncheck exit codes (3) signal "vulns found" rather
		// than failure. The streaming JSON parser tolerates trailing
		// data, so try to parse stdout regardless.
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 3 && len(stdout) > 0 {
			result, parseErr := parseGovulncheckJSON(stdout)
			if parseErr != nil {
				return RunnerResult{}, fmt.Errorf("parse govulncheck output: %w", parseErr)
			}
			return result, nil
		}
		return RunnerResult{}, fmt.Errorf("govulncheck failed: %w", err)
	}
	return parseGovulncheckJSON(stdout)
}
