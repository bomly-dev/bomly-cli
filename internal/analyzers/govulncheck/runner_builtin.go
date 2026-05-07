//go:build !bomly_external_govulncheck

package govulncheck

import (
	"context"
	"fmt"
	"os/exec"

	"go.uber.org/zap"
)

// NewDefaultRunner returns the runner selected at build time. The
// default (non-external) build uses the builtin runner.
//
// NOTE: the in-process runner backed by golang.org/x/vuln/scan is not
// yet vendored. Until that lands, the builtin runner falls back to
// invoking the `govulncheck` binary on PATH (same path as the external
// runner) so that users on the default build get reachability when they
// have govulncheck installed. A follow-up commit on this branch will
// replace this with a true in-process implementation; the build-tag
// architecture and Runner interface stay stable.
func NewDefaultRunner(logger *zap.Logger) Runner {
	return builtinRunner{logger: ensureLogger(logger)}
}

type builtinRunner struct {
	logger *zap.Logger
}

func (builtinRunner) Name() string { return "builtin" }

func (r builtinRunner) Run(ctx context.Context, moduleDir string) (RunnerResult, error) {
	bin, err := exec.LookPath("govulncheck")
	if err != nil {
		return RunnerResult{}, fmt.Errorf("builtin runner not yet vendored and govulncheck binary not on PATH: %w", err)
	}
	cmd := exec.CommandContext(ctx, bin, "-json", "./...")
	cmd.Dir = moduleDir
	stdout, err := cmd.Output()
	if err != nil {
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
