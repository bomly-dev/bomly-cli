//go:build bomly_external_jsreach

package jsreach

import (
	"context"
	"fmt"

	"go.uber.org/zap"
)

// NewDefaultRunner returns the runner selected at build time. With the
// bomly_external_jsreach tag, this is a no-op stub that always reports
// "missing-toolchain". The lite build deliberately avoids vendoring
// esbuild; users who want JavaScript reachability should use the
// default (full) build.
//
// A future commit can replace this with a real exec implementation
// that shells out to a system esbuild binary if there is demand. The
// Runner interface stays stable so analyzer.go is unaffected either way.
func NewDefaultRunner(logger *zap.Logger) Runner {
	return externalRunner{logger: ensureLogger(logger)}
}

type externalRunner struct {
	logger *zap.Logger
}

func (externalRunner) Name() string { return "external" }

func (externalRunner) Version() string { return "" }

func (r externalRunner) Run(_ context.Context, _ string) (RunnerResult, error) {
	return RunnerResult{}, fmt.Errorf("jsreach external runner is not implemented in lite builds; use the default build for JavaScript reachability")
}
