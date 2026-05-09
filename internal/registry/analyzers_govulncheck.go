package registry

import (
	"github.com/bomly-dev/bomly-cli/internal/analyzers/govulncheck"
)

// registerGovulncheckAnalyzer wires the Go reachability analyzer.
// The runner is backed by the vendored golang.org/x/vuln/scan library
// and runs in-process.
func (r *Registry) registerGovulncheckAnalyzer() {
	r.RegisterAnalyzer(govulncheck.Analyzer{Logger: r.logger})
}
