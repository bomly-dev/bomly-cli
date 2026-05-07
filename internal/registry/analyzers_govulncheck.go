package registry

import (
	"github.com/bomly-dev/bomly-cli/internal/analyzers/govulncheck"
)

// registerGovulncheckAnalyzer wires the Go reachability analyzer.
// The runner implementation is selected at build time via the
// bomly_external_govulncheck tag.
func (r *Registry) registerGovulncheckAnalyzer() {
	r.RegisterAnalyzer(govulncheck.Analyzer{Logger: r.logger})
}
