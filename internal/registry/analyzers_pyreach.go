package registry

import (
	"github.com/bomly-dev/bomly-cli/internal/analyzers/pyreach"
)

// registerPyReachAnalyzer wires the Python Tier-3 reachability
// analyzer. The runner is an in-process line-oriented import scanner
// that walks the project's .py source tree.
func (r *Registry) registerPyReachAnalyzer() {
	r.RegisterAnalyzer(pyreach.Analyzer{Logger: r.logger})
}
