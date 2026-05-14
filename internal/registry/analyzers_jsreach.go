package registry

import (
	"github.com/bomly-dev/bomly-cli/internal/analyzers/jsreach"
)

// registerJSReachAnalyzer wires the JavaScript Tier-3 reachability
// analyzer. The runner is backed by the vendored
// github.com/evanw/esbuild/pkg/api library and runs in-process.
func (r *Registry) registerJSReachAnalyzer() {
	r.RegisterAnalyzer(jsreach.Analyzer{Logger: r.logger})
}
