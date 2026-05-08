package registry

import (
	"github.com/bomly-dev/bomly-cli/internal/analyzers/jsreach"
)

// registerJSReachAnalyzer wires the JavaScript Tier-3 reachability
// analyzer. The runner implementation is selected at build time via
// the bomly_external_jsreach tag (default: vendored esbuild library;
// external: stub that reports "missing-toolchain").
func (r *Registry) registerJSReachAnalyzer() {
	r.RegisterAnalyzer(jsreach.Analyzer{Logger: r.logger})
}
