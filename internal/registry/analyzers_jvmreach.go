package registry

import (
	"github.com/bomly-dev/bomly-cli/internal/analyzers/jvmreach"
)

// registerJVMReachAnalyzer wires the JVM (Maven/Gradle/SBT) Tier-3
// reachability analyzer. The runner is an in-process line-oriented
// import scanner that walks the project's .java / .kt / .scala /
// .groovy source tree.
func (r *Registry) registerJVMReachAnalyzer() {
	r.RegisterAnalyzer(jvmreach.Analyzer{Logger: r.logger})
}
