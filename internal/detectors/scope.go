package detectors

import "github.com/bomly/bomly-cli/internal/model"

// MergeScope combines two normalized scopes, preferring runtime when a package
// is reachable from both runtime and development roots.
func MergeScope(current, next Scope) Scope {
	switch {
	case next == ScopeUnknown:
		return current
	case current == ScopeUnknown:
		return next
	case current == ScopeRuntime || next == ScopeRuntime:
		return ScopeRuntime
	default:
		return ScopeDevelopment
	}
}

// MergePackageScope updates pkg.Scope using normalized scope precedence rules.
func MergePackageScope(pkg *model.Package, next Scope) {
	if pkg == nil {
		return
	}
	pkg.Scope = string(MergeScope(Scope(pkg.Scope), next))
}
