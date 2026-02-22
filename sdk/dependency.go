package sdk

import (
	"fmt"
	"strings"
)

// Scope describes the normalized dependency scope surfaced to users.
type Scope string

const (
	// ScopeUnknown indicates that a detector could not determine dependency scope.
	ScopeUnknown Scope = ""
	// ScopeRuntime indicates a dependency required at runtime.
	ScopeRuntime Scope = "runtime"
	// ScopeDevelopment indicates a dependency used only for development workflows.
	ScopeDevelopment Scope = "development"
)

// ParseScope normalizes a user-provided dependency scope value.
func ParseScope(value string) (Scope, error) {
	switch Scope(strings.ToLower(strings.TrimSpace(value))) {
	case ScopeRuntime:
		return ScopeRuntime, nil
	case ScopeDevelopment:
		return ScopeDevelopment, nil
	case ScopeUnknown:
		return ScopeUnknown, nil
	default:
		return ScopeUnknown, fmt.Errorf("unsupported scope %q", value)
	}
}

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
func MergePackageScope(pkg *Package, next Scope) {
	if pkg == nil {
		return
	}
	pkg.Scope = string(MergeScope(Scope(pkg.Scope), next))
}

// DependencyQuery identifies a specific component target.
type DependencyQuery struct {
	Name string `json:"name,omitempty"`
	ID   string `json:"id,omitempty"`
}
