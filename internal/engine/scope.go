package engine

import (
	"fmt"

	"github.com/bomly-dev/bomly-cli/sdk"
)

// MergeScope combines two normalized scopes, preferring runtime when a package
// is reachable from both runtime and development roots.
func MergeScope(current, next sdk.Scope) sdk.Scope {
	return sdk.MergeScope(current, next)
}

// MergePackageScope updates pkg.Scope using normalized scope precedence rules.
func MergePackageScope(pkg *sdk.Package, next sdk.Scope) {
	sdk.MergePackageScope(pkg, next)
}

// FilterGraphByScope returns a graph view containing roots plus packages whose
// normalized scope matches the requested filter.
func FilterGraphByScope(src *sdk.Graph, scope sdk.Scope) (*sdk.Graph, error) {
	if src == nil || scope == sdk.ScopeUnknown {
		return src, nil
	}

	allowed := make(map[string]struct{}, src.Size())
	for _, root := range src.Roots() {
		if root == nil {
			continue
		}
		allowed[root.ID] = struct{}{}
	}
	src.WalkPackages(func(pkg *sdk.Package) bool {
		if pkg != nil && sdk.Scope(pkg.Scope) == scope {
			allowed[pkg.ID] = struct{}{}
		}
		return true
	})

	filtered := sdk.NewWithCapacity(len(allowed))
	for id := range allowed {
		pkg, ok := src.Package(id)
		if !ok {
			continue
		}
		if err := filtered.AddPackage(pkg.Clone()); err != nil {
			return nil, err
		}
	}

	var mergeErr error
	src.WalkRelationships(func(from, to *sdk.Package) bool {
		if from == nil || to == nil {
			return true
		}
		if _, ok := allowed[from.ID]; !ok {
			return true
		}
		if _, ok := allowed[to.ID]; !ok {
			return true
		}
		if err := filtered.AddDependency(from.ID, to.ID); err != nil {
			mergeErr = fmt.Errorf("add filtered dependency %q -> %q: %w", from.ID, to.ID, err)
			return false
		}
		return true
	})
	if mergeErr != nil {
		return nil, mergeErr
	}

	return filtered, nil
}
