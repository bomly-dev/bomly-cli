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

// MergeDependencyScope adds next onto dep's scope set using normalized scope
// precedence rules.
func MergeDependencyScope(dep *sdk.Dependency, next sdk.Scope) {
	if dep == nil {
		return
	}
	dep.AddScope(next)
}

// FilterGraphByScope returns a graph view containing roots plus dependencies
// whose normalized scope matches the requested filter.
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
	src.WalkNodes(func(dep *sdk.Dependency) bool {
		if dep != nil && dep.HasScope(scope) {
			allowed[dep.ID] = struct{}{}
		}
		return true
	})

	filtered := sdk.NewWithCapacity(len(allowed))
	for id := range allowed {
		dep, ok := src.Node(id)
		if !ok {
			continue
		}
		if err := filtered.AddNode(dep.Clone()); err != nil {
			return nil, err
		}
	}

	var mergeErr error
	src.WalkEdges(func(from, to *sdk.Dependency) bool {
		if from == nil || to == nil {
			return true
		}
		if _, ok := allowed[from.ID]; !ok {
			return true
		}
		if _, ok := allowed[to.ID]; !ok {
			return true
		}
		if err := filtered.AddEdge(from.ID, to.ID); err != nil {
			mergeErr = fmt.Errorf("add filtered edge %q -> %q: %w", from.ID, to.ID, err)
			return false
		}
		return true
	})
	if mergeErr != nil {
		return nil, mergeErr
	}

	return filtered, nil
}
