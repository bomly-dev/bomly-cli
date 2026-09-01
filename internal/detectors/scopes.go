package detectors

import (
	"github.com/bomly-dev/bomly-cli/internal/nodes"
	sdk "github.com/bomly-dev/bomly-sdk"
)

// PropagateScopes seeds the scopes of a root's direct dependencies and spreads
// them breadth-first through the graph, so a package reachable on a runtime
// path is marked runtime even when it is also a development dependency. Any
// dependency node still unscoped afterwards defaults to runtime: a package the
// resolver installed is used at runtime unless something said otherwise.
//
// This lived three times over -- once per Python lockfile detector -- with the
// same off-by-one traps in each copy, which is the signal that the rule had no
// home. Only the seed differed, so that is the parameter: seed reports where a
// direct dependency starts, and a nil seed reads the node's own primary scope.
// Non-dependency nodes are skipped; scope is a claim about a package, and a
// manifest or a module does not carry one.
func PropagateScopes(g *sdk.Graph, rootID string, seed func(*sdk.DependencyNode) sdk.Scope) {
	if g == nil {
		return
	}
	if seed == nil {
		seed = func(node *sdk.DependencyNode) sdk.Scope { return node.PrimaryScope() }
	}

	directNodes, _ := g.DirectDependencies(rootID)
	directDeps := nodes.DependenciesOf(directNodes)
	propagated := make(map[string]sdk.Scope, g.Size())
	queue := make([]*sdk.DependencyNode, 0, len(directDeps))
	for _, dep := range directDeps {
		scope := seed(dep)
		if scope == sdk.ScopeUnknown {
			scope = sdk.ScopeRuntime
		}
		propagated[dep.NodeID()] = sdk.MergeScope(propagated[dep.NodeID()], scope)
		dep.AddScope(propagated[dep.NodeID()])
		queue = append(queue, dep)
	}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		scope := propagated[current.NodeID()]
		if scope == sdk.ScopeUnknown {
			continue
		}
		children, err := g.DirectDependencies(current.NodeID())
		if err != nil {
			continue
		}
		for _, child := range nodes.DependenciesOf(children) {
			if child.NodeID() == rootID {
				continue
			}
			next := sdk.MergeScope(propagated[child.NodeID()], scope)
			// Stop when neither the propagated value nor the node's own scope
			// would change: without this the queue revisits every cycle
			// forever.
			if next == propagated[child.NodeID()] && child.PrimaryScope() == next {
				continue
			}
			propagated[child.NodeID()] = next
			child.AddScope(next)
			queue = append(queue, child)
		}
	}

	for _, pkg := range g.DependencyNodes() {
		if pkg != nil && pkg.NodeID() != rootID && pkg.PrimaryScope() == sdk.ScopeUnknown {
			pkg.AddScope(sdk.ScopeRuntime)
		}
	}
}
