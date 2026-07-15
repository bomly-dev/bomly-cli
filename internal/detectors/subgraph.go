package detectors

import (
	"errors"
	"fmt"

	"github.com/bomly-dev/bomly-cli/sdk"
)

// SubgraphFrom returns a new graph containing rootID and every node and edge
// reachable from it in g. Detectors that resolve a whole workspace/reactor
// into one graph use it to partition the merged graph into per-module
// manifest entries: each module entry carries the module root plus its
// reachable dependency subtree. Node pointers are shared with the source
// graph, matching how detectors already share nodes across container entries.
func SubgraphFrom(g *sdk.Graph, rootID string) (*sdk.Graph, error) {
	if g == nil {
		return nil, errors.New("subgraph from nil graph")
	}
	root, ok := g.Node(rootID)
	if !ok {
		return nil, fmt.Errorf("subgraph root %q not found in graph", rootID)
	}

	out := sdk.New()
	visited := map[string]struct{}{}
	var walk func(pkg *sdk.Dependency) error
	walk = func(pkg *sdk.Dependency) error {
		if pkg == nil {
			return nil
		}
		if _, ok := visited[pkg.ID]; ok {
			return nil
		}
		visited[pkg.ID] = struct{}{}
		if err := out.AddNode(pkg); err != nil {
			return fmt.Errorf("add subgraph node %q: %w", pkg.ID, err)
		}
		deps, err := g.DirectDependencies(pkg.ID)
		if err != nil {
			return fmt.Errorf("subgraph dependencies of %q: %w", pkg.ID, err)
		}
		for _, dep := range deps {
			if dep == nil {
				continue
			}
			if err := walk(dep); err != nil {
				return err
			}
			if err := out.AddEdge(pkg.ID, dep.ID); err != nil && !errors.Is(err, sdk.ErrSelfDependency) {
				return fmt.Errorf("add subgraph edge %q -> %q: %w", pkg.ID, dep.ID, err)
			}
		}
		return nil
	}
	if err := walk(root); err != nil {
		return nil, err
	}
	return out, nil
}
