package explain

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-sdk"
)

// ErrDependencyNotFound indicates the requested package was not found.
var ErrDependencyNotFound = errors.New("dependency not found")

// Path is an alias for output.DependencyPath.
type Path = output.DependencyPath

// FindWhy resolves a target package and returns all root-to-target paths.
func FindWhy(deps *sdk.Graph, query string) (output.PackageRef, []Path, error) {
	target, paths, err := FindWhyPackage(deps, query)
	if err != nil {
		return output.PackageRef{}, nil, err
	}
	return output.PackageFromGraphPackage(target), paths, nil
}

// FindWhyPackage resolves a target package and returns the package plus all root-to-target paths.
func FindWhyPackage(deps *sdk.Graph, query string) (*sdk.DependencyNode, []Path, error) {
	target, err := resolveTarget(deps, query)
	if err != nil {
		return nil, nil, err
	}

	rawPaths, err := deps.CollectPathsTo(target.NodeID())
	if err != nil {
		return nil, nil, err
	}

	paths := make([]Path, 0, len(rawPaths))
	for _, rawPath := range rawPaths {
		paths = append(paths, toPath(rawPath.Nodes, rawPath.Cyclic, rawPath.CycleTo))
	}
	sort.Slice(paths, func(i, j int) bool {
		return pathKey(paths[i]) < pathKey(paths[j])
	})

	return target, paths, nil
}

func resolveTarget(deps *sdk.Graph, query string) (*sdk.DependencyNode, error) {
	var exact *sdk.DependencyNode
	var matches []*sdk.DependencyNode
	for _, pkg := range deps.DependencyNodes() {
		if pkg.NodeID() == query {
			exact = pkg
			break
		}
		if pkg.Name == query || pkg.QualifiedName() == query {
			matches = append(matches, pkg)
		}
	}
	if exact != nil {
		return exact, nil
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrDependencyNotFound, query)
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].NodeID() < matches[j].NodeID() })
	return matches[0], nil
}

// Takes the union type: a path runs through manifests and modules as well
// as dependencies, and RelationshipForPath counts only the dependency hops.
func toPath(packages []sdk.GraphNode, cyclic bool, cycleTo string) Path {
	refs := make([]output.PackageRef, 0, len(packages))
	for _, node := range packages {
		// Only dependency nodes become package references; the structural
		// nodes on a path are the manifest and module it runs through.
		pkg, ok := node.(*sdk.DependencyNode)
		if !ok {
			continue
		}
		refs = append(refs, output.PackageFromGraphPackage(pkg))
	}
	if len(refs) == 0 {
		return Path{Cyclic: cyclic, CycleTo: cycleTo}
	}
	relationship := sdk.RelationshipForPath(packages)
	introducedVia := refs[0].ID
	return Path{
		Relationship:  string(relationship),
		Packages:      refs,
		IntroducedVia: introducedVia,
		Cyclic:        cyclic,
		CycleTo:       cycleTo,
	}
}

func pathKey(path Path) string {
	ids := make([]string, 0, len(path.Packages))
	for _, pkg := range path.Packages {
		ids = append(ids, pkg.ID)
	}
	return strings.Join(ids, "/")
}

// GraphFromPaths returns a focused subgraph of source containing only the
// packages and edges that appear in the supplied explain paths.
func GraphFromPaths(source *sdk.Graph, paths []Path) (*sdk.Graph, error) {
	focused := sdk.New()
	if source == nil {
		return focused, nil
	}
	for _, path := range paths {
		for i, ref := range path.Packages {
			pkg, ok := source.Node(ref.ID)
			if !ok || pkg == nil {
				continue
			}
			if _, exists := focused.Node(pkg.NodeID()); !exists {
				if err := focused.AddNode(pkg.CloneNode()); err != nil {
					return nil, err
				}
			}
			if i == 0 {
				continue
			}
			parentRef := path.Packages[i-1]
			parent, ok := source.Node(parentRef.ID)
			if !ok || parent == nil {
				continue
			}
			if _, exists := focused.Node(parent.NodeID()); !exists {
				if err := focused.AddNode(parent.CloneNode()); err != nil {
					return nil, err
				}
			}
			if err := focused.AddEdge(parent.NodeID(), pkg.NodeID()); err != nil && !errors.Is(err, sdk.ErrCycleDetected) {
				return nil, err
			}
		}
	}
	return focused, nil
}
