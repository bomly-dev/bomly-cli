package node

import (
	"fmt"
	"sort"

	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// UnknownComponent describes a disconnected component attached to its owning
// manifest root with an unknown relationship.
type UnknownComponent struct {
	RootID string
	Size   int
}

// AttachUnknownComponentsToApplication finds the application root and
// delegates to AttachUnknownComponents. Graphs without an application root
// are left for consolidation to normalize beneath a manifest root.
func AttachUnknownComponentsToApplication(graph *sdk.Graph, logger *zap.Logger, detector, manifest string) ([]UnknownComponent, error) {
	if graph == nil {
		return nil, nil
	}
	for _, root := range graph.Roots() {
		if root != nil && root.Type == sdk.PackageTypeApplication {
			return AttachUnknownComponents(graph, root.ID, logger, detector, manifest)
		}
	}
	return nil, nil
}

// AttachUnknownComponents attaches every component without an incoming edge
// beneath rootID. Only the component root is marked unknown; known descendant
// edges remain transitive.
func AttachUnknownComponents(graph *sdk.Graph, rootID string, logger *zap.Logger, detector, manifest string) ([]UnknownComponent, error) {
	if graph == nil || rootID == "" {
		return nil, nil
	}
	if _, ok := graph.Node(rootID); !ok {
		return nil, fmt.Errorf("dependency root %q not found", rootID)
	}
	known := make(map[string]struct{}, graph.Size())
	for _, candidate := range graph.Roots() {
		if candidate != nil && candidate.Type == sdk.PackageTypeApplication {
			addReachable(graph, candidate.ID, known)
		}
	}
	addReachable(graph, rootID, known)

	components := make([]UnknownComponent, 0)
	for {
		unresolved := unresolvedDependencyNodes(graph, known)
		if len(unresolved) == 0 {
			break
		}
		candidate := unresolvedComponentRoot(graph, unresolved)
		candidate.Relationship = sdk.DependencyRelationshipUnknown
		before := len(known)
		addReachable(graph, candidate.ID, known)
		if err := graph.AddEdge(rootID, candidate.ID); err != nil {
			return nil, fmt.Errorf("attach unknown component %q to %q: %w", candidate.ID, rootID, err)
		}
		components = append(components, UnknownComponent{RootID: candidate.ID, Size: len(known) - before})
	}
	if len(components) == 0 {
		return nil, nil
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	logger.Debug("node detector attached dependency components with unknown parent relationships",
		zap.String("detector", detector), zap.String("manifest", manifest), zap.Int("components", len(components)))
	for _, component := range components {
		logger.Debug("node detector unknown dependency component",
			zap.String("detector", detector), zap.String("manifest", manifest),
			zap.String("component_root", component.RootID), zap.Int("component_size", component.Size))
	}
	return components, nil
}

func addReachable(graph *sdk.Graph, rootID string, seen map[string]struct{}) {
	if _, ok := seen[rootID]; ok {
		return
	}
	seen[rootID] = struct{}{}
	queue := []string{rootID}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		children, err := graph.DirectDependencies(current)
		if err != nil {
			continue
		}
		for _, child := range children {
			if child == nil {
				continue
			}
			if _, ok := seen[child.ID]; ok {
				continue
			}
			seen[child.ID] = struct{}{}
			queue = append(queue, child.ID)
		}
	}
}

func unresolvedDependencyNodes(graph *sdk.Graph, known map[string]struct{}) []*sdk.Dependency {
	var unresolved []*sdk.Dependency
	for _, dependency := range graph.Nodes() {
		if dependency == nil || dependency.Type == sdk.PackageTypeApplication || dependency.Type == sdk.PackageTypeManifest {
			continue
		}
		if _, ok := known[dependency.ID]; !ok {
			unresolved = append(unresolved, dependency)
		}
	}
	sort.Slice(unresolved, func(i, j int) bool { return unresolved[i].ID < unresolved[j].ID })
	return unresolved
}

func unresolvedComponentRoot(graph *sdk.Graph, unresolved []*sdk.Dependency) *sdk.Dependency {
	set := make(map[string]struct{}, len(unresolved))
	for _, dependency := range unresolved {
		set[dependency.ID] = struct{}{}
	}
	for _, dependency := range unresolved {
		parents, err := graph.Dependents(dependency.ID)
		if err != nil {
			continue
		}
		hasUnresolvedParent := false
		for _, parent := range parents {
			if parent == nil {
				continue
			}
			if _, ok := set[parent.ID]; ok {
				hasUnresolvedParent = true
				break
			}
		}
		if !hasUnresolvedParent {
			return dependency
		}
	}
	// A remaining strongly connected component has no natural root. Selecting
	// the stable first ID retains the cycle while making parent uncertainty explicit.
	return unresolved[0]
}
