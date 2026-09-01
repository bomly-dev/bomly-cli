package node

import (
	"fmt"
	"sort"

	"github.com/bomly-dev/bomly-sdk"
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
		if root != nil && root.Kind() == sdk.NodeKindModule {
			return AttachUnknownComponents(graph, root.NodeID(), logger, detector, manifest)
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
		if candidate != nil && candidate.Kind() == sdk.NodeKindModule {
			addReachable(graph, candidate.NodeID(), known)
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
		addReachable(graph, candidate.NodeID(), known)
		if err := graph.AddEdge(rootID, candidate.NodeID()); err != nil {
			return nil, fmt.Errorf("attach unknown component %q to %q: %w", candidate.NodeID(), rootID, err)
		}
		components = append(components, UnknownComponent{RootID: candidate.NodeID(), Size: len(known) - before})
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
			if _, ok := seen[child.NodeID()]; ok {
				continue
			}
			seen[child.NodeID()] = struct{}{}
			queue = append(queue, child.NodeID())
		}
	}
}

func unresolvedDependencyNodes(graph *sdk.Graph, known map[string]struct{}) []*sdk.DependencyNode {
	var unresolved []*sdk.DependencyNode
	for _, dependency := range graph.DependencyNodes() {
		if dependency == nil || dependency.Type == sdk.PackageTypeApplication || dependency.Type == sdk.PackageTypeManifest {
			continue
		}
		if _, ok := known[dependency.NodeID()]; !ok {
			unresolved = append(unresolved, dependency)
		}
	}
	sort.Slice(unresolved, func(i, j int) bool { return unresolved[i].NodeID() < unresolved[j].NodeID() })
	return unresolved
}

func unresolvedComponentRoot(graph *sdk.Graph, unresolved []*sdk.DependencyNode) *sdk.DependencyNode {
	set := make(map[string]struct{}, len(unresolved))
	for _, dependency := range unresolved {
		set[dependency.NodeID()] = struct{}{}
	}
	for _, dependency := range unresolved {
		parents, err := graph.Dependents(dependency.NodeID())
		if err != nil {
			continue
		}
		hasUnresolvedParent := false
		for _, parent := range parents {
			if parent == nil {
				continue
			}
			if _, ok := set[parent.NodeID()]; ok {
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
