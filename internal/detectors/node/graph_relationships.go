package node

import (
	"fmt"

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
	components := make([]UnknownComponent, 0)
	for _, root := range graph.Roots() {
		if root == nil || root.ID == rootID || root.Type == sdk.PackageTypeApplication {
			continue
		}
		root.Relationship = sdk.DependencyRelationshipUnknown
		size := reachableSize(graph, root.ID)
		if err := graph.AddEdge(rootID, root.ID); err != nil {
			return nil, fmt.Errorf("attach unknown component %q to %q: %w", root.ID, rootID, err)
		}
		components = append(components, UnknownComponent{RootID: root.ID, Size: size})
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

func reachableSize(graph *sdk.Graph, rootID string) int {
	seen := map[string]struct{}{rootID: {}}
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
	return len(seen)
}
