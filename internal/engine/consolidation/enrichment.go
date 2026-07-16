package consolidation

import (
	"errors"
	"fmt"
	"strings"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func normalizeGraphPackageIdentity(src *sdk.Graph) (*sdk.Graph, error) {
	if src == nil {
		return nil, nil
	}

	normalized := sdk.NewWithCapacity(src.Size())
	idMapping := make(map[string]string, src.Size())
	for _, node := range src.Nodes() {
		if node == nil {
			continue
		}

		clone := node.Clone()
		sdk.NormalizeDependencyIdentity(clone)
		canonicalPURL := sdk.CanonicalPackageURLFromDependency(clone)
		if canonicalPURL != "" {
			clone.PURL = canonicalPURL
			clone.ID = canonicalPURL
		} else if strings.TrimSpace(clone.ID) == "" {
			clone.ID = clone.StableID()
		}

		if clone.ID == "" {
			return nil, fmt.Errorf("dependency %q has no canonical identity", node.QualifiedName())
		}
		if _, exists := normalized.Node(clone.ID); !exists {
			if err := normalized.AddNode(clone); err != nil {
				return nil, fmt.Errorf("add normalized dependency %q: %w", clone.ID, err)
			}
		}
		idMapping[node.ID] = clone.ID
	}

	for _, node := range src.Nodes() {
		if node == nil {
			continue
		}
		fromID := idMapping[node.ID]
		if fromID == "" {
			continue
		}
		deps, err := src.DirectDependencies(node.ID)
		if err != nil {
			continue
		}
		for _, dependency := range deps {
			if dependency == nil {
				continue
			}
			toID := idMapping[dependency.ID]
			if toID == "" || fromID == toID {
				continue
			}
			if err := normalized.AddEdge(fromID, toID); err != nil {
				return nil, fmt.Errorf("add normalized edge %q -> %q: %w", fromID, toID, err)
			}
		}
	}
	return normalized, nil
}

// BuildPackageRegistry seeds a PURL-keyed package registry from a consolidated
// graph. Each dependency node contributes one registry package (deduplicated by
// PURL); detection-time license facts stashed on the node by SBOM-backed
// detectors are lifted into the registry package. Matchers later enrich these
// packages in place. Dependency nodes are linked to their package via
// PackageRef.
func BuildPackageRegistry(consolidated sdk.ConsolidatedGraph) *sdk.PackageRegistry {
	registry := sdk.NewPackageRegistry()
	if consolidated.Graphs == nil {
		return registry
	}
	for _, entry := range consolidated.Graphs.Entries {
		if entry.Graph == nil {
			continue
		}
		for _, node := range entry.Graph.Nodes() {
			if node == nil {
				continue
			}
			purl := sdk.CanonicalPackageURLFromDependency(node)
			if purl == "" {
				continue
			}
			node.PackageRef = purl
			pkg := registry.Add(sdk.PackageFromDependency(node))
			if pkg == nil {
				continue
			}
			if licenses := sdk.DetectionLicenses(node); len(licenses) > 0 && len(pkg.Licenses) == 0 {
				pkg.Licenses = append([]sdk.PackageLicense(nil), licenses...)
			}
		}
		// Also fold any detection-time package facts carried alongside the graph.
		for _, pkg := range entry.Packages {
			if pkg == nil || pkg.PURL == "" {
				continue
			}
			registry.Add(pkg)
		}
	}
	return registry
}

func addNodeIfMissing(g *sdk.Graph, node *sdk.Dependency) error {
	if node == nil {
		return nil
	}
	clone := node.Clone()
	if err := g.AddNode(clone); errors.Is(err, sdk.ErrNodeAlreadyExist) {
		if existing, ok := g.Node(node.ID); ok && existing != nil {
			existing.Relationship = sdk.MergeDependencyRelationship(existing.Relationship, node.Relationship)
		}
	} else if err != nil {
		return fmt.Errorf("add dependency %q: %w", node.ID, err)
	}
	return nil
}
