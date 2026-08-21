package consolidation

import (
	"errors"
	"fmt"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-sdk"
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
		if existing, exists := normalized.Node(clone.ID); !exists {
			if err := normalized.AddNode(clone); err != nil {
				return nil, fmt.Errorf("add normalized dependency %q: %w", clone.ID, err)
			}
		} else if detectors.OriginsConflict(existing.Origin, clone.Origin) {
			// The manifest recorded two resolutions for one canonical
			// identity -- one package from two places. They are different
			// occurrences, so both stay. The occurrence ID derives from the
			// origin itself, not the detector position, so a third record
			// repeating one of the origins folds into its occurrence
			// instead of minting yet another node.
			clone.ID = detectors.OccurrenceID(clone.ID, originKey(clone.Origin))
			if _, taken := normalized.Node(clone.ID); !taken {
				if err := normalized.AddNode(clone); err != nil {
					return nil, fmt.Errorf("add occurrence %q: %w", clone.ID, err)
				}
			}
		} else {
			// Two witnesses of one resolution fold; a gap fills from
			// whichever record has an origin, matching the SDK's merge.
			if existing.Origin.Empty() && !clone.Origin.Empty() {
				existing.Origin = clone.Origin
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

// preserveContradictingOccurrences walks the selected entries in order and
// re-IDs any node whose origin contradicts the origin already established for
// that ID by an earlier entry, so the later SDK graph merge folds only
// witnesses of one resolution. The occurrence ID is derived from the origin
// itself, not from which manifest carried it: with three manifests resolving
// origins A, B, then B, both B witnesses land on one occurrence ID and fold,
// whatever order the manifests are walked in. No tiebreak ever picks a winner.
func preserveContradictingOccurrences(entries []sdk.GraphEntry) {
	established := make(map[string]*sdk.DependencyOrigin)
	for _, entry := range entries {
		if entry.Graph == nil {
			continue
		}
		var contradicting []*sdk.Dependency
		for _, node := range entry.Graph.Nodes() {
			if node == nil {
				continue
			}
			recorded, seen := established[node.ID]
			switch {
			case !seen || recorded.Empty():
				if origin := node.Origin.Normalized(); origin != nil {
					established[node.ID] = origin
				} else if !seen {
					established[node.ID] = nil
				}
			case detectors.OriginsConflict(recorded, node.Origin):
				contradicting = append(contradicting, node)
			}
		}
		for _, node := range contradicting {
			renameNode(entry.Graph, node, detectors.OccurrenceID(node.ID, originKey(node.Origin)))
		}
	}
}

// originKey renders a normalized origin as a stable string, so occurrence IDs
// derived from it are identical for identical witnesses across manifests.
func originKey(origin *sdk.DependencyOrigin) string {
	normalized := origin.Normalized()
	if normalized == nil {
		return ""
	}
	return normalized.ArtifactURL + "\x00" + normalized.Repository + "\x00" + normalized.Revision
}

// renameNode rebuilds a node under a new ID, remapping its edges. sdk.Graph
// keys nodes by ID, so a rename is a remove-and-reinsert.
func renameNode(g *sdk.Graph, node *sdk.Dependency, newID string) {
	if g == nil || node == nil || newID == node.ID || newID == "" {
		return
	}
	if _, taken := g.Node(newID); taken {
		return // never overwrite an unrelated node; leave the original in place
	}
	var parents []*sdk.Dependency
	g.WalkEdges(func(from, to *sdk.Dependency) bool {
		if to != nil && to.ID == node.ID && from != nil {
			parents = append(parents, from)
		}
		return true
	})
	children, err := g.DirectDependencies(node.ID)
	if err != nil {
		return
	}
	renamed := node.Clone()
	renamed.ID = newID
	if !g.RemoveNode(node.ID) {
		return
	}
	if err := g.AddNode(renamed); err != nil {
		return
	}
	for _, parent := range parents {
		if parent != nil {
			_ = g.AddEdge(parent.ID, newID)
		}
	}
	for _, child := range children {
		if child != nil {
			_ = g.AddEdge(newID, child.ID)
		}
	}
}

func addNodeIfMissing(g *sdk.Graph, node *sdk.Dependency) error {
	if node == nil {
		return nil
	}
	clone := node.Clone()
	if err := g.AddNode(clone); errors.Is(err, sdk.ErrNodeAlreadyExist) {
		if existing, ok := g.Node(node.ID); ok && existing != nil {
			existing.Relationship = sdk.MergeDependencyRelationship(existing.Relationship, node.Relationship)
			if existing.Origin.Empty() {
				existing.Origin = clone.Origin
			}
		}
	} else if err != nil {
		return fmt.Errorf("add dependency %q: %w", node.ID, err)
	}
	return nil
}
