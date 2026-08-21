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
	sourcesByNormalized := make(map[string][]string, src.Size())
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
		} else if resolutionKey(existing) != resolutionKey(clone) {
			// The manifest recorded two resolutions for one canonical
			// identity -- one package from two places. They are different
			// occurrences even when only one yields a publishable origin
			// (a registry record has none), so both stay. The occurrence
			// ID derives from the resolution itself, not the detector
			// position, so a third record repeating one of them folds into
			// its occurrence instead of minting yet another node.
			//
			// The canonical ID is reserved for the project's own record: if
			// an external record happened to normalize first, it moves to
			// its occurrence ID and the project takes the canonical slot,
			// whatever the traversal order.
			switch {
			case detectors.IsProjectOwned(clone) && detectors.IsProjectOwned(existing):
				// Two records of the project's own module fold.
				if existing.Origin.Empty() && !clone.Origin.Empty() {
					existing.Origin = clone.Origin
				}
			case detectors.IsProjectOwned(clone):
				externalID := detectors.OccurrenceID(existing.ID, resolutionKey(existing))
				renameNode(normalized, existing, externalID)
				for _, sourceID := range sourcesByNormalized[clone.ID] {
					idMapping[sourceID] = externalID
				}
				sourcesByNormalized[externalID] = sourcesByNormalized[clone.ID]
				sourcesByNormalized[clone.ID] = nil
				if err := normalized.AddNode(clone); err != nil {
					return nil, fmt.Errorf("add project record %q: %w", clone.ID, err)
				}
			default:
				clone.ID = detectors.OccurrenceID(clone.ID, resolutionKey(clone))
				if _, taken := normalized.Node(clone.ID); !taken {
					if err := normalized.AddNode(clone); err != nil {
						return nil, fmt.Errorf("add occurrence %q: %w", clone.ID, err)
					}
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
		sourcesByNormalized[clone.ID] = append(sourcesByNormalized[clone.ID], node.ID)
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

// preserveContradictingOccurrences makes occurrence identity a pure function
// of (package, origin) across the whole scan. It collects the distinct origins
// recorded for each canonical package; where there is more than one, *every*
// node of that package -- in every entry, including whichever happened to hold
// the canonical ID -- is renamed to an ID derived from its own origin. The
// same origin therefore gets the same ID no matter which entry carried it or
// in what order records appeared, so the later SDK graph merge folds exactly
// the witnesses of one resolution and nothing else. A node with no origin
// keeps the canonical ID as its own "resolution unknown" occurrence.
// It returns the applied renames per entry (old node ID to new, index-aligned
// with entries), so callers can refresh stored references -- manifest root IDs
// in particular. The maps are per entry because the same canonical ID can be
// renamed to different occurrence IDs in different entries.
func preserveContradictingOccurrences(entries []sdk.GraphEntry) []map[string]string {
	renames := make([]map[string]string, len(entries))
	distinct := make(map[string]map[string]struct{})
	base := func(node *sdk.Dependency) string {
		if node.PURL != "" {
			return node.PURL
		}
		return node.ID
	}
	for _, entry := range entries {
		if entry.Graph == nil {
			continue
		}
		for _, node := range entry.Graph.Nodes() {
			if node == nil {
				continue
			}
			if key := resolutionKey(node); key != "" {
				b := base(node)
				if distinct[b] == nil {
					distinct[b] = make(map[string]struct{})
				}
				distinct[b][key] = struct{}{}
			}
		}
	}

	for entryIndex, entry := range entries {
		if entry.Graph == nil {
			continue
		}
		var contested []*sdk.Dependency
		for _, node := range entry.Graph.Nodes() {
			if node == nil {
				continue
			}
			if len(distinct[base(node)]) < 2 {
				continue
			}
			if detectors.IsProjectOwned(node) {
				// The project's own record is not an occurrence of an
				// external resolution: it keeps its identity. Its key still
				// counted above, so a contested external record is renamed
				// away from it rather than folding into it.
				continue
			}
			if key := resolutionKey(node); key != "" {
				contested = append(contested, node)
			}
		}
		for _, node := range contested {
			renamed := detectors.OccurrenceID(base(node), resolutionKey(node))
			renameNode(entry.Graph, node, renamed)
			if renames[entryIndex] == nil {
				renames[entryIndex] = make(map[string]string)
			}
			renames[entryIndex][node.ID] = renamed
		}
	}
	return renames
}

// resolutionKey identifies which resolution a record witnesses: the
// normalized origin when one is publishable, else the manifest's raw
// resolution string. A registry record has no publishable origin but is still
// a distinct resolution from a git one, and must not fold into it. The raw
// form is only ever hashed into an occurrence ID, never published.
func resolutionKey(node *sdk.Dependency) string {
	if key := originKey(node.Origin); key != "" {
		return key
	}
	if raw := strings.TrimSpace(node.ResolvedURL); raw != "" {
		return raw
	}
	if detectors.IsProjectOwned(node) {
		// The project's own record is a resolution in its own right -- the
		// local source tree -- even when no resolution string exists. Without
		// this, an external record sharing its PURL reads as uncontested,
		// keeps the canonical ID, and the merge collapses the application
		// into the fetched dependency. Ordinary records with no resolution
		// stay empty-keyed, so gap-filling for origin-silent records is
		// unaffected.
		return "\x00first-party"
	}
	return ""
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
