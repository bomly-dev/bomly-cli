package consolidation

import (
	"fmt"

	"github.com/bomly-dev/bomly-sdk"
)

// normalizeGraphPackageIdentity rebuilds a graph so one canonical identity is
// one node.
//
// It used to do considerably more: rewrite each node's ID into canonical form,
// mint a StableID when none could be derived, split records that disagreed
// about their resolution into suffixed occurrence IDs, and arbitrate which
// record got to keep the unsuffixed slot. ADR-0041 removed the need for all of
// it. A node's ID is its canonical package URL, minted by the constructor and
// unique by construction, so there is nothing to rewrite and no suffix to
// mint; two records of one identity fold, and Graph.InsertNode is the fold.
//
// Keeping any of that machinery would mean two identity systems in one
// pipeline, disagreeing about which node a reference names.
func normalizeGraphPackageIdentity(src *sdk.Graph) (*sdk.Graph, error) {
	if src == nil {
		return nil, nil
	}

	normalized := sdk.NewWithCapacity(src.Size())
	// Every node kind is carried, not just dependencies: manifests and modules
	// are the structure the edges hang off, and dropping them here would strip
	// a scan of its subproject layout.
	src.WalkNodes(func(node sdk.GraphNode) bool {
		_, _ = normalized.InsertNode(node.CloneNode())
		return true
	})

	// Edges follow, keeping their kind. An edge that became a self-edge
	// because both ends folded into one node is dropped rather than being an
	// error: folding two nodes into one legitimately collapses the edge
	// between them.
	if err := sdk.CopyEdgesInto(normalized, src, nil); err != nil {
		return nil, fmt.Errorf("copy normalized edges: %w", err)
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
		for _, node := range entry.Graph.DependencyNodes() {
			if node == nil {
				continue
			}
			purl := node.NodeID()
			if purl == "" {
				continue
			}
			node.PackageRef = purl
			pkg := registry.Add(sdk.PackageFromDependencyNode(node))
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

// The occurrence cluster that lived here -- preserveContradictingOccurrences,
// foldWitness, hasLocation, resolutionKey, originKey, renameNode -- was
// deleted with ADR-0041. It existed to give two records of one identity two
// node IDs and then reconcile what that split, which is no longer a problem
// the pipeline has: identity is minted by the constructor, and two records of
// it fold through Graph.InsertNode, whose fold already unions scopes,
// locations and origins.

// addNodeIfMissing inserts a node, folding it into the existing one when the
// graph already holds its identity.
//
// The fold is the SDK's: Graph.InsertNode unions scopes, locations and
// origins, and merges the relationship. This used to hand-write a narrower
// version of that -- relationship plus a single fill-gaps origin -- which lost
// every scope and location the duplicate carried.
func addNodeIfMissing(g *sdk.Graph, node *sdk.DependencyNode) error {
	if node == nil {
		return nil
	}
	if _, err := g.InsertNode(node.Clone()); err != nil {
		return fmt.Errorf("add dependency %q: %w", node.NodeID(), err)
	}
	return nil
}
