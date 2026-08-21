package detectors

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/bomly-dev/bomly-sdk"
)

// EnsureNode inserts node into g, or returns the node already carrying its ID.
//
// Every detector needs this: a lockfile can name one package more than once,
// and the graph keeps one node per ID. Doing the existence check by hand is
// what left a dozen detectors silently discarding duplicate records' data --
// each copy of the check was written independently and never revisited. Use
// this rather than calling Graph.AddNode after a Node lookup, so a detector
// added later inherits the shared behavior instead of having to know about it.
//
// EnsureNode deliberately merges nothing. Records that genuinely differ are
// different occurrences and belong in distinct nodes under distinct IDs (the
// caller decides identity); records that are the same need nothing merged.
func EnsureNode(g *sdk.Graph, node *sdk.Dependency) (*sdk.Dependency, error) {
	if g == nil || node == nil {
		return nil, nil
	}
	if existing, ok := g.Node(node.ID); ok {
		return existing, nil
	}
	if err := g.AddNode(node); err != nil {
		return nil, fmt.Errorf("add node %q: %w", node.ID, err)
	}
	return node, nil
}

// OriginsConflict reports whether two records assert different publishable
// origins. Absence is never a conflict, and neither is one location written
// two ways: contradiction means both publish and they disagree. Callers use
// this to decide that two records are distinct occurrences deserving distinct
// nodes, never to pick a winner.
func OriginsConflict(left, right *sdk.DependencyOrigin) bool {
	l, r := left.Normalized(), right.Normalized()
	if l == nil || r == nil {
		return false
	}
	return *l != *r
}

// OccurrenceID derives a distinct node ID for an additional occurrence of a
// package, qualified by what distinguishes it. The qualifier is hashed rather
// than embedded: node IDs become SBOM component identifiers (CycloneDX
// bom-refs, SPDX element IDs), and a raw source string can carry credentials
// or tokens that every other path in this feature exists to keep out of
// published documents.
func OccurrenceID(baseID, qualifier string) string {
	digest := sha256.Sum256([]byte(qualifier))
	return baseID + "#" + hex.EncodeToString(digest[:6])
}
