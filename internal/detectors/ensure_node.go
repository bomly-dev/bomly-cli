package detectors

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

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

// EnsureOccurrence inserts node, folding it into an existing node only when
// both records claim the same resolution. When the graph already holds this ID
// with a *different* ResolvedURL, the manifest has asserted two resolutions of
// one name@version: the newcomer stays a distinct occurrence under an opaque
// ID derived from qualifier (its stable positional key -- a lockfile path,
// entry key, or source string).
//
// This is the one home for the collision rule. Five detectors grew the same
// hand-written shape one review round at a time before it was centralized;
// route new sites through here.
func EnsureOccurrence(g *sdk.Graph, node *sdk.Dependency, qualifier string) (*sdk.Dependency, error) {
	surviving, err := EnsureNode(g, node)
	if err != nil || surviving == node || surviving == nil {
		return surviving, err
	}
	if strings.TrimSpace(surviving.ResolvedURL) == strings.TrimSpace(node.ResolvedURL) {
		return surviving, nil
	}
	node.ID = OccurrenceID(node.ID, qualifier)
	return EnsureNode(g, node)
}

// IsProjectOwned reports whether dep is the scanned project's own artifact --
// its root package, a workspace member, a reactor module -- rather than a
// consumed package. Detectors mark this in two ways, an explicit FirstParty
// flag or an application package type, and either is enough. The project's own
// records never take an external origin, never fold into an external
// occurrence, and never inherit enrichment resolved from a package identity
// they merely share.
func IsProjectOwned(dep *sdk.Dependency) bool {
	return dep != nil && (dep.FirstParty || dep.Type == sdk.PackageTypeApplication)
}
