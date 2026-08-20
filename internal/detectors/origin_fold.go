package detectors

import (
	"fmt"

	"github.com/bomly-dev/bomly-sdk"
)

// FoldOrigin settles package origin when two records of one package become one
// node. Call it at every such point -- graph deduplication, name indexes,
// dependency-group merges -- so the surviving node never reports one record's
// answer as though the other did not exist.
//
// survivor is the node that will remain; replaced is the record it stands in
// for. Which is which does not affect the outcome, because reconciliation is
// symmetric: records that agree keep their origin, a record asserting nothing
// leaves an existing one standing, and records that disagree cancel and stay
// cancelled. The argument names say what is happening rather than what the
// caller must get right.
//
// This exists because the rule was repeatedly rediscovered one call site at a
// time: a lockfile listing one package twice, two dependency groups naming
// different sources, two manifests resolving one package differently. Each
// missed site published whichever record happened to be walked first as if it
// were the only one. Route new folds through here rather than writing the
// reconciliation by hand.
func FoldOrigin(survivor, replaced *sdk.Dependency) {
	if survivor == nil || replaced == nil {
		return
	}
	survivor.Origin = sdk.ReconcileOrigin(survivor.Origin, replaced.Origin)
}

// AddNodeFolding inserts node into g, or folds it into the node already
// carrying its ID, and returns whichever node now represents the package.
//
// Every detector needs this: a lockfile can name one package more than once,
// and the graph keeps one node for it. Doing the existence check by hand is
// what left package origin silently dropped in a dozen detectors -- each copy
// of the check was written before origin existed and never revisited. Use this
// rather than calling Graph.AddNode after a Node lookup, so a detector added
// later inherits the folding instead of having to know about it.
func AddNodeFolding(g *sdk.Graph, node *sdk.Dependency) (*sdk.Dependency, error) {
	if g == nil || node == nil {
		return nil, nil
	}
	if existing, ok := g.Node(node.ID); ok {
		FoldOrigin(existing, node)
		return existing, nil
	}
	if err := g.AddNode(node); err != nil {
		return nil, fmt.Errorf("add node %q: %w", node.ID, err)
	}
	return node, nil
}
