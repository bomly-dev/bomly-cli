package detectors

import (
	"errors"
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
// The fold itself is the SDK's (ADR-0041): Graph.InsertNode unions scopes,
// locations and origins onto the survivor. This wrapper exists for the typed
// return and the nil tolerance detectors rely on -- the rule lives in one
// place, and that place is now the model rather than here.
//
// It is generic in the node type so a caller inserting a module gets a module
// back without asserting. A survivor of a different kind is an error rather
// than a silent nil: two nodes sharing one ID across kinds means the ID
// grammars collided, and a detector must not carry on with a node that is not
// what it built.
func EnsureNode[T sdk.GraphNode](g *sdk.Graph, node T) (T, error) {
	var zero T
	// A typed nil is not an untyped one: comparing the interface against nil
	// is false for (*DependencyNode)(nil), and the next call dereferences it.
	if g == nil || isNilNode(node) {
		return zero, nil
	}
	inserted, err := g.InsertNode(node)
	if err != nil {
		return zero, fmt.Errorf("add node %q: %w", node.NodeID(), err)
	}
	surviving, ok := inserted.(T)
	if !ok {
		return zero, fmt.Errorf("node %q already exists as a %s node", node.NodeID(), inserted.Kind())
	}
	return surviving, nil
}

// isNilNode reports whether a node value carries no node, typed nil included.
func isNilNode(node sdk.GraphNode) bool {
	switch typed := node.(type) {
	case nil:
		return true
	case *sdk.DependencyNode:
		return typed == nil
	case *sdk.ModuleNode:
		return typed == nil
	case *sdk.ManifestNode:
		return typed == nil
	default:
		return false
	}
}

// Occurrence machinery -- OriginsConflict, OccurrenceID, EnsureOccurrence --
// was deleted with ADR-0041. Identity is the canonical package URL and is
// unique by construction, so there is no suffix to mint and nothing to
// qualify: two records that resolved one name@version from different places
// fold into one node whose Origins list carries both. That list is the
// dependency-confusion signal the suffixes were standing in for, and it says
// more than two nodes did, because it keeps the disagreement on one identity
// rather than splitting it across two.
//
// Cargo is the case that made this worth checking rather than assuming.
// Its package IDs are source-qualified upstream, so one crate name and
// version can appear twice -- from two git remotes, or from a git remote and
// the registry -- and cargo builds both: it has no nearest-wins rule, and the
// crate that asked for each gets the one it asked for. Those really are two
// pieces of code in the artifact.
//
// They still fold, and folding is the right answer here rather than a
// concession. Identity is the canonical package URL, and a cargo PURL carries
// no source: both records mint "pkg:cargo/<name>@<version>" whatever they
// resolved from. Keeping them apart would produce two components with byte-
// identical identity -- same purl, same package reference, same matching
// result, same vulnerabilities -- which is the duplicate-identity problem
// ADR-0041 exists to remove, and it is worse than one node that records both
// sources. Nothing is lost: Origins is union-merged, so the node carries
// every source it was resolved from, which is the dependency-confusion signal
// the old distinct nodes were standing in for.
//
// What would reopen this: cargo PURLs gaining a source qualifier (the three
// URL-valued keys cannot serve -- SplitIdentity relocates them into origins),
// or matching keying on origin rather than on the package URL. Either makes
// the two genuinely distinguishable, and then they deserve distinct nodes.

// PromoteToModule replaces a node with a module node declared by a manifest
// path, keeping its edges, and returns the surviving node's ID.
//
// A node's kind and identity are both fixed at construction under ADR-0041, so
// a detector that only learns ownership later -- Maven learns which graph
// roots are reactor modules after parsing the dependency tree, and which
// directory declares each one later still -- cannot set a flag or rewrite an
// ID afterwards. It replaces the node instead, and this is the one place that
// knows how: build the module, re-point every edge, remove the old node.
//
// It is idempotent for the path it is given: a module already declared by that
// manifest is returned unchanged, and one declared by another manifest is
// re-minted, because the declaring path is part of a module's identity.
//
// Edges are re-added by ID, so callers must not hold node pointers across the
// call; the returned ID is what to hold instead.
func PromoteToModule(g *sdk.Graph, nodeID, manifestPath string) (string, error) {
	if g == nil || strings.TrimSpace(nodeID) == "" {
		return nodeID, nil
	}
	existing, ok := g.Node(nodeID)
	if !ok {
		return nodeID, nil
	}

	var coords sdk.Coordinates
	var locations []sdk.PackageLocation
	switch typed := existing.(type) {
	case *sdk.DependencyNode:
		coords, locations = typed.Coordinates, typed.Locations
	case *sdk.ModuleNode:
		if typed.DeclaringManifestPath == manifestPath {
			return nodeID, nil
		}
		coords, locations = typed.Coordinates, typed.Locations
	default:
		// A manifest node is already structural and declares nothing.
		return nodeID, nil
	}

	module, err := sdk.NewModuleNode(manifestPath, coords)
	if err != nil {
		return nodeID, fmt.Errorf("promote %q to a module node: %w", nodeID, err)
	}
	if module.NodeID() == nodeID {
		return nodeID, nil
	}
	module.Locations = append([]sdk.PackageLocation(nil), locations...)

	parents, _ := g.Dependents(nodeID)
	children, _ := g.DirectDependencies(nodeID)
	parentIDs := make([]string, 0, len(parents))
	for _, parent := range parents {
		parentIDs = append(parentIDs, parent.NodeID())
	}
	childIDs := make([]string, 0, len(children))
	for _, child := range children {
		childIDs = append(childIDs, child.NodeID())
	}

	g.RemoveNode(nodeID)
	surviving, err := g.InsertNode(module)
	if err != nil {
		return nodeID, fmt.Errorf("insert promoted module %q: %w", module.NodeID(), err)
	}
	survivingID := surviving.NodeID()
	for _, parentID := range parentIDs {
		if parentID == survivingID {
			continue
		}
		if err := g.AddEdge(parentID, survivingID); err != nil && !errors.Is(err, sdk.ErrSelfDependency) {
			return survivingID, fmt.Errorf("re-point %q -> %q: %w", parentID, survivingID, err)
		}
	}
	for _, childID := range childIDs {
		if childID == survivingID {
			continue
		}
		if err := g.AddEdge(survivingID, childID); err != nil && !errors.Is(err, sdk.ErrSelfDependency) {
			return survivingID, fmt.Errorf("re-point %q -> %q: %w", survivingID, childID, err)
		}
	}
	return survivingID, nil
}
