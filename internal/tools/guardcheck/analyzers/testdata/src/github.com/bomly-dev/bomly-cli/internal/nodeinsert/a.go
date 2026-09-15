package nodeinsert

import (
	"github.com/bomly-dev/bomly-sdk"
	"github.com/bomly-dev/bomly-sdk/detectorkit"
)

type pkg struct{ id string }

func (p *pkg) NodeID() string       { return p.id }
func (p *pkg) Clone() sdk.GraphNode { return &pkg{id: p.id} }

// The shape that passes: the helper decides what happens to a duplicate.
func viaHelper(g *sdk.Graph, p *pkg) error {
	_, err := detectorkit.EnsureNode(g, p)
	return err
}

// The shape the rule was first written against: an identifier argument.
func identArgument(g *sdk.Graph, id string, p *pkg) error {
	if _, ok := g.Node(id); !ok { // want `lookup-then-insert on g`
		return g.AddNode(p)
	}
	return nil
}

// The shape the regex this replaced walked past: the argument is a call.
func callArgument(g *sdk.Graph, p *pkg) error {
	if _, exists := g.Node(p.NodeID()); !exists { // want `lookup-then-insert on g`
		if err := g.AddNode(p.Clone()); err != nil {
			return err
		}
	}
	return nil
}

// A lookup on one graph and an insert on another are not the hazard.
func differentGraphs(from, to *sdk.Graph, p *pkg) error {
	if _, ok := from.Node(p.NodeID()); ok {
		return to.AddNode(p)
	}
	return nil
}

// An insert before the lookup is not the hazard either.
func insertThenLookup(g *sdk.Graph, p *pkg) bool {
	_ = g.AddNode(p)
	_, ok := g.Node(p.NodeID())
	return ok
}

// A field receiver pairs on its spelling like any other.
type holder struct{ graph *sdk.Graph }

func (h *holder) fieldReceiver(p *pkg) error {
	if _, ok := h.graph.Node(p.NodeID()); !ok { // want `lookup-then-insert on h.graph`
		return h.graph.AddNode(p)
	}
	return nil
}

// A lookup in the function paired with an insert in a closure it runs.
func viaClosure(g *sdk.Graph, p *pkg) error {
	_, ok := g.Node(p.NodeID()) // want `lookup-then-insert on g`
	add := func() error { return g.AddNode(p) }
	if !ok {
		return add()
	}
	return nil
}

// A package-level literal is a function body too.
var atPackageLevel = func(g *sdk.Graph, p *pkg) error {
	if _, ok := g.Node(p.NodeID()); !ok { // want `lookup-then-insert on g`
		return g.AddNode(p)
	}
	return nil
}

// A local type with the same method names is not the SDK graph.
type localGraph struct{}

func (localGraph) Node(id string) (any, bool) { return nil, false }
func (localGraph) AddNode(n any) error        { return nil }

func localType(g localGraph, p *pkg) error {
	if _, ok := g.Node(p.NodeID()); !ok {
		return g.AddNode(p)
	}
	return nil
}

// An alias of the graph is the same graph.
func viaAlias(g *sdk.Graph, p *pkg) error {
	alias := g
	if _, ok := g.Node(p.NodeID()); !ok { // want `lookup-then-insert on g`
		return alias.AddNode(p)
	}
	return nil
}

// An alias declared with var, and assigned rather than defined.
func viaAssignedAlias(g *sdk.Graph, p *pkg) error {
	var alias *sdk.Graph
	alias = g
	_, ok := alias.Node(p.NodeID()) // want `lookup-then-insert on alias`
	if !ok {
		return g.AddNode(p)
	}
	return nil
}

// A shadowing name in an inner scope is a different graph, not this one.
func shadowed(g *sdk.Graph, p *pkg) error {
	_, ok := g.Node(p.NodeID())
	{
		g := &sdk.Graph{}
		if err := g.AddNode(p); err != nil {
			return err
		}
	}
	_ = ok
	return nil
}

// An alias taken from a field folds with the field.
func viaFieldAlias(h *holder, p *pkg) error {
	alias := h.graph
	if _, ok := h.graph.Node(p.NodeID()); !ok { // want `lookup-then-insert on h.graph`
		return alias.AddNode(p)
	}
	return nil
}

// And the other way round: the field aliased to a name, looked up by the
// name, inserted through the field.
func viaFieldAliasReversed(h *holder, p *pkg) error {
	var alias *sdk.Graph = h.graph
	if _, ok := alias.Node(p.NodeID()); !ok { // want `lookup-then-insert on alias`
		return h.graph.AddNode(p)
	}
	return nil
}

// A variable reassigned to another graph folds both identities for the
// whole body, so the pair is reported rather than missed: the analyzer errs
// toward a red a reviewer reads.
func reassigned(first, second *sdk.Graph, p *pkg) error {
	_, ok := first.Node(p.NodeID()) // want `lookup-then-insert on first`
	first = second
	if !ok {
		return second.AddNode(p)
	}
	return nil
}

// The same under a conditional reassignment.
func conditionallyReassigned(first, second *sdk.Graph, p *pkg, swap bool) error {
	_, ok := first.Node(p.NodeID()) // want `lookup-then-insert on first`
	if swap {
		first = second
	}
	if !ok {
		return second.AddNode(p)
	}
	return nil
}

// A closure declared before the lookup and called after it: the insert
// runs after the lookup even though it is written above it.
func closureDeclaredFirst(g *sdk.Graph, p *pkg) error {
	add := func() error { return g.AddNode(p) }
	_, ok := g.Node(p.NodeID()) // want `lookup-then-insert on g`
	if !ok {
		return add()
	}
	return nil
}

// A closure on a different graph declared first is still not the hazard.
func closureOnOtherGraph(from, to *sdk.Graph, p *pkg) error {
	add := func() error { return to.AddNode(p) }
	if _, ok := from.Node(p.NodeID()); ok {
		return add()
	}
	return nil
}
