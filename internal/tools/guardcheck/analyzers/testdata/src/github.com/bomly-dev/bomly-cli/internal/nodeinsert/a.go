package nodeinsert

import (
	"github.com/bomly-dev/bomly-sdk/detectorkit"
	"github.com/bomly-dev/bomly-sdk/model"
)

type pkg struct{ id string }

func (p *pkg) NodeID() string         { return p.id }
func (p *pkg) Clone() model.GraphNode { return &pkg{id: p.id} }

// The shape that passes: the helper decides what happens to a duplicate.
func viaHelper(g *model.Graph, p *pkg) error {
	_, err := detectorkit.EnsureNode(g, p)
	return err
}

// The shape the rule was first written against: an identifier argument.
func identArgument(g *model.Graph, id string, p *pkg) error {
	if _, ok := g.Node(id); !ok { // want `lookup-then-insert on g`
		return g.AddNode(p)
	}
	return nil
}

// The shape the regex this replaced walked past: the argument is a call.
func callArgument(g *model.Graph, p *pkg) error {
	if _, exists := g.Node(p.NodeID()); !exists { // want `lookup-then-insert on g`
		if err := g.AddNode(p.Clone()); err != nil {
			return err
		}
	}
	return nil
}

// A lookup on one graph and an insert on another are not the hazard.
func differentGraphs(from, to *model.Graph, p *pkg) error {
	if _, ok := from.Node(p.NodeID()); ok {
		return to.AddNode(p)
	}
	return nil
}

// An insert before the lookup is not the hazard either.
func insertThenLookup(g *model.Graph, p *pkg) bool {
	_ = g.AddNode(p)
	_, ok := g.Node(p.NodeID())
	return ok
}

// A field receiver pairs on its spelling like any other.
type holder struct{ graph *model.Graph }

func (h *holder) fieldReceiver(p *pkg) error {
	if _, ok := h.graph.Node(p.NodeID()); !ok { // want `lookup-then-insert on h.graph`
		return h.graph.AddNode(p)
	}
	return nil
}

// A lookup in the function paired with an insert in a closure it runs.
func viaClosure(g *model.Graph, p *pkg) error {
	_, ok := g.Node(p.NodeID()) // want `lookup-then-insert on g`
	add := func() error { return g.AddNode(p) }
	if !ok {
		return add()
	}
	return nil
}

// A package-level literal is a function body too.
var atPackageLevel = func(g *model.Graph, p *pkg) error {
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
func viaAlias(g *model.Graph, p *pkg) error {
	alias := g
	if _, ok := g.Node(p.NodeID()); !ok { // want `lookup-then-insert on g`
		return alias.AddNode(p)
	}
	return nil
}

// An alias declared with var, and assigned rather than defined.
func viaAssignedAlias(g *model.Graph, p *pkg) error {
	var alias *model.Graph
	alias = g
	_, ok := alias.Node(p.NodeID()) // want `lookup-then-insert on alias`
	if !ok {
		return g.AddNode(p)
	}
	return nil
}

// A shadowing name in an inner scope is a different graph, not this one.
func shadowed(g *model.Graph, p *pkg) error {
	_, ok := g.Node(p.NodeID())
	{
		g := &model.Graph{}
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
	var alias *model.Graph = h.graph
	if _, ok := alias.Node(p.NodeID()); !ok { // want `lookup-then-insert on alias`
		return h.graph.AddNode(p)
	}
	return nil
}

// A variable reassigned to another graph folds both identities for the
// whole body, so the pair is reported rather than missed: the analyzer errs
// toward a red a reviewer reads.
func reassigned(first, second *model.Graph, p *pkg) error {
	_, ok := first.Node(p.NodeID()) // want `lookup-then-insert on first`
	first = second
	if !ok {
		return second.AddNode(p)
	}
	return nil
}

// The same under a conditional reassignment.
func conditionallyReassigned(first, second *model.Graph, p *pkg, swap bool) error {
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
func closureDeclaredFirst(g *model.Graph, p *pkg) error {
	add := func() error { return g.AddNode(p) }
	_, ok := g.Node(p.NodeID()) // want `lookup-then-insert on g`
	if !ok {
		return add()
	}
	return nil
}

// A closure on a different graph declared first is still not the hazard.
func closureOnOtherGraph(from, to *model.Graph, p *pkg) error {
	add := func() error { return to.AddNode(p) }
	if _, ok := from.Node(p.NodeID()); ok {
		return add()
	}
	return nil
}

// Method values hide which graph a call acts on, so taking one is reported.
func methodValues(g *model.Graph, p *pkg) error {
	lookup, insert := g.Node, g.AddNode // want `takes g.Node as a value` `takes g.AddNode as a value`
	if _, ok := lookup(p.NodeID()); !ok {
		return insert(p)
	}
	return nil
}

// A method expression is the same capability.
func methodExpression(g *model.Graph, p *pkg) error {
	return (*model.Graph).AddNode(g, p) // want `takes \(\*model.Graph\).AddNode as a value`
}

// A method value of a method the check does not pair is not reported.
func otherMethodValue(g *model.Graph, p *pkg) error {
	insert := g.InsertNode
	_, err := insert(p)
	return err
}
