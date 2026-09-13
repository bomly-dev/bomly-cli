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
