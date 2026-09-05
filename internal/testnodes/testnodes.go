// Package testnodes builds graph nodes for tests.
//
// Node identity is minted by a constructor now (ADR-0041), so a fixture can no
// longer be written as a struct literal with a hand-chosen ID. Every fixture
// has to go through NewDependencyNode or NewModuleNode and handle the error --
// which, repeated across hundreds of table entries, buries what each test is
// actually about.
//
// These helpers take the fixture shapes the tests already used and route them
// through the real constructors. They panic rather than returning an error: a
// fixture whose coordinates cannot mint an identity is a broken test, not a
// condition under test. Tests that mean to exercise a rejected identity call
// the SDK constructor directly and assert on the error.
//
// What each helper does NOT own is the rule it applies. Constructing a node
// belongs to the SDK constructors, and resolving a "name@version" label to a
// node belongs to bomly-sdk/testkit: a second copy of the label rules is a
// second answer to "which node is this", and the two drifted the first time
// they existed side by side. What is left here is the shape the CLI's own
// fixtures are written in -- helpers that panic instead of taking a
// testing.TB, so a table entry stays one expression.
package testnodes

import (
	"fmt"

	sdk "github.com/bomly-dev/bomly-sdk"
	"github.com/bomly-dev/bomly-sdk/testkit"
)

// Dep builds a dependency node from coordinates.
func Dep(coords sdk.Coordinates) *sdk.DependencyNode {
	node, err := sdk.NewDependencyNode(coords)
	if err != nil {
		panic(fmt.Sprintf("testnodes: build dependency node %q: %v", coords.Name, err))
	}
	return node
}

// DepFrom builds a dependency node from a prototype, copying every field the
// prototype states onto the constructed node.
//
// It exists so a test can keep describing a fixture as one literal. The
// identity fields are not copied: they are minted from the prototype's
// coordinates, which is the whole point of the constructor. The field list is
// the SDK's, so a field added to the model reaches these fixtures with the
// producers rather than one release later.
func DepFrom(proto sdk.DependencyNode) *sdk.DependencyNode {
	node, err := sdk.NewDependencyNodeFrom(proto)
	if err != nil {
		panic(fmt.Sprintf("testnodes: build dependency node %q: %v", proto.Name, err))
	}
	return node
}

// Ref builds a dependency node from a bare name and version. Coordinates with
// no ecosystem mint a pkg:generic identity, which is what these fixtures want:
// a node that exists and has an ID, with nothing said about where it came
// from.
func Ref(name, version string) *sdk.DependencyNode {
	return Dep(sdk.Coordinates{Name: name, Version: version})
}

// Module builds a module node -- the scanned project's own artifact -- from
// the manifest that declares it plus a bare name and version.
func Module(manifestPath, name, version string) *sdk.ModuleNode {
	return ModuleFrom(manifestPath, sdk.Coordinates{Name: name, Version: version})
}

// ModuleFrom builds a module node from full coordinates.
func ModuleFrom(manifestPath string, coords sdk.Coordinates) *sdk.ModuleNode {
	node, err := sdk.NewModuleNode(manifestPath, coords)
	if err != nil {
		panic(fmt.Sprintf("testnodes: build module node %q: %v", coords.Name, err))
	}
	return node
}

// Manifest builds a manifest node.
func Manifest(path string, kind sdk.ManifestKind) *sdk.ManifestNode {
	node, err := sdk.NewManifestNode(path, kind)
	if err != nil {
		panic(fmt.Sprintf("testnodes: build manifest node %q: %v", path, err))
	}
	return node
}

// Find returns the node a "name@version" label names, and whether one matched.
func Find(g *sdk.Graph, label string) (sdk.GraphNode, bool) {
	return testkit.FindNode(g, label)
}

// FindDep is Find narrowed to a dependency node.
func FindDep(g *sdk.Graph, label string) (*sdk.DependencyNode, bool) {
	return testkit.FindDependencyNode(g, label)
}

// ID returns the node ID a "name@version" label names, or the label unchanged
// when no node matches -- so a lookup that is meant to fail still fails, with
// the label in the error where a reader expects it.
//
// Use it where a graph method takes an ID rather than returning a node:
// DirectDependencies, Dependents, CollectPathsTo.
func ID(g *sdk.Graph, label string) string {
	return testkit.NodeID(g, label)
}

// Is reports whether a node answers to a "name@version" label: by ID, or by
// any of the spellings its coordinates carry.
//
// It is the comparison form of Find, for the many assertions that hold a node
// and want to know which one it is. An exact ID still matches exactly, so a
// case that names a package URL keeps asserting on the package URL.
func Is(node sdk.GraphNode, label string) bool {
	return testkit.NodeIs(node, label)
}
