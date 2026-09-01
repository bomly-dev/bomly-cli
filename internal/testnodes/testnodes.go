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
package testnodes

import (
	"fmt"
	"strings"

	sdk "github.com/bomly-dev/bomly-sdk"
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
// coordinates, which is the whole point of the constructor.
func DepFrom(proto sdk.DependencyNode) *sdk.DependencyNode {
	node := Dep(proto.Coordinates)
	node.Relationship = proto.Relationship
	node.Source = proto.Source
	node.Scopes = append([]sdk.Scope(nil), proto.Scopes...)
	node.Locations = append([]sdk.PackageLocation(nil), proto.Locations...)
	node.CPEs = append([]string(nil), proto.CPEs...)
	node.Digests = append([]sdk.Digest(nil), proto.Digests...)
	node.Copyright = proto.Copyright
	node.FoundBy = proto.FoundBy
	node.ResolvedURL = proto.ResolvedURL
	node.Origins = append([]sdk.DependencyOrigin(nil), proto.Origins...)
	node.Licenses = append([]sdk.PackageLicense(nil), proto.Licenses...)
	node.Description = proto.Description
	node.Homepage = proto.Homepage
	node.Supplier = proto.Supplier
	node.Originator = proto.Originator
	node.ExternalReferences = append([]sdk.ExternalReference(nil), proto.ExternalReferences...)
	node.Metadata = proto.Metadata
	node.Matched = proto.Matched
	node.PackageRef = proto.PackageRef
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
//
// Node IDs are canonical package URLs now (ADR-0041), so a test can no longer
// look a node up by the label it was built from. Rewriting every lookup to a
// PURL string would spread the identity rules across hundreds of literals and
// hide, rather than pin, what each case is about -- so the label stays and
// this resolves it.
//
// A label matches a node's ID outright, or its name and version in any of the
// spellings a node answers to: the bare name, the ecosystem-native name, and
// the display name. A label with no version matches on name alone, which is
// what a module or manifest label looks like.
func Find(g *sdk.Graph, label string) (sdk.GraphNode, bool) {
	if g == nil {
		return nil, false
	}
	if node, ok := g.Node(label); ok {
		return node, true
	}
	name, version := splitLabel(label)
	for _, node := range g.Nodes() {
		if labelMatches(node, name, version) {
			return node, true
		}
	}
	return nil, false
}

// FindDep is Find narrowed to a dependency node.
func FindDep(g *sdk.Graph, label string) (*sdk.DependencyNode, bool) {
	node, ok := Find(g, label)
	if !ok {
		return nil, false
	}
	dep, isDependency := node.(*sdk.DependencyNode)
	return dep, isDependency
}

// splitLabel splits "name@version" at the last "@", so a scoped npm name
// ("@scope/pkg@1.2.3") splits where it should.
func splitLabel(label string) (name, version string) {
	if at := strings.LastIndex(label, "@"); at > 0 {
		return label[:at], label[at+1:]
	}
	return label, ""
}

func labelMatches(node sdk.GraphNode, name, version string) bool {
	var coords sdk.Coordinates
	switch typed := node.(type) {
	case *sdk.DependencyNode:
		coords = typed.Coordinates
	case *sdk.ModuleNode:
		coords = typed.Coordinates
	case *sdk.ManifestNode:
		return version == "" && typed.Path == name
	default:
		return false
	}
	if version != "" && coords.Version != version {
		return false
	}
	for _, spelling := range []string{coords.Name, coords.EcosystemName(), coords.DisplayName()} {
		if spelling == name {
			return true
		}
	}
	return false
}
