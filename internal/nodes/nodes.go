// Package nodes reads graph nodes of any kind.
//
// ADR-0041 made the graph a sealed union of manifest, module, and dependency
// nodes, and the GraphNode interface deliberately exposes only what every kind
// has: an ID, a kind, locations, warnings. Everything else -- coordinates, a
// display name, a scope -- belongs to some kinds and not others, so every
// caller that renders or narrows a node needs the same type switch.
//
// Written once per caller, that switch disagrees with itself: one copy treats
// a manifest as an empty package, another as a package with no name, a third
// forgets the kind exists and falls through to a nil dereference. This package
// is the single place that decides what each kind looks like to a reader.
//
// Reading only. Helpers that build or mutate a detector graph -- EnsureNode,
// PromoteToModule, PropagateScopes -- stay in internal/detectors, next to the
// code that constructs graphs.
//
// The deepest home for this is the SDK, which owns what a node means
// (ADR-0040); it is here because the union shipped in bomly-sdk v0.8.0 without
// a coordinates accessor and the CLI adoption cannot wait for the next SDK
// release. Tracked as bomly-dev/bomly-sdk#33: once the SDK exposes it, this
// package delegates.
package nodes

import (
	"strings"

	sdk "github.com/bomly-dev/bomly-sdk"
)

// Coordinates returns the package coordinates a node carries, and reports
// whether it carries any. Manifest nodes do not: a file is not a package.
func Coordinates(node sdk.GraphNode) (sdk.Coordinates, bool) {
	switch typed := node.(type) {
	case *sdk.DependencyNode:
		if typed == nil {
			return sdk.Coordinates{}, false
		}
		return typed.Coordinates, true
	case *sdk.ModuleNode:
		if typed == nil {
			return sdk.Coordinates{}, false
		}
		return typed.Coordinates, true
	default:
		return sdk.Coordinates{}, false
	}
}

// Display pulls the fields a list or a path label renders, from any kind.
// A manifest renders as its path, which is the only name it has.
func Display(node sdk.GraphNode) (name, version, scope, ecosystem string) {
	switch typed := node.(type) {
	case *sdk.DependencyNode:
		if typed == nil {
			return "", "", "", ""
		}
		return typed.DisplayName(), typed.Version, string(typed.PrimaryScope()), string(typed.Ecosystem)
	case *sdk.ModuleNode:
		if typed == nil {
			return "", "", "", ""
		}
		return typed.DisplayName(), typed.Version, "", string(typed.Ecosystem)
	case *sdk.ManifestNode:
		if typed == nil {
			return "", "", "", ""
		}
		return typed.Path, "", "", ""
	default:
		return "", "", "", ""
	}
}

// Label renders a node the way a dependency path shows it: a display name
// with its version appended when the name does not already carry one.
func Label(node sdk.GraphNode) string {
	name, version, _, _ := Display(node)
	if version == "" || strings.HasSuffix(name, "@"+version) {
		return name
	}
	return name + "@" + version
}

// AsDependency narrows a node to a dependency node, reporting whether it is
// one. A typed nil is not.
func AsDependency(node sdk.GraphNode) (*sdk.DependencyNode, bool) {
	dep, ok := node.(*sdk.DependencyNode)
	return dep, ok && dep != nil
}

// DependenciesOf narrows graph nodes to the dependency nodes among them.
//
// Graph traversal yields the union now, and most logic -- scope propagation,
// relationship marking, enrichment -- is about consumed packages
// specifically. Narrowing in one named place keeps every site agreeing about
// what a structural node means: it is skipped, not defaulted.
func DependenciesOf(list []sdk.GraphNode) []*sdk.DependencyNode {
	out := make([]*sdk.DependencyNode, 0, len(list))
	for _, node := range list {
		if dep, ok := AsDependency(node); ok {
			out = append(out, dep)
		}
	}
	return out
}

// IsProjectOwned reports whether a node is the scanned project's own artifact
// -- its root package, a workspace member, a reactor module -- rather than a
// consumed package.
//
// It reads the node kind. ADR-0041 removed the FirstParty flag because
// ownership is what the kind means: the project's own artifacts are module
// nodes, and a dependency node is a consumed package by construction. The
// application package type is no longer sufficient on its own -- an
// application-typed *import* is a consumed package, and treating it as owned
// is what kept such packages out of diffing and matching (ADR-0015).
func IsProjectOwned(node sdk.GraphNode) bool {
	if node == nil {
		return false
	}
	return node.Kind() == sdk.NodeKindModule
}
