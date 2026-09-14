package resolvedurl

import (
	"reflect"

	"github.com/bomly-dev/bomly-sdk"
)

// No comment in this file may spell the banned name either: the rule reads
// comments too, and the want patterns below split it for that reason.
type node struct {
	ResolvedURL string // want `names Resolv.dURL \(as an identifier\)`
	Origin      string
}

// The field read the rule exists for.
func fieldRead(n node) string {
	return n.ResolvedURL // want `names Resolv.dURL \(as an identifier\)`
}

// Reached through reflection by name: the string is the access.
func viaReflection(n node) string {
	return reflect.ValueOf(n).FieldByName("ResolvedURL").String() // want `names Resolv.dURL \(inside a string\)`
}

// A composite literal key.
func literalKey() node {
	return node{ResolvedURL: "x"} // want `names Resolv.dURL \(as an identifier\)`
}

// What export does instead.
func normalized(n node) string {
	return n.Origin
}

// The SDK's graph is fine to touch; the rule is about one name.
func graph(g *sdk.Graph) { _, _ = g.Node("id") }
