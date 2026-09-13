// Package detectorkit is a stand-in for bomly-sdk/detectorkit.
package detectorkit

import "github.com/bomly-dev/bomly-sdk"

// EnsureNode inserts node or returns the node already there.
func EnsureNode[T sdk.GraphNode](g *sdk.Graph, node T) (T, error) {
	var zero T
	inserted, err := g.InsertNode(node)
	if err != nil {
		return zero, err
	}
	return inserted.(T), nil
}
