// Package sdk is a stand-in for bomly-sdk with just the surface the analyzers
// resolve: the graph's lookup and insert methods and the detection result.
package sdk

// GraphNode is a node of a graph.
type GraphNode interface {
	NodeID() string
	Clone() GraphNode
}

// Graph is the dependency graph.
type Graph struct{}

// Node looks a node up by ID.
func (g *Graph) Node(id string) (GraphNode, bool) { return nil, false }

// AddNode inserts a node.
func (g *Graph) AddNode(node GraphNode) error { return nil }

// InsertNode inserts a node or returns the existing one.
func (g *Graph) InsertNode(node GraphNode) (GraphNode, error) { return node, nil }

// GraphContainer carries resolved graphs.
type GraphContainer struct{}

// DetectionResult is what a detector returns.
type DetectionResult struct {
	DetectorName string
	Graphs       *GraphContainer
}
