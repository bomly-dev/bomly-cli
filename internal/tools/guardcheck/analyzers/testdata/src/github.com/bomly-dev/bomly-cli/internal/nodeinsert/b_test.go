package nodeinsert

import "github.com/bomly-dev/bomly-sdk"

// A test may spell the forbidden shape; the analyzer skips test files, so
// this carries no want comment and must produce no diagnostic.
func inATest(g *sdk.Graph, p *pkg) error {
	if _, ok := g.Node(p.NodeID()); !ok {
		return g.AddNode(p)
	}
	return nil
}
