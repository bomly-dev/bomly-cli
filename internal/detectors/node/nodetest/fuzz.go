package nodetest

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

// MaxFuzzInputSize caps fuzz payloads for lockfile parser targets.
const MaxFuzzInputSize = 1 << 20

// RequireFuzzGraphValid verifies graph invariants shared by node lockfile fuzz tests.
func RequireFuzzGraphValid(t *testing.T, graph *sdk.Graph) {
	t.Helper()
	if graph == nil {
		t.Fatal("successful parse returned nil graph")
	}
	graph.WalkNodes(func(node *sdk.Dependency) bool {
		if node == nil {
			t.Fatal("graph contains nil node")
		}
		if node.ID == "" {
			t.Fatalf("graph contains node with empty ID: %+v", node)
		}
		return true
	})
	graph.WalkEdges(func(from, to *sdk.Dependency) bool {
		if from == nil || to == nil {
			t.Fatalf("graph contains nil edge endpoint: from=%+v to=%+v", from, to)
		}
		if from.ID == "" || to.ID == "" {
			t.Fatalf("graph contains edge with empty endpoint ID: from=%+v to=%+v", from, to)
		}
		return true
	})
}
