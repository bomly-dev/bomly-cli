package yarn

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

const maxFuzzInputSize = 1 << 20

func FuzzDepGraphFromYarnLockfile(f *testing.F) {
	for _, seed := range []string{
		"left-pad@^1.3.0:\n  version \"1.3.0\"\n  resolved \"https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz\"\n  integrity sha512-seed\n",
		"\"@scope/pkg@npm:1.0.0\":\n  version: 1.0.0\n  resolution: \"@scope/pkg@npm:1.0.0\"\n  dependencies:\n    left-pad: ^1.3.0\nleft-pad@^1.3.0:\n  version: 1.3.0\n",
		"__metadata:\n  version: 8\n  cacheKey: 10\n",
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > maxFuzzInputSize {
			return
		}
		projectDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(projectDir, "yarn.lock"), raw, 0o644); err != nil {
			t.Fatalf("write yarn.lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(projectDir, "package.json"), []byte(`{"name":"demo","version":"1.0.0","dependencies":{"left-pad":"^1.3.0"}}`), 0o644); err != nil {
			t.Fatalf("write package.json: %v", err)
		}

		graph, err := depGraphFromYarnLockfile(projectDir)
		if err != nil {
			return
		}
		requireFuzzGraphValid(t, graph)
	})
}

func requireFuzzGraphValid(t *testing.T, graph *sdk.Graph) {
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
