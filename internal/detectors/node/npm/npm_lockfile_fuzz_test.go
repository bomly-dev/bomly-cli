package npm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/detectors/node/nodetest"
)

func FuzzDepGraphFromNPMLockfile(f *testing.F) {
	for _, seed := range []string{
		`{"name":"demo","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"demo","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}},"node_modules/left-pad":{"name":"left-pad","version":"1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz","integrity":"sha512-seed"}}}`,
		`{"name":"demo","version":"1.0.0","lockfileVersion":1,"dependencies":{"left-pad":{"version":"1.3.0","dependencies":{"repeat-string":{"version":"1.6.1"}}}}}`,
		`{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"benchmark":"1.0.0"}},"node_modules/benchmark":{"version":"1.0.0","engines":["node","rhino"]}}}`,
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > nodetest.MaxFuzzInputSize {
			return
		}
		projectDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(projectDir, "package-lock.json"), raw, 0o644); err != nil {
			t.Fatalf("write package-lock.json: %v", err)
		}

		graph, err := depGraphFromNPMLockfile(projectDir)
		if err != nil {
			return
		}
		nodetest.RequireFuzzGraphValid(t, graph)
	})
}
