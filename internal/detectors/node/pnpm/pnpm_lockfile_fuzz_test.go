package pnpm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/detectors/node/nodetest"
)

func FuzzDepGraphFromPNPMLockfile(f *testing.F) {
	for _, seed := range []string{
		"lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      left-pad:\n        version: 1.3.0\npackages:\n  left-pad@1.3.0:\n    resolution:\n      integrity: sha512-seed\nsnapshots:\n  left-pad@1.3.0: {}\n",
		"lockfileVersion: 5.4\ndependencies:\n  react: 18.2.0\npackages:\n  /react/18.2.0:\n    resolution:\n      integrity: sha512-seed\n    dependencies:\n      loose-envify: 1.4.0\n  /loose-envify/1.4.0:\n    resolution:\n      integrity: sha512-seed\n",
		"packages:\n  /@scope/pkg/1.0.0:\n    resolution:\n      tarball: https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz\n",
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > nodetest.MaxFuzzInputSize {
			return
		}
		projectDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(projectDir, "pnpm-lock.yaml"), raw, 0o644); err != nil {
			t.Fatalf("write pnpm-lock.yaml: %v", err)
		}
		if err := os.WriteFile(filepath.Join(projectDir, "package.json"), []byte(`{"name":"demo","version":"1.0.0"}`), 0o644); err != nil {
			t.Fatalf("write package.json: %v", err)
		}

		graph, err := depGraphFromPNPMLockfile(projectDir)
		if err != nil {
			return
		}
		nodetest.RequireFuzzGraphValid(t, graph.graph)
	})
}
