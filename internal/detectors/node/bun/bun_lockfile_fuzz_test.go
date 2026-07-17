package bun

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/detectors/node/nodetest"
)

func FuzzDepGraphFromBunLockfile(f *testing.F) {
	for _, fixture := range []string{"bun-v0", "bun-v1-workspaces"} {
		raw, err := os.ReadFile(filepath.Join("..", "testdata", "lockfiles", fixture, "bun.lock"))
		if err != nil {
			f.Fatalf("read %s seed: %v", fixture, err)
		}
		f.Add(raw)
	}
	f.Add([]byte(`{"lockfileVersion":1,"packages":{"left-pad":["left-pad@1.3.0"]},}`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > nodetest.MaxFuzzInputSize {
			return
		}
		projectDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(projectDir, "bun.lock"), raw, 0o644); err != nil {
			t.Fatalf("write bun.lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(projectDir, "package.json"), []byte(`{"name":"demo","version":"1.0.0"}`), 0o644); err != nil {
			t.Fatalf("write package.json: %v", err)
		}
		graphs, err := depGraphFromBunLockfile(projectDir)
		if err != nil {
			return
		}
		nodetest.RequireFuzzGraphValid(t, graphs.graph)
	})
}
