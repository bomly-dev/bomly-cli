package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/testutil"
)

func FuzzLoadFile(f *testing.F) {
	for _, seed := range []string{
		"",
		"target:\n  path: ./project\nscan:\n  enrich: true\n",
		"plugins:\n  example:\n    nested:\n      enabled: true\n",
		"target: [",
		"config: other.yaml\n",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > testutil.MaxFuzzInputSize {
			return
		}
		path := filepath.Join(t.TempDir(), "bomly.yaml")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		first, firstErr := LoadFile(path)
		second, secondErr := LoadFile(path)
		if (firstErr == nil) != (secondErr == nil) {
			t.Fatalf("LoadFile changed success state: first=%v second=%v", firstErr, secondErr)
		}
		if firstErr != nil {
			if firstErr.Error() != secondErr.Error() {
				t.Fatalf("LoadFile changed error: first=%v second=%v", firstErr, secondErr)
			}
			return
		}
		if first == nil || second == nil {
			t.Fatalf("successful LoadFile returned nil: first=%#v second=%#v", first, second)
		}
	})
}
