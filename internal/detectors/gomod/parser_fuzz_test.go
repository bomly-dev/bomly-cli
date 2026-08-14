package gomod

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-sdk"
	testutil "github.com/bomly-dev/bomly-sdk/testkit"
)

func FuzzDepGraphFromGoList(f *testing.F) {
	f.Add([]byte("{\"ImportPath\":\"example.com/root\",\"Module\":{\"Path\":\"example.com/root\",\"Main\":true}}\n{\"ImportPath\":\"example.com/dep/pkg\",\"Module\":{\"Path\":\"example.com/dep\",\"Version\":\"v1.2.3\"}}\n"))
	f.Add([]byte("{"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > testutil.MaxFuzzInputSize {
			return
		}
		graph, err := depGraphFromGoListWithScope(data, "example.com/root", nil, sdk.Scope(""), nil)
		if err == nil {
			testutil.RequireFuzzGraphValid(t, graph)
		}
	})
}

func FuzzParseGoSumDigests(f *testing.F) {
	f.Add([]byte("github.com/google/uuid v1.6.0 h1:NIvaJDMOsjHA8n1jAhLSgzrAzy1Hgr+hNrb57e+94F0=\ngithub.com/google/uuid v1.6.0/go.mod h1:TIyPZe4MgqvfeYDBFedMoGGpEw/LqOeaOT+nhxU+yHo=\n"))
	f.Add([]byte("example.com/mod v1.0.0 h1:not-base64!!\n"))
	f.Add([]byte("example.com/mod v1.0.0"))
	f.Add([]byte("\n\n   \n"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > testutil.MaxFuzzInputSize {
			return
		}
		path := filepath.Join(t.TempDir(), "go.sum")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Skipf("write go.sum: %v", err)
		}

		first, firstErr := parseGoSumDigests(path)
		second, secondErr := parseGoSumDigests(path)
		if (firstErr == nil) != (secondErr == nil) {
			t.Fatalf("nondeterministic parse outcome: %v vs %v", firstErr, secondErr)
		}
		if firstErr != nil {
			return
		}
		if len(first) != len(second) {
			t.Fatalf("nondeterministic digest count: %d vs %d", len(first), len(second))
		}
		for key, digest := range first {
			other, ok := second[key]
			if !ok || other != digest {
				t.Fatalf("nondeterministic digest for %q: %#v vs %#v", key, digest, other)
			}
			if digest.Algorithm != sdk.DigestAlgorithmSHA256 || len(digest.Value) != 64 {
				t.Fatalf("unexpected digest shape for %q: %#v", key, digest)
			}
		}
	})
}
