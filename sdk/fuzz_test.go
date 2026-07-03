package sdk

import (
	"encoding/json"
	"testing"
)

const maxFuzzInputSize = 1 << 20

func FuzzCanonicalizePackageURL(f *testing.F) {
	for _, seed := range []string{
		"pkg:npm/%40scope/name@1.0.0",
		"pkg:golang/github.com/bomly-dev/bomly-cli@v0.1.0",
		"pkg:pypi/requests@2.31.0",
		"not a package url",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > maxFuzzInputSize {
			return
		}
		canonical := CanonicalizePackageURL(raw)
		if canonical == "" {
			return
		}
		if reparsed := ParsePackageURL(canonical); reparsed == nil {
			t.Fatalf("canonical package URL does not parse: %q", canonical)
		}
		if again := CanonicalizePackageURL(canonical); again != canonical {
			t.Fatalf("package URL canonicalization is not stable: %q then %q", canonical, again)
		}
	})
}

func FuzzGraphJSON(f *testing.F) {
	for _, seed := range []string{
		`null`,
		`{"nodes":[{"id":"app","name":"app","version":"1.0.0"},{"id":"dep","name":"dep","version":"2.0.0"}],"edges":[{"fromId":"app","toId":"dep"}]}`,
		`{"nodes":[{"id":"pkg:npm/react@18.2.0","purl":"pkg:npm/react@18.2.0","name":"react","version":"18.2.0"}]}`,
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > maxFuzzInputSize {
			return
		}
		var graph Graph
		if err := json.Unmarshal(raw, &graph); err != nil {
			return
		}
		requireFuzzGraphValid(t, &graph)
		encoded, err := json.Marshal(&graph)
		if err != nil {
			t.Fatalf("marshal graph after successful unmarshal: %v", err)
		}
		var roundTrip Graph
		if err := json.Unmarshal(encoded, &roundTrip); err != nil {
			t.Fatalf("round-trip graph JSON does not unmarshal: %v", err)
		}
	})
}

func FuzzPackageRegistryJSON(f *testing.F) {
	for _, seed := range []string{
		`null`,
		`{"pkg:npm/react@18.2.0":{"name":"react","version":"18.2.0","purl":"pkg:npm/react@18.2.0"}}`,
		`{"pkg:golang/github.com/bomly-dev/bomly-cli@v0.1.0":{"name":"github.com/bomly-dev/bomly-cli","version":"v0.1.0"}}`,
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > maxFuzzInputSize {
			return
		}
		var registry PackageRegistry
		if err := json.Unmarshal(raw, &registry); err != nil {
			return
		}
		for _, pkg := range registry.All() {
			if pkg == nil {
				t.Fatal("registry contains nil package after successful unmarshal")
			}
			if pkg.PURL == "" {
				t.Fatalf("registry contains package with empty PURL: %+v", pkg)
			}
		}
		encoded, err := json.Marshal(&registry)
		if err != nil {
			t.Fatalf("marshal registry after successful unmarshal: %v", err)
		}
		var roundTrip PackageRegistry
		if err := json.Unmarshal(encoded, &roundTrip); err != nil {
			t.Fatalf("round-trip registry JSON does not unmarshal: %v", err)
		}
	})
}

func requireFuzzGraphValid(t *testing.T, graph *Graph) {
	t.Helper()
	if graph == nil {
		t.Fatal("nil graph")
	}
	graph.WalkNodes(func(node *Dependency) bool {
		if node == nil {
			t.Fatal("graph contains nil node")
		}
		if node.ID == "" {
			t.Fatalf("graph contains node with empty ID: %+v", node)
		}
		return true
	})
	graph.WalkEdges(func(from, to *Dependency) bool {
		if from == nil || to == nil {
			t.Fatalf("graph contains nil edge endpoint: from=%+v to=%+v", from, to)
		}
		if from.ID == "" || to.ID == "" {
			t.Fatalf("graph contains edge with empty endpoint ID: from=%+v to=%+v", from, to)
		}
		return true
	})
}
