package gomod

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

// readFixture loads a committed fixture file from testdata. These tests drive
// the go.mod and `go list -deps -json` parsers directly against real fixtures,
// so they never invoke the `go` toolchain.
func readFixture(t *testing.T, parts ...string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(append([]string{"testdata"}, parts...)...))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return raw
}

func TestGoModFixture_ParseModAndGraph(t *testing.T) {
	module, requires, err := parseGoModFile(filepath.Join("testdata", "demo", "go.mod"))
	if err != nil {
		t.Fatalf("parseGoModFile: %v", err)
	}
	if module != "example.com/demo" {
		t.Fatalf("module = %q, want example.com/demo", module)
	}
	// go.mod declares two direct requires plus one indirect.
	if len(requires) != 3 {
		t.Fatalf("requires = %d, want 3: %#v", len(requires), requires)
	}

	raw := readFixture(t, "demo", "go-list-deps.json")
	g, err := depGraphFromGoList(raw, module, requires)
	if err != nil {
		t.Fatalf("depGraphFromGoList: %v", err)
	}

	if g.Size() != 5 {
		t.Fatalf("graph size = %d, want 5: %v", g.Size(), nodeIDs(g))
	}
	for _, want := range []string{
		"github.com/google/uuid@v1.6.0",
		"golang.org/x/text@v0.14.0",
		"github.com/stretchr/testify@v1.9.0",
		"github.com/davecgh/go-spew@v1.1.1",
	} {
		if _, ok := g.Node(want); !ok {
			t.Errorf("missing node %s; present: %v", want, nodeIDs(g))
		}
	}
	// stdlib must never appear as a dependency node.
	if _, ok := g.Node("fmt"); ok {
		t.Error("stdlib package fmt should not be a node")
	}
}

func TestGoModFixture_Scopes(t *testing.T) {
	module, requires, err := parseGoModFile(filepath.Join("testdata", "demo", "go.mod"))
	if err != nil {
		t.Fatalf("parseGoModFile: %v", err)
	}
	g, err := depGraphFromGoList(readFixture(t, "demo", "go-list-deps.json"), module, requires)
	if err != nil {
		t.Fatalf("depGraphFromGoList: %v", err)
	}

	// Imported via main → runtime; reachable only through TestImports → development.
	requireScope(t, g, "github.com/google/uuid@v1.6.0", sdk.ScopeRuntime)
	requireScope(t, g, "golang.org/x/text@v0.14.0", sdk.ScopeRuntime)
	requireScope(t, g, "github.com/stretchr/testify@v1.9.0", sdk.ScopeDevelopment)
	requireScope(t, g, "github.com/davecgh/go-spew@v1.1.1", sdk.ScopeDevelopment)
}

func nodeIDs(g *sdk.Graph) []string {
	nodes := g.Nodes()
	ids := make([]string, len(nodes))
	for i, n := range nodes {
		ids[i] = n.ID
	}
	return ids
}

func requireScope(t *testing.T, g *sdk.Graph, id string, scope sdk.Scope) {
	t.Helper()
	n, ok := g.Node(id)
	if !ok {
		t.Fatalf("missing node %s", id)
	}
	if got := n.PrimaryScope(); got != scope {
		t.Errorf("%s scope = %q, want %q", id, got, scope)
	}
}
