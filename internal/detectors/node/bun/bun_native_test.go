package bun

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/detectors/node"
	"github.com/bomly-dev/bomly-cli/internal/testutil"
	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestParseBunPMListLine(t *testing.T) {
	for _, test := range []struct {
		line        string
		name        string
		version     string
		depth       int
		shouldParse bool
	}{
		{line: "├── is-number@7.0.0", name: "is-number", version: "7.0.0", shouldParse: true},
		{line: "└── @types/bun@1.2.18", name: "@types/bun", version: "1.2.18", shouldParse: true},
		{line: "│   └── is-number@3.0.0", name: "is-number", version: "3.0.0", depth: 1, shouldParse: true},
		{line: "/project node_modules", shouldParse: false},
		{line: "├── malformed", shouldParse: false},
	} {
		name, version, depth, ok := parseBunPMListLine(test.line)
		if ok != test.shouldParse || name != test.name || version != test.version || depth != test.depth {
			t.Fatalf("parseBunPMListLine(%q) = (%q, %q, %d, %t)", test.line, name, version, depth, ok)
		}
	}
}

func TestDepGraphFromBunPMListPreservesUnprovenParents(t *testing.T) {
	manifest := node.PackageJSONManifest{
		Name: "demo", Version: "1.0.0",
		Dependencies: map[string]string{"direct": "1.0.0", "duplicate": "1.0.0"},
	}
	graph, err := depGraphFromBunPMList([]byte("/project node_modules\n├── direct@1.0.0\n├── transitive@2.0.0\n│   └── nested@3.0.0\n├── duplicate@1.0.0\n└── duplicate@2.0.0\n"), manifest, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	direct, _ := graph.Node("direct@1.0.0")
	if direct == nil || direct.PrimaryScope() != sdk.ScopeRuntime || direct.Relationship == sdk.DependencyRelationshipUnknown {
		t.Fatalf("expected a known direct dependency, got %#v", direct)
	}
	for _, id := range []string{"transitive@2.0.0", "duplicate@1.0.0", "duplicate@2.0.0"} {
		dependency, _ := graph.Node(id)
		if dependency == nil || dependency.Relationship != sdk.DependencyRelationshipUnknown {
			t.Fatalf("expected %s to retain unknown placement, got %#v", id, dependency)
		}
	}
	children, err := graph.DirectDependencies("transitive@2.0.0")
	if err != nil || len(children) != 1 || children[0].ID != "nested@3.0.0" {
		t.Fatalf("expected proven nested edge, got children=%#v err=%v", children, err)
	}
	if children[0].Relationship == sdk.DependencyRelationshipUnknown {
		t.Fatalf("proven nested dependency must not be unknown: %#v", children[0])
	}
}

func TestNativeDetectorResolveGraph(t *testing.T) {
	projectDir := t.TempDir()
	writeBunNativeTestFile(t, filepath.Join(projectDir, "package.json"), `{"name":"demo","version":"1.0.0","dependencies":{"is-number":"7.0.0","number-check":"npm:is-number@7.0.0"}}`)
	if err := os.MkdirAll(filepath.Join(projectDir, "apps", "api"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeBunNativeTestFile(t, filepath.Join(projectDir, "apps", "api", "package.json"), `{"name":"@fixture/api","version":"1.0.0"}`)
	binDir := t.TempDir()
	binaryName := "bun"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	if err := testutil.BuildGoBinary(t, filepath.Join(binDir, binaryName), `package main
import "fmt"
func main() { fmt.Print("/project node_modules\n├── @fixture/api@workspace:apps/api\n├── is-number@7.0.0\n├── is-odd@0.1.2\n│   └── is-number@3.0.0\n├── number-check@7.0.0\n└── left-pad@1.3.0\n") }
`); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)

	result, err := (NativeDetector{}).ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: projectDir})
	if err != nil {
		t.Fatal(err)
	}
	graph, err := result.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatal(err)
	}
	if graph.Size() != 7 {
		t.Fatalf("expected root, workspace, and five package occurrences, got %d", graph.Size())
	}
	leftPad, _ := graph.Node("left-pad@1.3.0")
	if leftPad == nil || leftPad.Relationship != sdk.DependencyRelationshipUnknown {
		t.Fatalf("expected unproven package placement, got %#v", leftPad)
	}
	workspace, _ := graph.Node("workspace:apps/api")
	if workspace == nil || workspace.Type != sdk.PackageTypeApplication || workspace.Version != "1.0.0" {
		t.Fatalf("expected canonical workspace application, got %#v", workspace)
	}
	alias, _ := graph.Node("bun-native-alias:number-check@7.0.0")
	if alias == nil || alias.Name != "is-number" || alias.Version != "7.0.0" || alias.PrimaryScope() != sdk.ScopeRuntime {
		t.Fatalf("expected normalized direct alias occurrence, got %#v", alias)
	}
	children, err := graph.DirectDependencies("is-odd@0.1.2")
	if err != nil || len(children) != 1 || children[0].ID != "is-number@3.0.0" {
		t.Fatalf("expected Bun tree edge, got children=%#v err=%v", children, err)
	}
}

func writeBunNativeTestFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}
