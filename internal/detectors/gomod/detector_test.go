package gomod

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestDetectorApplicable_GoMod(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "go.mod"), []byte("module example.com/demo\n"), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	detector := Detector{WorkingDir: projectDir}
	applicable, err := detector.Applicable(context.Background(), sdk.DetectionRequest{ProjectPath: projectDir})
	if err != nil {
		t.Fatalf("Applicable() error = %v", err)
	}
	if !applicable {
		t.Fatal("expected detector to be applicable")
	}
}

func TestBuildGoListArgs(t *testing.T) {
	originalLookupEnv := goLookupEnv
	t.Cleanup(func() {
		goLookupEnv = originalLookupEnv
	})

	t.Run("without go tags", func(t *testing.T) {
		goLookupEnv = func(string) (string, bool) {
			return "", false
		}

		got := buildGoListArgs()
		want := []string{"list", "-deps", "-json", "all"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("buildGoListArgs() = %#v, want %#v", got, want)
		}
	})

	t.Run("with go tags", func(t *testing.T) {
		goLookupEnv = func(key string) (string, bool) {
			if key != "BOMLY_GO_TAGS" {
				return "", false
			}
			return "enterprise,sqlite", true
		}

		got := buildGoListArgs()
		want := []string{"list", "-deps", "-json", "-tags=enterprise,sqlite", "all"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("buildGoListArgs() = %#v, want %#v", got, want)
		}
	})

	t.Run("with blank go tags", func(t *testing.T) {
		goLookupEnv = func(key string) (string, bool) {
			if key != "BOMLY_GO_TAGS" {
				return "", false
			}
			return "   ", true
		}

		got := buildGoListArgs()
		want := []string{"list", "-deps", "-json", "all"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("buildGoListArgs() = %#v, want %#v", got, want)
		}
	})
}

func TestDepGraphFromGoList(t *testing.T) {
	raw := []byte(`
{"ImportPath":"example.com/demo","Module":{"Path":"example.com/demo","Main":true},"Imports":["example.com/demo/internal/app","github.com/google/uuid"],"TestImports":["github.com/stretchr/testify/require"]}
{"ImportPath":"example.com/demo/internal/app","Module":{"Path":"example.com/demo","Main":true},"Imports":["golang.org/x/text/language","fmt"]}
{"ImportPath":"github.com/google/uuid","Module":{"Path":"github.com/google/uuid","Version":"v1.6.0"},"Imports":["crypto/rand"]}
{"ImportPath":"golang.org/x/text/language","Module":{"Path":"golang.org/x/text","Version":"v0.14.0"}}
{"ImportPath":"github.com/stretchr/testify/require","Module":{"Path":"github.com/stretchr/testify","Version":"v1.9.0"},"Imports":["github.com/stretchr/testify/assert"]}
{"ImportPath":"github.com/stretchr/testify/assert","Module":{"Path":"github.com/stretchr/testify","Version":"v1.9.0"},"Imports":["github.com/davecgh/go-spew/spew"]}
{"ImportPath":"github.com/davecgh/go-spew/spew","Module":{"Path":"github.com/davecgh/go-spew","Version":"v1.1.1"}}
`)

	g, err := depGraphFromGoList(raw, "example.com/demo", nil)
	if err != nil {
		t.Fatalf("depGraphFromGoList() error = %v", err)
	}

	if g.Size() != 5 {
		t.Fatalf("expected 5 packages, got %d", g.Size())
	}

	rootDeps, err := g.DirectDependencies("example.com/demo")
	if err != nil {
		t.Fatalf("Dependencies(root) error = %v", err)
	}
	if len(rootDeps) != 3 {
		t.Fatalf("expected 3 root dependencies, got %d", len(rootDeps))
	}

	uuidNode, ok := g.Node("github.com/google/uuid@v1.6.0")
	if !ok {
		t.Fatal("expected runtime dependency package")
	}
	if got := string(uuidNode.PrimaryScope()); got != string(sdk.ScopeRuntime) {
		t.Fatalf("expected runtime scope for uuid, got %q", got)
	}

	textNode, ok := g.Node("golang.org/x/text@v0.14.0")
	if !ok {
		t.Fatal("expected transitive runtime dependency package")
	}
	if got := string(textNode.PrimaryScope()); got != string(sdk.ScopeRuntime) {
		t.Fatalf("expected runtime scope for golang.org/x/text, got %q", got)
	}

	testifyNode, ok := g.Node("github.com/stretchr/testify@v1.9.0")
	if !ok {
		t.Fatal("expected development dependency package")
	}
	if got := string(testifyNode.PrimaryScope()); got != string(sdk.ScopeDevelopment) {
		t.Fatalf("expected development scope for testify, got %q", got)
	}

	spewNode, ok := g.Node("github.com/davecgh/go-spew@v1.1.1")
	if !ok {
		t.Fatal("expected transitive development dependency package")
	}
	if got := string(spewNode.PrimaryScope()); got != string(sdk.ScopeDevelopment) {
		t.Fatalf("expected development scope for go-spew, got %q", got)
	}

	testifyDeps, err := g.DirectDependencies(testifyNode.ID)
	if err != nil {
		t.Fatalf("Dependencies(testify) error = %v", err)
	}
	if len(testifyDeps) != 1 || testifyDeps[0].ID != spewNode.ID {
		t.Fatalf("unexpected testify dependencies: %#v", testifyDeps)
	}

	if _, ok := g.Node("fmt"); ok {
		t.Fatal("did not expect stdlib package to be included")
	}
}

func TestDepGraphFromGoList_RuntimeScopeSkipsTestImports(t *testing.T) {
	raw := []byte(`
{"ImportPath":"example.com/demo","Module":{"Path":"example.com/demo","Main":true},"Imports":["github.com/google/uuid"],"TestImports":["github.com/stretchr/testify/require"]}
{"ImportPath":"github.com/google/uuid","Module":{"Path":"github.com/google/uuid","Version":"v1.6.0"}}
{"ImportPath":"github.com/stretchr/testify/require","Module":{"Path":"github.com/stretchr/testify","Version":"v1.9.0"},"Imports":["github.com/davecgh/go-spew/spew"]}
{"ImportPath":"github.com/davecgh/go-spew/spew","Module":{"Path":"github.com/davecgh/go-spew","Version":"v1.1.1"}}
`)

	g, err := depGraphFromGoListWithScope(raw, "example.com/demo", nil, sdk.ScopeRuntime)
	if err != nil {
		t.Fatalf("depGraphFromGoListWithScope() error = %v", err)
	}
	if _, ok := g.Node("github.com/google/uuid@v1.6.0"); !ok {
		t.Fatal("expected runtime dependency package")
	}
	if _, ok := g.Node("github.com/stretchr/testify@v1.9.0"); ok {
		t.Fatalf("did not expect test dependency in runtime graph: %s", g.PrettyString())
	}
	if _, ok := g.Node("github.com/davecgh/go-spew@v1.1.1"); ok {
		t.Fatalf("did not expect transitive test dependency in runtime graph: %s", g.PrettyString())
	}
}

func TestDepGraphFromGoList_PrefersRuntimeScope(t *testing.T) {
	raw := []byte(`
{"ImportPath":"example.com/demo","Module":{"Path":"example.com/demo","Main":true},"Imports":["example.com/shared/pkg"]}
{"ImportPath":"example.com/demo/internal/app","ForTest":"example.com/demo/internal/app","Module":{"Path":"example.com/demo","Main":true},"Imports":["example.com/shared/pkg"]}
{"ImportPath":"example.com/shared/pkg","Module":{"Path":"example.com/shared","Version":"v1.2.3"}}
`)

	g, err := depGraphFromGoList(raw, "example.com/demo", nil)
	if err != nil {
		t.Fatalf("depGraphFromGoList() error = %v", err)
	}

	shared, ok := g.Node("example.com/shared@v1.2.3")
	if !ok {
		t.Fatal("expected shared dependency package")
	}
	if got := string(shared.PrimaryScope()); got != string(sdk.ScopeRuntime) {
		t.Fatalf("expected runtime scope to win, got %q", got)
	}
}

func TestDepGraphFromGoList_UsesOriginalModuleIdentityForReplace(t *testing.T) {
	raw := []byte(`
{"ImportPath":"example.com/demo","Module":{"Path":"example.com/demo","Main":true},"Imports":["example.com/original/pkg"]}
{"ImportPath":"example.com/original/pkg","Module":{"Path":"example.com/original","Version":"v1.2.3","Replace":{"Path":"../local/original"}}}
`)

	g, err := depGraphFromGoList(raw, "example.com/demo", nil)
	if err != nil {
		t.Fatalf("depGraphFromGoList() error = %v", err)
	}

	if _, ok := g.Node("example.com/original@v1.2.3"); !ok {
		t.Fatal("expected replaced module to keep original module identity")
	}
}

func TestDepGraphFromGoList_EmptyOutput(t *testing.T) {
	if _, err := depGraphFromGoList(nil, "example.com/demo", nil); err == nil {
		t.Fatal("expected empty go list output to fail")
	}
}

func TestParseGoModFile(t *testing.T) {
	projectDir := t.TempDir()
	modPath := filepath.Join(projectDir, "go.mod")
	if err := os.WriteFile(modPath, []byte(`module example.com/demo

go 1.22.0

require (
	github.com/google/uuid v1.6.0
	rsc.io/quote v1.5.2 // indirect
)

require golang.org/x/text v0.14.0
`), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	modulePath, requires, err := parseGoModFile(modPath)
	if err != nil {
		t.Fatalf("parseGoModFile() error = %v", err)
	}
	if modulePath != "example.com/demo" {
		t.Fatalf("expected module path example.com/demo, got %q", modulePath)
	}
	if len(requires) != 3 {
		t.Fatalf("expected 3 requires, got %d", len(requires))
	}
	if requires[0].Path != "github.com/google/uuid" || requires[0].Version != "v1.6.0" {
		t.Fatalf("unexpected first require: %#v", requires[0])
	}
	if requires[2].Path != "golang.org/x/text" || requires[2].Version != "v0.14.0" {
		t.Fatalf("unexpected final require: %#v", requires[2])
	}
	// Line numbers from the go.mod fixture:
	//   1: module example.com/demo
	//   2: (blank)
	//   3: go 1.22.0
	//   4: (blank)
	//   5: require (
	//   6:   github.com/google/uuid v1.6.0
	//   7:   rsc.io/quote v1.5.2 // indirect
	//   8: )
	//   9: (blank)
	//  10: require golang.org/x/text v0.14.0
	if requires[0].Line != 6 {
		t.Errorf("require[0] line = %d, want 6", requires[0].Line)
	}
	if requires[1].Line != 7 {
		t.Errorf("require[1] line = %d, want 7", requires[1].Line)
	}
	if requires[2].Line != 10 {
		t.Errorf("require[2] line = %d, want 10", requires[2].Line)
	}
}

func TestDepGraphFromGoList_AttachesPositionToDirectDeps(t *testing.T) {
	raw := []byte(`
{"ImportPath":"example.com/demo","Module":{"Path":"example.com/demo","Main":true},"Imports":["github.com/direct/dep","example.com/trans/dep"]}
{"ImportPath":"github.com/direct/dep","Module":{"Path":"github.com/direct/dep","Version":"v1.0.0"},"Imports":["example.com/trans/dep"]}
{"ImportPath":"example.com/trans/dep","Module":{"Path":"example.com/trans/dep","Version":"v2.0.0"}}
`)
	directRequires := []moduleRef{
		{Path: "github.com/direct/dep", Version: "v1.0.0", Line: 7},
	}
	g, err := depGraphFromGoList(raw, "example.com/demo", directRequires)
	if err != nil {
		t.Fatalf("depGraphFromGoList: %v", err)
	}
	direct, ok := g.Node("github.com/direct/dep@v1.0.0")
	if !ok {
		t.Fatal("direct dep missing from graph")
	}
	if len(direct.Locations) != 1 {
		t.Fatalf("direct dep Locations = %d, want 1", len(direct.Locations))
	}
	loc := direct.Locations[0]
	if loc.RealPath != "go.mod" {
		t.Errorf("direct dep RealPath = %q, want go.mod", loc.RealPath)
	}
	if loc.Position == nil || loc.Position.Line != 7 || loc.Position.File != "go.mod" {
		t.Errorf("direct dep Position = %+v, want {File: go.mod, Line: 7}", loc.Position)
	}
	trans, ok := g.Node("example.com/trans/dep@v2.0.0")
	if !ok {
		t.Fatal("transitive dep missing from graph")
	}
	if len(trans.Locations) != 0 {
		t.Errorf("transitive dep should have no Locations (not in go.mod); got %+v", trans.Locations)
	}
}
