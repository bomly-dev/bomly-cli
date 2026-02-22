package gomod

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	model "github.com/bomly-dev/bomly-cli/sdk"
)

func TestDetectorApplicable_GoMod(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "go.mod"), []byte("module example.com/demo\n"), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	detector := Detector{WorkingDir: projectDir}
	applicable, err := detector.Applicable(context.Background(), model.DetectionRequest{ProjectPath: projectDir})
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

	g, err := depGraphFromGoList(raw, "example.com/demo")
	if err != nil {
		t.Fatalf("depGraphFromGoList() error = %v", err)
	}

	if g.Size() != 5 {
		t.Fatalf("expected 5 packages, got %d", g.Size())
	}

	rootDeps, err := g.Dependencies("example.com/demo")
	if err != nil {
		t.Fatalf("Dependencies(root) error = %v", err)
	}
	if len(rootDeps) != 3 {
		t.Fatalf("expected 3 root dependencies, got %d", len(rootDeps))
	}

	uuidNode, ok := g.Package("github.com/google/uuid@v1.6.0")
	if !ok {
		t.Fatal("expected runtime dependency package")
	}
	if got := uuidNode.Scope; got != string(model.ScopeRuntime) {
		t.Fatalf("expected runtime scope for uuid, got %q", got)
	}

	textNode, ok := g.Package("golang.org/x/text@v0.14.0")
	if !ok {
		t.Fatal("expected transitive runtime dependency package")
	}
	if got := textNode.Scope; got != string(model.ScopeRuntime) {
		t.Fatalf("expected runtime scope for golang.org/x/text, got %q", got)
	}

	testifyNode, ok := g.Package("github.com/stretchr/testify@v1.9.0")
	if !ok {
		t.Fatal("expected development dependency package")
	}
	if got := testifyNode.Scope; got != string(model.ScopeDevelopment) {
		t.Fatalf("expected development scope for testify, got %q", got)
	}

	spewNode, ok := g.Package("github.com/davecgh/go-spew@v1.1.1")
	if !ok {
		t.Fatal("expected transitive development dependency package")
	}
	if got := spewNode.Scope; got != string(model.ScopeDevelopment) {
		t.Fatalf("expected development scope for go-spew, got %q", got)
	}

	testifyDeps, err := g.Dependencies(testifyNode.ID)
	if err != nil {
		t.Fatalf("Dependencies(testify) error = %v", err)
	}
	if len(testifyDeps) != 1 || testifyDeps[0].ID != spewNode.ID {
		t.Fatalf("unexpected testify dependencies: %#v", testifyDeps)
	}

	if _, ok := g.Package("fmt"); ok {
		t.Fatal("did not expect stdlib package to be included")
	}
}

func TestDepGraphFromGoList_PrefersRuntimeScope(t *testing.T) {
	raw := []byte(`
{"ImportPath":"example.com/demo","Module":{"Path":"example.com/demo","Main":true},"Imports":["example.com/shared/pkg"]}
{"ImportPath":"example.com/demo/internal/app","ForTest":"example.com/demo/internal/app","Module":{"Path":"example.com/demo","Main":true},"Imports":["example.com/shared/pkg"]}
{"ImportPath":"example.com/shared/pkg","Module":{"Path":"example.com/shared","Version":"v1.2.3"}}
`)

	g, err := depGraphFromGoList(raw, "example.com/demo")
	if err != nil {
		t.Fatalf("depGraphFromGoList() error = %v", err)
	}

	shared, ok := g.Package("example.com/shared@v1.2.3")
	if !ok {
		t.Fatal("expected shared dependency package")
	}
	if got := shared.Scope; got != string(model.ScopeRuntime) {
		t.Fatalf("expected runtime scope to win, got %q", got)
	}
}

func TestDepGraphFromGoList_UsesOriginalModuleIdentityForReplace(t *testing.T) {
	raw := []byte(`
{"ImportPath":"example.com/demo","Module":{"Path":"example.com/demo","Main":true},"Imports":["example.com/original/pkg"]}
{"ImportPath":"example.com/original/pkg","Module":{"Path":"example.com/original","Version":"v1.2.3","Replace":{"Path":"../local/original"}}}
`)

	g, err := depGraphFromGoList(raw, "example.com/demo")
	if err != nil {
		t.Fatalf("depGraphFromGoList() error = %v", err)
	}

	if _, ok := g.Package("example.com/original@v1.2.3"); !ok {
		t.Fatal("expected replaced module to keep original module identity")
	}
}

func TestDepGraphFromGoList_EmptyOutput(t *testing.T) {
	if _, err := depGraphFromGoList(nil, "example.com/demo"); err == nil {
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
}
