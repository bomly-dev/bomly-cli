package gomod

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly/bomly-cli/internal/detectors"
)

func TestDetectorApplicable_GoMod(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "go.mod"), []byte("module example.com/demo\n"), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	detector := Detector{WorkingDir: projectDir}
	applicable, err := detector.Applicable(context.Background(), detectors.ResolveGraphRequest{ProjectPath: projectDir})
	if err != nil {
		t.Fatalf("Applicable() error = %v", err)
	}
	if !applicable {
		t.Fatal("expected detector to be applicable")
	}
}

func TestDepGraphFromGoModGraph(t *testing.T) {
	raw := []byte(`example.com/demo github.com/google/uuid@v1.6.0
example.com/demo rsc.io/quote@v1.5.2
rsc.io/quote@v1.5.2 golang.org/x/text@v0.14.0
`)

	g, err := depGraphFromGoModGraph(raw, "example.com/demo")
	if err != nil {
		t.Fatalf("depGraphFromGoModGraph() error = %v", err)
	}

	if g.Size() != 4 {
		t.Fatalf("expected 4 packages, got %d", g.Size())
	}

	rootDeps, err := g.Dependencies("example.com/demo")
	if err != nil {
		t.Fatalf("Dependencies(root) error = %v", err)
	}
	if len(rootDeps) != 2 {
		t.Fatalf("expected 2 root dependencies, got %d", len(rootDeps))
	}

	quoteDeps, err := g.Dependencies("rsc.io/quote@v1.5.2")
	if err != nil {
		t.Fatalf("Dependencies(quote) error = %v", err)
	}
	if len(quoteDeps) != 1 || quoteDeps[0].ID != "golang.org/x/text@v0.14.0" {
		t.Fatalf("unexpected quote dependencies: %#v", quoteDeps)
	}
	if _, ok := g.Package("github.com/google/uuid@v1.6.0"); !ok {
		t.Fatal("expected direct dependency package")
	}
	textNode, ok := g.Package("golang.org/x/text@v0.14.0")
	if !ok {
		t.Fatal("expected transitive dependency package")
	}
	if textNode.Ecosystem != "go" || textNode.Name != "golang.org/x/text" || textNode.Version != "v0.14.0" {
		t.Fatalf("unexpected transitive dependency coordinates: %#v", textNode)
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
