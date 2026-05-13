package python

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestDepGraphFromPipInspect(t *testing.T) {
	raw := []byte(`{
  "installed": [
    {
      "metadata": {
        "name": "demo-app",
        "version": "1.0.0",
        "requires_dist": ["requests>=2", "uvicorn; extra == 'server'"]
      },
      "requested": true,
      "requested_by": []
    },
    {
      "metadata": {
        "name": "requests",
        "version": "2.32.0",
        "requires_dist": ["certifi>=2024.0.0"]
      },
      "requested": false,
      "requested_by": ["demo-app"]
    },
    {
      "metadata": {
        "name": "certifi",
        "version": "2024.2.2",
        "requires_dist": []
      },
      "requested": false,
      "requested_by": ["requests"]
    }
  ]
}`)

	g, err := depGraphFromPipInspect(raw)
	if err != nil {
		t.Fatalf("depGraphFromPipInspect() error = %v", err)
	}
	if g.Size() != 4 {
		t.Fatalf("expected 4 packages, got %d", g.Size())
	}
}

func TestDepGraphFromPipfileLock(t *testing.T) {
	path := t.TempDir() + "/Pipfile.lock"
	raw := []byte(`{
  "default": {
    "requests": {"version": "==2.2.1"},
    "Django": {"version": "==1.7.1"}
  },
  "develop": {
    "pytest": {"version": "==9.0.3"}
  }
}`)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write Pipfile.lock: %v", err)
	}

	g, err := depGraphFromPipfileLock(path)
	if err != nil {
		t.Fatalf("depGraphFromPipfileLock() error = %v", err)
	}
	if g.Size() != 4 {
		t.Fatalf("expected root plus 3 packages, got %d", g.Size())
	}
	if _, ok := g.Package("requests@2.2.1"); !ok {
		t.Fatalf("expected requests package, got %s", g.PrettyString())
	}
}

func TestFilterPythonToolPackagesRemovesUndeclaredTools(t *testing.T) {
	g := sdk.New()
	root := sdk.NewPackage(sdk.Package{Ecosystem: string(sdk.EcosystemPython), Name: "root"})
	requests := sdk.NewPackage(sdk.Package{Ecosystem: string(sdk.EcosystemPython), Name: "requests", Version: "2.32.0"})
	pip := sdk.NewPackage(sdk.Package{Ecosystem: string(sdk.EcosystemPython), Name: "pip", Version: "25.0"})
	for _, pkg := range []*sdk.Package{root, requests, pip} {
		if err := g.AddPackage(pkg); err != nil {
			t.Fatalf("add package %q: %v", pkg.ID, err)
		}
	}
	if err := g.AddDependency(root.ID, requests.ID); err != nil {
		t.Fatalf("add requests dependency: %v", err)
	}
	if err := g.AddDependency(root.ID, pip.ID); err != nil {
		t.Fatalf("add pip dependency: %v", err)
	}

	filtered, err := filterPythonToolPackages(g, t.TempDir())
	if err != nil {
		t.Fatalf("filterPythonToolPackages() error = %v", err)
	}
	if _, ok := filtered.Package("pip@25.0"); ok {
		t.Fatalf("expected undeclared pip to be removed: %s", filtered.PrettyString())
	}
	if _, ok := filtered.Package("requests@2.32.0"); !ok {
		t.Fatalf("expected application dependency to remain: %s", filtered.PrettyString())
	}
}

func TestFilterPythonToolPackagesKeepsDeclaredTools(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("pip==25.0\nrequests==2.32.0\n"), 0o644); err != nil {
		t.Fatalf("write requirements: %v", err)
	}
	g := sdk.New()
	root := sdk.NewPackage(sdk.Package{Ecosystem: string(sdk.EcosystemPython), Name: "root"})
	pip := sdk.NewPackage(sdk.Package{Ecosystem: string(sdk.EcosystemPython), Name: "pip", Version: "25.0"})
	wheel := sdk.NewPackage(sdk.Package{Ecosystem: string(sdk.EcosystemPython), Name: "wheel", Version: "0.45.0"})
	for _, pkg := range []*sdk.Package{root, pip, wheel} {
		if err := g.AddPackage(pkg); err != nil {
			t.Fatalf("add package %q: %v", pkg.ID, err)
		}
	}
	if err := g.AddDependency(root.ID, pip.ID); err != nil {
		t.Fatalf("add pip dependency: %v", err)
	}
	if err := g.AddDependency(root.ID, wheel.ID); err != nil {
		t.Fatalf("add wheel dependency: %v", err)
	}

	filtered, err := filterPythonToolPackages(g, dir)
	if err != nil {
		t.Fatalf("filterPythonToolPackages() error = %v", err)
	}
	if _, ok := filtered.Package("pip@25.0"); !ok {
		t.Fatalf("expected declared pip to remain: %s", filtered.PrettyString())
	}
	if _, ok := filtered.Package("wheel@0.45.0"); ok {
		t.Fatalf("expected undeclared wheel to be removed: %s", filtered.PrettyString())
	}
}

func TestAttachDeclaredPositions(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/requirements.txt", []byte(
		"# leading comment\n"+
			"requests==2.32.3\n"+
			"flask>=2.0\n"+
			"\n"+
			"-r other.txt\n"+
			"numpy==1.26.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	g := sdk.New()
	for _, name := range []string{"requests", "flask", "numpy", "urllib3"} {
		pkg := sdk.NewPackage(sdk.Package{
			Ecosystem: string(sdk.EcosystemPython),
			Name:      name,
			Version:   "0.0.0",
		})
		_ = g.AddPackage(pkg)
	}

	attachDeclaredPositions(g, dir)

	cases := map[string]int{
		"requests": 2,
		"flask":    3,
		"numpy":    6,
	}
	for name, wantLine := range cases {
		pkg, _ := g.Package(name + "@0.0.0")
		if pkg == nil {
			t.Fatalf("%s missing from graph", name)
		}
		if len(pkg.Locations) != 1 {
			t.Errorf("%s Locations = %d, want 1", name, len(pkg.Locations))
			continue
		}
		loc := pkg.Locations[0]
		if loc.RealPath != "requirements.txt" {
			t.Errorf("%s RealPath = %q, want requirements.txt", name, loc.RealPath)
		}
		if loc.Position == nil || loc.Position.Line != wantLine {
			t.Errorf("%s Position = %+v, want line %d", name, loc.Position, wantLine)
		}
	}

	// Transitive (not declared) gets no Locations.
	pkg, _ := g.Package("urllib3@0.0.0")
	if pkg != nil && len(pkg.Locations) != 0 {
		t.Errorf("urllib3 (undeclared) should have no Locations; got %+v", pkg.Locations)
	}
}
