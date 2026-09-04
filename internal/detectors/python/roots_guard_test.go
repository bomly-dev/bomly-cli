package python

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-sdk"
)

// Every Python project root is built by pythonModuleRoot, which decides the
// declaring manifest from the package manager.
//
// Four parsers each hard-coded "requirements.txt" instead, naming a file a
// Pipenv or Poetry project does not have. The declaring path is part of a
// module's identity and is published in scan JSON, SBOM references and
// explain paths, so the literal was both a wrong reference and a fold risk
// between projects declared by different manifests. A parser added later
// would copy the nearest literal, so the rule gets a guard rather than a
// convention.
func TestPythonRootsGoThroughTheSharedConstructor(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	var offenders []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		// common.go holds the one permitted call, inside pythonModuleRoot.
		if name == "common.go" {
			if strings.Count(string(body), "sdk.NewModuleNode(") > 1 {
				offenders = append(offenders, name)
			}
			continue
		}
		if strings.Contains(string(body), "sdk.NewModuleNode(") {
			offenders = append(offenders, name)
		}
	}
	if len(offenders) > 0 {
		t.Fatalf("these files build a module root directly, which hard-codes the declaring manifest; "+
			"call pythonModuleRoot instead: %v", offenders)
	}
}

// The declaring manifest is the file each tool treats as the project
// declaration, not the lock it generates.
func TestPythonDeclaringManifest(t *testing.T) {
	cases := map[sdk.PackageManager]string{
		sdk.PackageManagerPipenv: "Pipfile",
		sdk.PackageManagerPoetry: "pyproject.toml",
		sdk.PackageManagerUV:     "pyproject.toml",
		sdk.PackageManagerPDM:    "pyproject.toml",
		sdk.PackageManagerPip:    "requirements.txt",
		"":                       "requirements.txt",
	}
	for manager, want := range cases {
		if got := pythonDeclaringManifest(manager); got != want {
			t.Errorf("pythonDeclaringManifest(%q) = %q, want %q", manager, got, want)
		}
	}
}

// The identity a parser publishes names the manifest that declares the
// project, so two projects with equal coordinates but different declarations
// stay distinct records.
func TestPythonModuleRootIdentityNamesTheRealManifest(t *testing.T) {
	pipenv, err := pythonModuleRoot(sdk.Coordinates{
		Ecosystem: sdk.EcosystemPython, PackageManager: sdk.PackageManagerPipenv, Name: "app",
	})
	if err != nil {
		t.Fatalf("pipenv root: %v", err)
	}
	poetry, err := pythonModuleRoot(sdk.Coordinates{
		Ecosystem: sdk.EcosystemPython, PackageManager: sdk.PackageManagerPoetry, Name: "app",
	})
	if err != nil {
		t.Fatalf("poetry root: %v", err)
	}
	if !strings.HasPrefix(pipenv.NodeID(), "module:Pipfile#") {
		t.Fatalf("pipenv root ID = %q, want it declared by Pipfile", pipenv.NodeID())
	}
	if !strings.HasPrefix(poetry.NodeID(), "module:pyproject.toml#") {
		t.Fatalf("poetry root ID = %q, want it declared by pyproject.toml", poetry.NodeID())
	}
	if pipenv.NodeID() == poetry.NodeID() {
		t.Fatalf("both roots minted %q; projects declared by different manifests must stay distinct",
			pipenv.NodeID())
	}
}

// End to end through the real parsers: the root a Pipenv or Poetry project
// gets is declared by the file that actually declares it.
//
// The smoke cases for these ecosystems need the pipenv and poetry binaries, so
// they skip on a machine without them; these run anywhere, because both
// parsers are pure.
func TestPythonParserRootsNameTheDeclaringManifest(t *testing.T) {
	dir := t.TempDir()

	lockPath := filepath.Join(dir, "Pipfile.lock")
	pipfileLock := []byte(`{
  "default": {"requests": {"version": "==2.2.1"}},
  "develop": {}
}`)
	if err := os.WriteFile(lockPath, pipfileLock, 0o644); err != nil {
		t.Fatalf("write Pipfile.lock: %v", err)
	}
	pipenvGraph, err := depGraphFromPipfileLock(lockPath, "demo")
	if err != nil {
		t.Fatalf("depGraphFromPipfileLock() error = %v", err)
	}
	assertSingleModuleDeclaredBy(t, pipenvGraph, "Pipfile")

	poetryDir := t.TempDir()
	poetryLock := filepath.Join(poetryDir, "poetry.lock")
	lock := []byte(`[[package]]
name = "requests"
version = "2.31.0"
category = "main"
optional = false
python-versions = "*"
`)
	if err := os.WriteFile(poetryLock, lock, 0o644); err != nil {
		t.Fatalf("write poetry.lock: %v", err)
	}
	poetryGraph, err := depGraphFromPoetryLock(poetryLock, poetryDir)
	if err != nil {
		t.Fatalf("depGraphFromPoetryLock() error = %v", err)
	}
	assertSingleModuleDeclaredBy(t, poetryGraph, "pyproject.toml")
}

func assertSingleModuleDeclaredBy(t *testing.T, g *sdk.Graph, want string) {
	t.Helper()
	modules := g.ModuleNodes()
	if len(modules) != 1 {
		t.Fatalf("graph holds %d module nodes, want one project root:\n%s", len(modules), g.PrettyString())
	}
	if got := modules[0].DeclaringManifestPath; got != want {
		t.Fatalf("root declared by %q, want %q", got, want)
	}
	if !strings.HasPrefix(modules[0].NodeID(), "module:"+want+"#") {
		t.Fatalf("root ID = %q, want it to name %q", modules[0].NodeID(), want)
	}
}
