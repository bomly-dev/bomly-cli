package python

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-sdk/model"
)

// The declaring manifest is the file each tool treats as the project
// declaration, not the lock it generates.
func TestPythonDeclaringManifest(t *testing.T) {
	cases := map[model.PackageManager]string{
		model.PackageManagerPipenv: "Pipfile",
		model.PackageManagerPoetry: "pyproject.toml",
		model.PackageManagerUV:     "pyproject.toml",
		model.PackageManagerPDM:    "pyproject.toml",
		model.PackageManagerPip:    "requirements.txt",
		"":                         "requirements.txt",
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
	pipenv, err := pythonModuleRoot(model.Coordinates{
		Ecosystem: model.EcosystemPython, PackageManager: model.PackageManagerPipenv, Name: "app",
	})
	if err != nil {
		t.Fatalf("pipenv root: %v", err)
	}
	poetry, err := pythonModuleRoot(model.Coordinates{
		Ecosystem: model.EcosystemPython, PackageManager: model.PackageManagerPoetry, Name: "app",
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

func assertSingleModuleDeclaredBy(t *testing.T, g *model.Graph, want string) {
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

// The pip-inspect path and the lockfile parsers must mint the same root
// identity for one project.
//
// baseDetector.resolveGraph is shared by pip, Pipenv, Poetry and uv, and it
// built the root without saying which manager it was speaking for -- so every
// successful pip-inspect graph declared itself from requirements.txt, and a
// Pipenv project got the correct Pipfile identity only when it fell back to
// the pure lock parser. One project would then have two identities depending
// on which strategy happened to succeed.
func TestPythonRootIdentityAgreesAcrossResolutionStrategies(t *testing.T) {
	cases := []struct {
		manager model.PackageManager
		want    string
	}{
		{model.PackageManagerPipenv, "Pipfile"},
		{model.PackageManagerPoetry, "pyproject.toml"},
		{model.PackageManagerUV, "pyproject.toml"},
		{model.PackageManagerPip, "requirements.txt"},
	}
	for _, tc := range cases {
		// The pip-inspect strategy's root, as resolveGraph builds it.
		inspectRoot, err := pythonSyntheticRoot(tc.manager, "demo")
		if err != nil {
			t.Fatalf("pythonSyntheticRoot(%q): %v", tc.manager, err)
		}
		// The lockfile strategy's root, as every parser builds it.
		lockRoot, err := pythonModuleRoot(model.Coordinates{
			Ecosystem:      model.EcosystemPython,
			PackageManager: tc.manager,
			Name:           "demo",
			Type:           model.PackageTypeApplication,
		})
		if err != nil {
			t.Fatalf("pythonModuleRoot(%q): %v", tc.manager, err)
		}
		if inspectRoot.NodeID() != lockRoot.NodeID() {
			t.Fatalf("%q: pip-inspect root %q != lockfile root %q; one project must have one identity",
				tc.manager, inspectRoot.NodeID(), lockRoot.NodeID())
		}
		if inspectRoot.DeclaringManifestPath != tc.want {
			t.Fatalf("%q declared by %q, want %q", tc.manager, inspectRoot.DeclaringManifestPath, tc.want)
		}
	}
}

// Every detector states the manager it speaks for, so the shared pip-inspect
// path can name the right declaring manifest.
func TestPythonDetectorsCarryTheirManager(t *testing.T) {
	cases := map[string]struct {
		got  model.PackageManager
		want model.PackageManager
	}{
		"pip":    {PipDetector{}.base().Manager, model.PackageManagerPip},
		"poetry": {PoetryDetector{}.base().Manager, model.PackageManagerPoetry},
		"uv":     {UVDetector{}.base().Manager, model.PackageManagerUV},
		"pipenv": {PipenvDetector{}.base().Manager, model.PackageManagerPipenv},
	}
	for name, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s detector base manager = %q, want %q", name, tc.got, tc.want)
		}
	}
}
