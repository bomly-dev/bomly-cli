package python

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

// These tests drive each Python detector's lock fast-path end-to-end through
// ResolveGraph against real manifest fixtures under testdata/lockfiles, mirroring
// the node detector's lockfile_integration_test.go. They cover the binary-free
// parsers only (requirements.lock, poetry.lock, uv.lock, Pipfile.lock); the
// install + pip-inspect paths are exercised elsewhere.

// pyStableID returns the graph node ID a parser assigns: "name@version", or just
// "name" when the version is empty.
func pyStableID(name, version string) string {
	if version == "" {
		return name
	}
	return name + "@" + version
}

func pyFixture(name string) string {
	return filepath.Join("testdata", "lockfiles", name)
}

func resolvePyLockGraph(t *testing.T, detector sdk.Detector, projectDir string) *sdk.Graph {
	t.Helper()
	result, err := detector.ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: projectDir})
	if err != nil {
		t.Fatalf("%T.ResolveGraph(%s): %v", detector, projectDir, err)
	}
	g, err := result.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("consolidated graph: %v", err)
	}
	return g
}

func pyGraphIDs(g *sdk.Graph) []string {
	nodes := g.Nodes()
	ids := make([]string, len(nodes))
	for i, n := range nodes {
		ids[i] = n.ID
	}
	return ids
}

func requirePyPackage(t *testing.T, g *sdk.Graph, name, version string) *sdk.Dependency {
	t.Helper()
	id := pyStableID(name, version)
	pkg, ok := g.Node(id)
	if !ok {
		t.Fatalf("expected package %s in graph; present: %v", id, pyGraphIDs(g))
	}
	return pkg
}

func requirePyEdge(t *testing.T, g *sdk.Graph, fromName, fromVersion, toName, toVersion string) {
	t.Helper()
	fromID := pyStableID(fromName, fromVersion)
	toID := pyStableID(toName, toVersion)
	deps, err := g.DirectDependencies(fromID)
	if err != nil {
		t.Fatalf("dependencies(%s): %v", fromID, err)
	}
	for _, dep := range deps {
		if dep.ID == toID {
			return
		}
	}
	t.Errorf("expected edge %s → %s", fromID, toID)
}

func requirePyScope(t *testing.T, g *sdk.Graph, name, version string, scope sdk.Scope) {
	t.Helper()
	pkg := requirePyPackage(t, g, name, version)
	if got := pkg.PrimaryScope(); got != scope {
		t.Errorf("expected %s scope %q, got %q", pyStableID(name, version), scope, got)
	}
}

// requirePySingleRoot asserts the graph has exactly one root with the expected ID.
func requirePySingleRoot(t *testing.T, g *sdk.Graph, rootID string) {
	t.Helper()
	roots := g.Roots()
	if len(roots) != 1 {
		t.Fatalf("expected exactly one root, got %d: %v", len(roots), pyGraphIDs(g))
	}
	if roots[0].ID != rootID {
		t.Errorf("expected root %q, got %q", rootID, roots[0].ID)
	}
}

// ---- pip (requirements.lock fast-path) -------------------------------------

func TestPipRequirementsLockFixture(t *testing.T) {
	g := resolvePyLockGraph(t, PipDetector{}, pyFixture("pip"))

	for _, want := range [][2]string{
		{"requests", "2.32.3"}, {"certifi", "2024.8.30"},
		{"charset-normalizer", "3.4.0"}, {"idna", "3.10"},
		{"urllib3", "2.2.3"}, {"pytest", "8.3.3"},
	} {
		requirePyPackage(t, g, want[0], want[1])
	}

	// requests pulls its four transitive deps via "# via requests".
	requirePyEdge(t, g, "requests", "2.32.3", "certifi", "2024.8.30")
	requirePyEdge(t, g, "requests", "2.32.3", "idna", "3.10")
	requirePyEdge(t, g, "requests", "2.32.3", "urllib3", "2.2.3")

	// Scope: runtime deps stay runtime; the requirements-dev.in input marks pytest dev.
	requirePyScope(t, g, "requests", "2.32.3", sdk.ScopeRuntime)
	requirePyScope(t, g, "urllib3", "2.2.3", sdk.ScopeRuntime)
	requirePyScope(t, g, "pytest", "8.3.3", sdk.ScopeDevelopment)
}

// ---- poetry (poetry.lock + pyproject.toml fast-path) -----------------------

func TestPoetryLockFixture(t *testing.T) {
	g := resolvePyLockGraph(t, PoetryDetector{}, pyFixture("poetry"))

	requirePySingleRoot(t, g, pyStableID("demo-app", "1.0.0"))
	for _, want := range [][2]string{
		{"requests", "2.32.3"}, {"certifi", "2024.8.30"},
		{"charset-normalizer", "3.4.0"}, {"idna", "3.10"},
		{"urllib3", "2.2.3"}, {"pytest", "8.3.3"}, {"pluggy", "1.5.0"},
	} {
		requirePyPackage(t, g, want[0], want[1])
	}

	// Direct deps off the project root, plus transitive edges from the lock.
	requirePyEdge(t, g, "demo-app", "1.0.0", "requests", "2.32.3")
	requirePyEdge(t, g, "requests", "2.32.3", "idna", "3.10")
	requirePyEdge(t, g, "pytest", "8.3.3", "pluggy", "1.5.0")

	// "main" group → runtime; "dev" group → development, propagated transitively.
	requirePyScope(t, g, "requests", "2.32.3", sdk.ScopeRuntime)
	requirePyScope(t, g, "idna", "3.10", sdk.ScopeRuntime)
	requirePyScope(t, g, "pytest", "8.3.3", sdk.ScopeDevelopment)
	requirePyScope(t, g, "pluggy", "1.5.0", sdk.ScopeDevelopment)
}

// ---- uv (uv.lock fast-path) ------------------------------------------------

func TestUVLockFixture(t *testing.T) {
	g := resolvePyLockGraph(t, UVDetector{}, pyFixture("uv"))

	requirePySingleRoot(t, g, pyStableID("demo-app", "1.0.0"))
	for _, want := range [][2]string{
		{"requests", "2.32.3"}, {"certifi", "2024.8.30"},
		{"idna", "3.10"}, {"urllib3", "2.2.3"},
		{"pytest", "8.3.3"}, {"pluggy", "1.5.0"},
	} {
		requirePyPackage(t, g, want[0], want[1])
	}

	requirePyEdge(t, g, "demo-app", "1.0.0", "requests", "2.32.3")
	requirePyEdge(t, g, "requests", "2.32.3", "urllib3", "2.2.3")
	requirePyEdge(t, g, "pytest", "8.3.3", "pluggy", "1.5.0")

	// Runtime deps (and their transitives) vs. the dev-dependency group.
	requirePyScope(t, g, "requests", "2.32.3", sdk.ScopeRuntime)
	requirePyScope(t, g, "urllib3", "2.2.3", sdk.ScopeRuntime)
	requirePyScope(t, g, "pytest", "8.3.3", sdk.ScopeDevelopment)
	requirePyScope(t, g, "pluggy", "1.5.0", sdk.ScopeDevelopment)
}

// ---- pipenv (Pipfile.lock fast-path) ---------------------------------------

func TestPipenvLockFixture(t *testing.T) {
	g := resolvePyLockGraph(t, PipenvDetector{}, pyFixture("pipenv"))

	for _, want := range [][2]string{
		{"requests", "2.32.3"}, {"certifi", "2024.8.30"},
		{"charset-normalizer", "3.4.0"}, {"idna", "3.10"},
		{"urllib3", "2.2.3"}, {"pytest", "8.3.3"}, {"pluggy", "1.5.0"},
	} {
		requirePyPackage(t, g, want[0], want[1])
	}

	// Pipfile.lock has no transitive edges; default/develop hang off the root.
	requirePyEdge(t, g, "root", "", "requests", "2.32.3")
	requirePyEdge(t, g, "root", "", "pytest", "8.3.3")

	// Scope is re-derived from the Pipfile's [packages] / [dev-packages]:
	// requests is runtime, pytest is development. pluggy is only a transitive
	// dependency of pytest, but Pipfile.lock is flat (no edge records it), so it
	// stays runtime — a known limitation of the lock-only fast-path.
	requirePyScope(t, g, "requests", "2.32.3", sdk.ScopeRuntime)
	requirePyScope(t, g, "pytest", "8.3.3", sdk.ScopeDevelopment)
}
