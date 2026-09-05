package python

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/testnodes"
	sdk "github.com/bomly-dev/bomly-sdk"
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
	nodes := g.DependencyNodes()
	ids := make([]string, len(nodes))
	for i, n := range nodes {
		ids[i] = n.NodeID()
	}
	return ids
}

func requirePyPackage(t *testing.T, g *sdk.Graph, name, version string) *sdk.DependencyNode {
	t.Helper()
	id := pyStableID(name, version)
	pkg, ok := testnodes.FindDep(g, id)
	if !ok {
		t.Fatalf("expected package %s in graph; present: %v", id, pyGraphIDs(g))
	}
	return pkg
}

func requirePyEdge(t *testing.T, g *sdk.Graph, fromName, fromVersion, toName, toVersion string) {
	t.Helper()
	fromID := pyStableID(fromName, fromVersion)
	toID := pyStableID(toName, toVersion)
	deps, err := g.DirectDependencies(testnodes.ID(g, fromID))
	if err != nil {
		t.Fatalf("dependencies(%s): %v", fromID, err)
	}
	for _, dep := range deps {
		if testnodes.Is(dep, toID) {
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

func requirePySource(t *testing.T, g *sdk.Graph, name, version string, source sdk.DependencySource) {
	t.Helper()
	pkg := requirePyPackage(t, g, name, version)
	if pkg.Source != source {
		t.Errorf("expected %s source %q, got %q", pyStableID(name, version), source, pkg.Source)
	}
}

// requirePySingleRoot asserts the graph has exactly one root with the expected ID.
func requirePySingleRoot(t *testing.T, g *sdk.Graph, rootID string) {
	t.Helper()
	roots := g.Roots()
	if len(roots) != 1 {
		t.Fatalf("expected exactly one root, got %d: %v", len(roots), pyGraphIDs(g))
	}
	if !testnodes.Is(roots[0], rootID) {
		t.Errorf("expected root %q, got %q", rootID, roots[0].NodeID())
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
	requirePySource(t, g, "requests", "2.32.3", sdk.DependencySourceRegistry)
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
	requirePySource(t, g, "requests", "2.32.3", sdk.DependencySourceRegistry)
}

// ---- uv (uv.lock fast-path) ------------------------------------------------

func TestUVLockFixture(t *testing.T) {
	g := resolvePyLockGraph(t, UVDetector{}, pyFixture("uv"))

	// The editable package is the scanned project itself, so it is a module
	// node -- and a module is never enriched (ADR-0041).
	roots := g.Roots()
	if len(roots) != 1 || !sdk.IsProjectOwned(roots[0]) {
		t.Fatalf("uv editable root must be the project's own module, got %#v", roots)
	}
	for _, want := range [][2]string{
		{"requests", "2.32.3"}, {"certifi", "2024.8.30"},
		{"idna", "3.10"}, {"urllib3", "2.2.3"},
		{"pytest", "8.3.3"}, {"pluggy", "1.5.0"}, {"git-helper", "1.0.0"},
	} {
		requirePyPackage(t, g, want[0], want[1])
	}

	requirePyEdge(t, g, "demo-app", "1.0.0", "requests", "2.32.3")
	requirePyEdge(t, g, "demo-app", "1.0.0", "git-helper", "1.0.0")
	requirePyEdge(t, g, "requests", "2.32.3", "urllib3", "2.2.3")
	requirePyEdge(t, g, "pytest", "8.3.3", "pluggy", "1.5.0")

	// Runtime deps (and their transitives) vs. the dev-dependency group.
	requirePyScope(t, g, "requests", "2.32.3", sdk.ScopeRuntime)
	requirePyScope(t, g, "urllib3", "2.2.3", sdk.ScopeRuntime)
	requirePyScope(t, g, "pytest", "8.3.3", sdk.ScopeDevelopment)
	requirePyScope(t, g, "pluggy", "1.5.0", sdk.ScopeDevelopment)
	requirePySource(t, g, "requests", "2.32.3", sdk.DependencySourceRegistry)
	gitHelper := requirePyPackage(t, g, "git-helper", "1.0.0")
	if gitHelper.Source != sdk.DependencySourceGit {
		t.Fatalf("git-helper source = %q, want %q", gitHelper.Source, sdk.DependencySourceGit)
	}
	if gitHelper.Metadata["source_revision"] != "abc123" {
		t.Fatalf("git-helper source revision = %#v, want abc123", gitHelper.Metadata["source_revision"])
	}
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

	// Pipfile.lock has no transitive edges; default/develop hang off the root,
	// which is named after the project directory (issue #272).
	requirePyEdge(t, g, "pipenv", "", "requests", "2.32.3")
	requirePyEdge(t, g, "pipenv", "", "pytest", "8.3.3")

	// Scope is re-derived from the Pipfile's [packages] / [dev-packages]:
	// requests is runtime, pytest is development. pluggy is only a transitive
	// dependency of pytest, but Pipfile.lock is flat (no edge records it), so it
	// stays runtime — a known limitation of the lock-only fast-path.
	requirePyScope(t, g, "requests", "2.32.3", sdk.ScopeRuntime)
	requirePyScope(t, g, "pytest", "8.3.3", sdk.ScopeDevelopment)
	requirePySource(t, g, "requests", "2.32.3", sdk.DependencySourceRegistry)
}
