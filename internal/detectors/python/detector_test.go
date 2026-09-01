package python

import (
	"github.com/bomly-dev/bomly-cli/internal/nodes"
	"github.com/bomly-dev/bomly-cli/internal/testnodes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-sdk"
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
      "requested": true
    },
    {
      "metadata": {
        "name": "requests",
        "version": "2.32.0",
        "requires_dist": ["certifi>=2024.0.0"]
      },
      "requested": false
    },
    {
      "metadata": {
        "name": "certifi",
        "version": "2024.2.2",
        "requires_dist": []
      },
      "requested": false
    }
  ]
}`)

	root, err := pythonSyntheticRoot("")
	if err != nil {
		t.Fatalf("pythonSyntheticRoot() error = %v", err)
	}
	g, err := depGraphFromPipInspect(raw, root, nil)
	if err != nil {
		t.Fatalf("depGraphFromPipInspect() error = %v", err)
	}
	if g.Size() != 4 {
		t.Fatalf("expected 4 packages, got %d", g.Size())
	}
	// The synthetic root node stands for the scanned project — and its
	// fallback name "root" is a real PyPI package name — so it must never be
	// enrichable.
	rootNode, ok := testnodes.Find(g, "root")
	if !ok {
		t.Fatal("expected synthetic root node")
	}
	if !nodes.IsProjectOwned(rootNode) {
		t.Fatalf("pip-inspect root must be the project's own module node, got a %s node", rootNode.Kind())
	}
	// Only the requested distribution is direct; the rest reach the graph
	// through requires_dist edges.
	assertDirectDependencies(t, g, root.NodeID(), []string{"demo-app@1.0.0"})
	assertDirectDependencies(t, g, "demo-app@1.0.0", []string{"requests@2.32.0"})
	assertDirectDependencies(t, g, "requests@2.32.0", []string{"certifi@2024.2.2"})
}

// TestDepGraphFromPipInspectScopesDirectDependencies covers issue #273: pip
// inspect reports a flat installed set, and treating every entry as direct
// listed pure transitives under "Top-level dependencies".
func TestDepGraphFromPipInspectScopesDirectDependencies(t *testing.T) {
	// An environment populated by a front-end that records no REQUESTED
	// marker: the project's requirements file is the only direct signal.
	raw := []byte(`{
  "installed": [
    {"metadata": {"name": "flask", "version": "3.1.1", "requires_dist": ["Werkzeug>=3.1", "Jinja2>=3.1", "click>=8.1"]}},
    {"metadata": {"name": "requests", "version": "2.32.4", "requires_dist": ["urllib3>=1.21.1", "certifi>=2017.4.17"]}},
    {"metadata": {"name": "Werkzeug", "version": "3.1.3", "requires_dist": ["MarkupSafe>=2.1.1"]}},
    {"metadata": {"name": "Jinja2", "version": "3.1.6", "requires_dist": ["MarkupSafe>=2.0"]}},
    {"metadata": {"name": "MarkupSafe", "version": "3.0.2", "requires_dist": []}},
    {"metadata": {"name": "click", "version": "8.2.1", "requires_dist": []}},
    {"metadata": {"name": "urllib3", "version": "2.5.0", "requires_dist": []}},
    {"metadata": {"name": "certifi", "version": "2025.7.14", "requires_dist": []}}
  ]
}`)

	declared := map[string]struct{}{"flask": {}, "requests": {}}
	root, err := pythonSyntheticRoot("")
	if err != nil {
		t.Fatalf("pythonSyntheticRoot() error = %v", err)
	}
	g, err := depGraphFromPipInspect(raw, root, declared)
	if err != nil {
		t.Fatalf("depGraphFromPipInspect() error = %v", err)
	}
	assertDirectDependencies(t, g, root.NodeID(), []string{"flask@3.1.1", "requests@2.32.4"})
	for _, transitive := range []string{"werkzeug@3.1.3", "jinja2@3.1.6", "markupsafe@3.0.2", "click@8.2.1", "urllib3@2.5.0", "certifi@2025.7.14"} {
		if _, ok := testnodes.Find(g, transitive); !ok {
			t.Fatalf("expected transitive %s in graph: %s", transitive, g.PrettyString())
		}
	}
}

// TestDepGraphFromPipInspectAttachesOrphans keeps packages whose parents are
// unknown reachable from the root instead of leaving a second graph root.
func TestDepGraphFromPipInspectAttachesOrphans(t *testing.T) {
	raw := []byte(`{
  "installed": [
    {"metadata": {"name": "flask", "version": "3.1.1", "requires_dist": []}, "requested": true},
    {"metadata": {"name": "mystery", "version": "0.1.0", "requires_dist": []}}
  ]
}`)

	root, err := pythonSyntheticRoot("")
	if err != nil {
		t.Fatalf("pythonSyntheticRoot() error = %v", err)
	}
	g, err := depGraphFromPipInspect(raw, root, nil)
	if err != nil {
		t.Fatalf("depGraphFromPipInspect() error = %v", err)
	}
	assertDirectDependencies(t, g, root.NodeID(), []string{"flask@3.1.1", "mystery@0.1.0"})
	if roots := g.Roots(); len(roots) != 1 || roots[0].NodeID() != root.NodeID() {
		t.Fatalf("expected a single graph root, got %s", g.PrettyString())
	}
}

// TestDepGraphFromPipInspectAttachesCycles covers a component that depends on
// itself: requires_dist cycles are legal, so every member has a parent while
// the component as a whole is unreachable from the root.
func TestDepGraphFromPipInspectAttachesCycles(t *testing.T) {
	raw := []byte(`{
  "installed": [
    {"metadata": {"name": "flask", "version": "3.1.1", "requires_dist": []}, "requested": true},
    {"metadata": {"name": "left", "version": "1.0.0", "requires_dist": ["right"]}},
    {"metadata": {"name": "right", "version": "1.0.0", "requires_dist": ["left"]}}
  ]
}`)

	root, err := pythonSyntheticRoot("")
	if err != nil {
		t.Fatalf("pythonSyntheticRoot() error = %v", err)
	}
	g, err := depGraphFromPipInspect(raw, root, nil)
	if err != nil {
		t.Fatalf("depGraphFromPipInspect() error = %v", err)
	}
	if roots := g.Roots(); len(roots) != 1 || roots[0].NodeID() != root.NodeID() {
		t.Fatalf("expected a single graph root, got %s", g.PrettyString())
	}
	for _, member := range []string{"left@1.0.0", "right@1.0.0"} {
		paths, err := g.CollectPathsTo(member)
		if err != nil || len(paths) == 0 {
			t.Fatalf("cycle member %s is unreachable from the root (err=%v): %s", member, err, g.PrettyString())
		}
	}
}

// TestDirectPythonDeclarationsExcludesLockfiles guards the direct-dependency
// signal shared by the pip / Poetry / uv / Pipenv inspect paths: a lockfile
// records the whole resolved closure, so counting its entries as declarations
// would mark every transitive package direct — the bug in #273.
func TestDirectPythonDeclarationsExcludesLockfiles(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"pyproject.toml": `[project]
name = "demo-app"
dependencies = ["requests>=2", "flask"]

[project.optional-dependencies]
test = ["pytest>=8"]

[dependency-groups]
dev = ["ruff", {include-group = "test"}]

[tool.poetry.dependencies]
python = "^3.11"
httpx = "^0.27"

[tool.poetry.group.docs.dependencies]
sphinx = "^7.0"

[tool.uv]
dev-dependencies = ["mypy>=1.0"]
`,
		"Pipfile": `[packages]
boto3 = "*"

[dev-packages]
black = "*"
`,
		"poetry.lock": `[[package]]
name = "certifi"
version = "2024.8.30"

[[package]]
name = "urllib3"
version = "2.2.3"
`,
		"uv.lock": `[[package]]
name = "idna"
version = "3.10"
`,
		"Pipfile.lock":         `{"default": {"charset-normalizer": {"version": "==3.4.0"}}}`,
		"requirements.lock":    "click==8.1.8\n    # via flask\nmarkupsafe==3.0.2\n    # via jinja2\n",
		"requirements.txt":     "flask==3.1.1\n",
		"requirements-dev.txt": "pytest==8.3.3\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	declared, err := directPythonDeclarations(dir)
	if err != nil {
		t.Fatalf("directPythonDeclarations() error = %v", err)
	}
	for _, want := range []string{"flask", "requests", "pytest", "ruff", "httpx", "sphinx", "mypy", "boto3", "black"} {
		if _, ok := declared[want]; !ok {
			t.Errorf("expected %q to be a direct declaration, got %v", want, declared)
		}
	}
	// Lockfile records, and Poetry's interpreter marker, are not declarations.
	for _, unwanted := range []string{"certifi", "urllib3", "idna", "charset-normalizer", "click", "markupsafe", "python"} {
		if _, ok := declared[unwanted]; ok {
			t.Errorf("%q came from a lockfile (or is the python marker) and must not count as a direct declaration", unwanted)
		}
	}
}

// TestPythonProjectName covers issue #272: a requirements.txt project has no
// declared name, so the directory is the closest thing to one.
func TestPythonProjectName(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "billing")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if got := pythonProjectName(dir); got != "billing" {
		t.Fatalf("pythonProjectName() = %q, want %q", got, "billing")
	}
	if err := os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte("[project]\nname = \"acme-billing\"\n"), 0o644); err != nil {
		t.Fatalf("write pyproject.toml: %v", err)
	}
	if got := pythonProjectName(dir); got != "acme-billing" {
		t.Fatalf("pythonProjectName() = %q, want %q", got, "acme-billing")
	}
	if got := pythonProjectName(""); got != "root" {
		t.Fatalf("pythonProjectName(\"\") = %q, want %q", got, "root")
	}
}

// TestPythonRootNameFromRequest covers the naming sources that only the
// detection request knows about: the subproject directory a recursive scan
// walked into, and the repository behind a remote target (whose clone lives in
// a per-run temp directory that must never become the node's name).
func TestPythonRootNameFromRequest(t *testing.T) {
	cloneDir := filepath.Join(t.TempDir(), "bomly-git-3781263492")
	if err := os.MkdirAll(cloneDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	remote := sdk.ExecutionTarget{Kind: sdk.ExecutionTargetGitRepository, RepositoryURL: "https://github.com/acme/billing-service.git"}

	tests := []struct {
		name string
		req  sdk.DetectionRequest
		want string
	}{
		{
			name: "subproject directory",
			req:  sdk.DetectionRequest{Subproject: sdk.Subproject{RelativePath: "services/billing"}},
			want: "billing",
		},
		{
			name: "remote repository",
			req:  sdk.DetectionRequest{ExecutionTarget: remote, Subproject: sdk.Subproject{RelativePath: "."}},
			want: "billing-service",
		},
		{
			name: "temp clone directory is not a name",
			req:  sdk.DetectionRequest{},
			want: "root",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pythonRootName(tt.req, cloneDir); got != tt.want {
				t.Fatalf("pythonRootName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func assertDirectDependencies(t *testing.T, g *sdk.Graph, parentID string, want []string) {
	t.Helper()
	deps, err := g.DirectDependencies(parentID)
	if err != nil {
		t.Fatalf("DirectDependencies(%q) error = %v", parentID, err)
	}
	got := make([]string, 0, len(deps))
	for _, dep := range deps {
		got = append(got, dep.NodeID())
	}
	sort.Strings(got)
	sorted := append([]string{}, want...)
	sort.Strings(sorted)
	if strings.Join(got, ",") != strings.Join(sorted, ",") {
		t.Fatalf("DirectDependencies(%q) = %v, want %v: %s", parentID, got, sorted, g.PrettyString())
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

	g, err := depGraphFromPipfileLock(path, "")
	if err != nil {
		t.Fatalf("depGraphFromPipfileLock() error = %v", err)
	}
	if g.Size() != 4 {
		t.Fatalf("expected root plus 3 packages, got %d", g.Size())
	}
	if _, ok := g.DependencyNode("pkg:pypi/requests@2.2.1"); !ok {
		t.Fatalf("expected requests package, got %s", g.PrettyString())
	}
}

// A package listed in both the default and develop groups is reachable at
// both scopes; folding the duplicate record must not drop the second group's
// scope (https://github.com/bomly-dev/bomly-cli/issues/400).
func TestDepGraphFromPipfileLockPackageInBothGroupsKeepsBothScopes(t *testing.T) {
	path := t.TempDir() + "/Pipfile.lock"
	raw := []byte(`{
  "default": {
    "requests": {"version": "==2.2.1"}
  },
  "develop": {
    "requests": {"version": "==2.2.1"},
    "pytest": {"version": "==9.0.3"}
  }
}`)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write Pipfile.lock: %v", err)
	}

	g, err := depGraphFromPipfileLock(path, "")
	if err != nil {
		t.Fatalf("depGraphFromPipfileLock() error = %v", err)
	}
	shared, ok := g.DependencyNode("pkg:pypi/requests@2.2.1")
	if !ok {
		t.Fatalf("expected requests package, got %s", g.PrettyString())
	}
	if !shared.HasScope(sdk.ScopeRuntime) || !shared.HasScope(sdk.ScopeDevelopment) {
		t.Fatalf("requests scopes = %v; want both the default and develop group scopes", shared.Scopes)
	}
	devOnly, ok := g.DependencyNode("pkg:pypi/pytest@9.0.3")
	if !ok {
		t.Fatalf("expected pytest package, got %s", g.PrettyString())
	}
	if devOnly.HasScope(sdk.ScopeRuntime) || !devOnly.HasScope(sdk.ScopeDevelopment) {
		t.Fatalf("pytest scopes = %v; want the develop group scope only", devOnly.Scopes)
	}
}

func TestFilterPythonToolPackagesRemovesUndeclaredTools(t *testing.T) {
	g := sdk.New()
	root := testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemPython, Name: "root"}})
	requests := testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemPython, Name: "requests", Version: "2.32.0"}})
	pip := testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemPython, Name: "pip", Version: "25.0"}})
	for _, pkg := range []*sdk.DependencyNode{root, requests, pip} {
		if err := g.AddNode(pkg); err != nil {
			t.Fatalf("add package %q: %v", pkg.NodeID(), err)
		}
	}
	if err := g.AddEdge(root.NodeID(), requests.NodeID()); err != nil {
		t.Fatalf("add requests dependency: %v", err)
	}
	if err := g.AddEdge(root.NodeID(), pip.NodeID()); err != nil {
		t.Fatalf("add pip dependency: %v", err)
	}

	filtered, err := filterPythonToolPackages(g, t.TempDir(), "root")
	if err != nil {
		t.Fatalf("filterPythonToolPackages() error = %v", err)
	}
	if _, ok := testnodes.Find(filtered, "pip@25.0"); ok {
		t.Fatalf("expected undeclared pip to be removed: %s", filtered.PrettyString())
	}
	if _, ok := testnodes.Find(filtered, "requests@2.32.0"); !ok {
		t.Fatalf("expected application dependency to remain: %s", filtered.PrettyString())
	}
}

func TestFilterPythonToolPackagesKeepsDeclaredTools(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("pip==25.0\nrequests==2.32.0\n"), 0o644); err != nil {
		t.Fatalf("write requirements: %v", err)
	}
	g := sdk.New()
	root := testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemPython, Name: "root"}})
	pip := testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemPython, Name: "pip", Version: "25.0"}})
	wheel := testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemPython, Name: "wheel", Version: "0.45.0"}})
	for _, pkg := range []*sdk.DependencyNode{root, pip, wheel} {
		if err := g.AddNode(pkg); err != nil {
			t.Fatalf("add package %q: %v", pkg.NodeID(), err)
		}
	}
	if err := g.AddEdge(root.NodeID(), pip.NodeID()); err != nil {
		t.Fatalf("add pip dependency: %v", err)
	}
	if err := g.AddEdge(root.NodeID(), wheel.NodeID()); err != nil {
		t.Fatalf("add wheel dependency: %v", err)
	}

	filtered, err := filterPythonToolPackages(g, dir, "root")
	if err != nil {
		t.Fatalf("filterPythonToolPackages() error = %v", err)
	}
	if _, ok := testnodes.Find(filtered, "pip@25.0"); !ok {
		t.Fatalf("expected declared pip to remain: %s", filtered.PrettyString())
	}
	if _, ok := testnodes.Find(filtered, "wheel@0.45.0"); ok {
		t.Fatalf("expected undeclared wheel to be removed: %s", filtered.PrettyString())
	}
}

func TestPipShouldInstallDevRequirements(t *testing.T) {
	tests := []struct {
		name                 string
		scope                sdk.Scope
		requirementsFile     string
		devRequirementsExist bool
		want                 bool
	}{
		{
			name:                 "runtime skips dev requirements",
			scope:                sdk.ScopeRuntime,
			requirementsFile:     "requirements.txt",
			devRequirementsExist: true,
			want:                 false,
		},
		{
			name:                 "development installs dev requirements",
			scope:                sdk.ScopeDevelopment,
			requirementsFile:     "requirements.txt",
			devRequirementsExist: true,
			want:                 true,
		},
		{
			name:                 "unknown installs dev requirements to preserve full graph",
			scope:                sdk.ScopeUnknown,
			requirementsFile:     "requirements.txt",
			devRequirementsExist: true,
			want:                 true,
		},
		{
			name:                 "primary dev file is not installed twice",
			scope:                sdk.ScopeDevelopment,
			requirementsFile:     "requirements-dev.txt",
			devRequirementsExist: true,
			want:                 false,
		},
		{
			name:                 "missing dev file is skipped",
			scope:                sdk.ScopeDevelopment,
			requirementsFile:     "requirements.txt",
			devRequirementsExist: false,
			want:                 false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pipShouldInstallDevRequirements(tt.scope, tt.requirementsFile, tt.devRequirementsExist)
			if got != tt.want {
				t.Fatalf("pipShouldInstallDevRequirements() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAnnotateGraphScopes_DevelopmentFilterExcludesRuntime(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("requests==2.32.0\n"), 0o644); err != nil {
		t.Fatalf("write requirements: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "requirements-dev.txt"), []byte("pytest==8.0.0\n"), 0o644); err != nil {
		t.Fatalf("write dev requirements: %v", err)
	}

	g := sdk.New()
	root := testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemPython, Name: "demo-app", Version: "1.0.0"}})
	requests := testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemPython, Name: "requests", Version: "2.32.0"}})
	pytest := testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemPython, Name: "pytest", Version: "8.0.0"}})
	shared := testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemPython, Name: "pluggy", Version: "1.5.0"}})
	for _, pkg := range []*sdk.DependencyNode{root, requests, pytest, shared} {
		if err := g.AddNode(pkg); err != nil {
			t.Fatalf("add package %q: %v", pkg.NodeID(), err)
		}
	}
	for _, edge := range [][2]string{
		{root.NodeID(), requests.NodeID()},
		{root.NodeID(), pytest.NodeID()},
		{requests.NodeID(), shared.NodeID()},
		{pytest.NodeID(), shared.NodeID()},
	} {
		if err := g.AddEdge(edge[0], edge[1]); err != nil {
			t.Fatalf("add dependency %q -> %q: %v", edge[0], edge[1], err)
		}
	}

	annotateGraphScopes(g, dir)
	filtered, err := sdk.FilterGraphByScope(g, sdk.ScopeDevelopment)
	if err != nil {
		t.Fatalf("FilterGraphByScope() error = %v", err)
	}
	if _, ok := testnodes.Find(filtered, pytest.NodeID()); !ok {
		t.Fatalf("expected development dependency to remain: %s", filtered.PrettyString())
	}
	if _, ok := testnodes.Find(filtered, requests.NodeID()); ok {
		t.Fatalf("expected runtime dependency to be filtered: %s", filtered.PrettyString())
	}
	if _, ok := testnodes.Find(filtered, shared.NodeID()); ok {
		t.Fatalf("expected runtime-primary shared dependency to be filtered: %s", filtered.PrettyString())
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
		pkg := testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemPython,
			Name:    name,
			Version: "0.0.0"},
		})

		_ = g.AddNode(pkg)
	}

	attachDeclaredPositions(g, dir)

	cases := map[string]int{
		"requests": 2,
		"flask":    3,
		"numpy":    6,
	}
	for name, wantLine := range cases {
		pkg, _ := g.Node(name + "@0.0.0")
		if pkg == nil {
			t.Fatalf("%s missing from graph", name)
		}
		if len(mustDep(t, pkg).Locations) != 1 {
			t.Errorf("%s Locations = %d, want 1", name, len(mustDep(t, pkg).Locations))
			continue
		}
		loc := mustDep(t, pkg).Locations[0]
		if loc.RealPath != "requirements.txt" {
			t.Errorf("%s RealPath = %q, want requirements.txt", name, loc.RealPath)
		}
		if loc.Position == nil || loc.Position.Line != wantLine {
			t.Errorf("%s Position = %+v, want line %d", name, loc.Position, wantLine)
		}
	}

	// Transitive (not declared) gets no Locations.
	pkg, _ := testnodes.Find(g, "urllib3@0.0.0")
	if pkg != nil && len(mustDep(t, pkg).Locations) != 0 {
		t.Errorf("urllib3 (undeclared) should have no Locations; got %+v", mustDep(t, pkg).Locations)
	}
}

// mustDep narrows a graph node to the dependency node a case is asserting
// about, failing rather than panicking when the graph holds something else.
func mustDep(t testing.TB, node sdk.GraphNode) *sdk.DependencyNode {
	t.Helper()
	dep, ok := node.(*sdk.DependencyNode)
	if !ok {
		t.Fatalf("expected a dependency node, got %T", node)
	}
	return dep
}
