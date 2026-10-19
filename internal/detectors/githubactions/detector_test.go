package githubactions

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/testnodes"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

func TestDetectorResolveGraphFromFixtureProject(t *testing.T) {
	detector := Detector{}
	result, err := detector.ResolveGraph(context.Background(), plugin.DetectionRequest{
		ProjectPath:     "testdata/project",
		PackageManager:  model.PackageManagerGitHubActions,
		Ecosystem:       model.EcosystemGitHub,
		ExecutionTarget: plugin.ExecutionTarget{Location: "testdata/project"},
	})
	if err != nil {
		t.Fatalf("ResolveGraph() error = %v", err)
	}
	g, err := result.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	if _, ok := testnodes.Find(g, "actions:checkout@v4"); !ok {
		t.Fatal("expected actions/checkout package")
	}
	if _, ok := testnodes.Find(g, "actions:cache@v4"); !ok {
		t.Fatal("expected actions/cache package")
	}
}

func TestDepGraphFromRepository(t *testing.T) {
	projectDir := t.TempDir()
	workflowDir := filepath.Join(projectDir, ".github", "workflows")
	actionDir := filepath.Join(projectDir, ".github", "actions", "local-setup")
	if err := os.MkdirAll(workflowDir, 0o755); err != nil {
		t.Fatalf("create workflow dir: %v", err)
	}
	if err := os.MkdirAll(actionDir, 0o755); err != nil {
		t.Fatalf("create action dir: %v", err)
	}

	workflow := []byte("jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n      - uses: ./.github/actions/local-setup\n  deploy:\n    uses: ./.github/workflows/reusable.yml\n")
	if err := os.WriteFile(filepath.Join(workflowDir, "ci.yml"), workflow, 0o644); err != nil {
		t.Fatalf("write workflow: %v", err)
	}
	reusable := []byte("jobs:\n  nested:\n    steps:\n      - uses: actions/setup-java@v5\n")
	if err := os.WriteFile(filepath.Join(workflowDir, "reusable.yml"), reusable, 0o644); err != nil {
		t.Fatalf("write reusable workflow: %v", err)
	}
	action := []byte("runs:\n  using: composite\n  steps:\n    - uses: actions/cache@v4\n")
	if err := os.WriteFile(filepath.Join(actionDir, "action.yml"), action, 0o644); err != nil {
		t.Fatalf("write action manifest: %v", err)
	}

	g, err := depGraphFromRepository(projectDir)
	if err != nil {
		t.Fatalf("depGraphFromRepository() error = %v", err)
	}
	if g.Size() != 6 {
		t.Fatalf("expected 6 packages, got %d", g.Size())
	}

	cache, ok := testnodes.FindDep(g, "actions:cache@v4")
	if !ok {
		t.Fatal("expected actions/cache package")
	}
	if got := string(cache.PrimaryScope()); got != string(model.ScopeRuntime) {
		t.Fatalf("expected runtime scope, got %q", got)
	}

	localAction, ok := testnodes.Find(g, "action:.github/actions/local-setup")
	if !ok {
		t.Fatal("expected local action package")
	}
	deps, err := g.DirectDependencies(localAction.NodeID())
	if err != nil {
		t.Fatalf("Dependencies() error = %v", err)
	}
	if len(deps) != 1 || !testnodes.Is(deps[0], "actions:cache@v4") {
		t.Fatalf("expected local action to depend on actions/cache, got %#v", deps)
	}
	workflowNode, ok := testnodes.Find(g, "workflow:.github/workflows/ci.yml")
	if !ok {
		t.Fatal("expected ci workflow package")
	}
	workflowDeps, err := g.DirectDependencies(workflowNode.NodeID())
	if err != nil {
		t.Fatalf("Dependencies() error = %v", err)
	}
	if len(workflowDeps) != 3 {
		t.Fatalf("expected 3 workflow dependencies, got %d", len(workflowDeps))
	}
}

func TestDetectorResolveGraphAttachesUsesLineLocations(t *testing.T) {
	projectDir := t.TempDir()
	workflowDir := filepath.Join(projectDir, ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0o755); err != nil {
		t.Fatalf("create workflow dir: %v", err)
	}
	workflow := []byte("name: CI\njobs:\n  build:\n    steps:\n      - name: Review dependencies\n        uses: actions/dependency-review-action@v5\n      - uses: github/codeql-action/upload-sarif@v4\n")
	if err := os.WriteFile(filepath.Join(workflowDir, "guard.yml"), workflow, 0o644); err != nil {
		t.Fatalf("write workflow: %v", err)
	}

	result, err := (Detector{}).ResolveGraph(context.Background(), plugin.DetectionRequest{
		ProjectPath:     projectDir,
		PackageManager:  model.PackageManagerGitHubActions,
		Ecosystem:       model.EcosystemGitHub,
		ExecutionTarget: plugin.ExecutionTarget{Location: projectDir},
	})
	if err != nil {
		t.Fatalf("ResolveGraph() error = %v", err)
	}
	g, err := result.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}

	dependencyReview, ok := testnodes.FindDep(g, "actions:dependency-review-action@v5")
	if !ok {
		t.Fatal("expected actions/dependency-review-action package")
	}
	if len(dependencyReview.Locations) != 1 {
		t.Fatalf("dependency-review-action locations = %#v, want one location", dependencyReview.Locations)
	}
	loc := dependencyReview.Locations[0]
	if loc.RealPath != ".github/workflows/guard.yml" || loc.AccessPath != ".github/workflows/guard.yml" {
		t.Fatalf("location path = %#v, want workflow manifest path", loc)
	}
	if loc.Position == nil || loc.Position.File != ".github/workflows/guard.yml" || loc.Position.Line != 6 || loc.Position.Column == 0 {
		t.Fatalf("location position = %#v, want workflow uses line with column", loc.Position)
	}

	codeql, ok := testnodes.FindDep(g, "github:codeql-action/upload-sarif@v4")
	if !ok {
		t.Fatal("expected github/codeql-action/upload-sarif package")
	}
	if len(codeql.Locations) != 1 || codeql.Locations[0].Position == nil || codeql.Locations[0].Position.Line != 7 {
		t.Fatalf("codeql action locations = %#v, want line 7", codeql.Locations)
	}
}

func TestDetectorResolveGraphPreservesDuplicateUsesLocations(t *testing.T) {
	projectDir := t.TempDir()
	workflowDir := filepath.Join(projectDir, ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0o755); err != nil {
		t.Fatalf("create workflow dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workflowDir, "ci.yml"), []byte("jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v5\n"), 0o644); err != nil {
		t.Fatalf("write ci workflow: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workflowDir, "guard.yml"), []byte("jobs:\n  guard:\n    steps:\n      - name: Checkout\n        uses: actions/checkout@v5\n"), 0o644); err != nil {
		t.Fatalf("write guard workflow: %v", err)
	}

	result, err := (Detector{}).ResolveGraph(context.Background(), plugin.DetectionRequest{
		ProjectPath:     projectDir,
		PackageManager:  model.PackageManagerGitHubActions,
		Ecosystem:       model.EcosystemGitHub,
		ExecutionTarget: plugin.ExecutionTarget{Location: projectDir},
	})
	if err != nil {
		t.Fatalf("ResolveGraph() error = %v", err)
	}
	g, err := result.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	checkout, ok := testnodes.FindDep(g, "actions:checkout@v5")
	if !ok {
		t.Fatal("expected actions/checkout package")
	}
	if len(checkout.Locations) != 2 {
		t.Fatalf("checkout locations = %#v, want both workflow locations", checkout.Locations)
	}
	got := map[string]int{}
	for _, loc := range checkout.Locations {
		if loc.Position != nil {
			got[loc.Position.File] = loc.Position.Line
		}
	}
	if got[".github/workflows/ci.yml"] != 4 || got[".github/workflows/guard.yml"] != 5 {
		t.Fatalf("checkout locations = %#v, want ci line 4 and guard line 5", checkout.Locations)
	}
}

func TestDepGraphDigests(t *testing.T) {
	projectDir := t.TempDir()
	workflowDir := filepath.Join(projectDir, ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0o755); err != nil {
		t.Fatalf("create workflow dir: %v", err)
	}
	pinned := "11bd71901bbe5b1630ceea73d27597364c9af683"
	workflow := []byte("jobs:\n  build:\n    steps:\n      - uses: actions/checkout@" + pinned + "\n      - uses: actions/cache@v4\n")
	if err := os.WriteFile(filepath.Join(workflowDir, "ci.yml"), workflow, 0o644); err != nil {
		t.Fatalf("write workflow: %v", err)
	}

	g, err := depGraphFromRepository(projectDir)
	if err != nil {
		t.Fatalf("depGraphFromRepository() error = %v", err)
	}

	found := map[string][]model.Digest{}
	g.WalkDependencyNodes(func(node *model.DependencyNode) bool {
		found[node.Name] = node.Digests
		return true
	})

	checkout := found["checkout"]
	if len(checkout) != 1 || checkout[0].Algorithm != model.DigestAlgorithmSHA1 || checkout[0].Value != pinned {
		t.Fatalf("expected pinned commit digest on actions/checkout, got %#v", checkout)
	}
	if len(found["cache"]) != 0 {
		t.Fatalf("tag-pinned action must not carry a digest, got %#v", found["cache"])
	}
	wf := found[".github/workflows/ci.yml"]
	if len(wf) != 1 || wf[0].Algorithm != model.DigestAlgorithmSHA256 || len(wf[0].Value) != 64 {
		t.Fatalf("expected sha256 file digest on the workflow manifest, got %#v", wf)
	}
}

// Every external reference publishes where it resolves from, so an SBOM
// consumer can tell a commit ID from a content digest (issue #508): the
// repository is the first two path segments and the revision is the ref the
// manifest wrote, whether or not that ref is a commit. Local references name
// files in the scanned tree and resolve from nowhere.
func TestDepGraphOrigins(t *testing.T) {
	projectDir := t.TempDir()
	workflowDir := filepath.Join(projectDir, ".github", "workflows")
	actionDir := filepath.Join(projectDir, ".github", "actions", "local-setup")
	for _, dir := range []string{workflowDir, actionDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("create %s: %v", dir, err)
		}
	}
	pinned := "11bd71901bbe5b1630ceea73d27597364c9af683"
	workflow := []byte("jobs:\n  build:\n    steps:\n      - uses: actions/checkout@" + pinned + "\n" +
		"      - uses: actions/cache@v4\n" +
		"      - uses: github/codeql-action/upload-sarif@" + pinned + "\n" +
		"      - uses: ./.github/actions/local-setup\n" +
		"      - uses: $/.github/actions/local-setup\n" +
		"  provenance:\n    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0\n")
	if err := os.WriteFile(filepath.Join(workflowDir, "ci.yml"), workflow, 0o644); err != nil {
		t.Fatalf("write workflow: %v", err)
	}
	if err := os.WriteFile(filepath.Join(actionDir, "action.yml"), []byte("runs:\n  using: composite\n  steps: []\n"), 0o644); err != nil {
		t.Fatalf("write action manifest: %v", err)
	}

	g, err := depGraphFromRepository(projectDir)
	if err != nil {
		t.Fatalf("depGraphFromRepository() error = %v", err)
	}
	found := map[string][]model.DependencyOrigin{}
	g.WalkDependencyNodes(func(node *model.DependencyNode) bool {
		found[node.Name] = node.Origins
		// "$/path" is the workflow's own repository, never an owner named
		// "$": the pre-fix parse published https://github.com/$/.github.
		if node.Org == "$" {
			t.Errorf("self-repository reference produced an external node %q with origins %#v", node.NodeID(), node.Origins)
		}
		return true
	})

	want := map[string]model.DependencyOrigin{
		"checkout":                   {Repository: "https://github.com/actions/checkout", Revision: pinned},
		"cache":                      {Repository: "https://github.com/actions/cache", Revision: "v4"},
		"codeql-action/upload-sarif": {Repository: "https://github.com/github/codeql-action", Revision: pinned},
		"slsa-github-generator/.github/workflows/generator_generic_slsa3.yml": {Repository: "https://github.com/slsa-framework/slsa-github-generator", Revision: "v2.1.0"},
	}
	for name, origin := range want {
		got, ok := found[name]
		if !ok {
			t.Fatalf("node %q not found; graph has %v", name, found)
		}
		if len(got) != 1 || got[0] != origin {
			t.Errorf("origins of %q = %#v, want [%#v]", name, got, origin)
		}
	}
	for _, local := range []string{".github/workflows/ci.yml", ".github/actions/local-setup"} {
		if got := found[local]; len(got) != 0 {
			t.Errorf("local reference %q must carry no origin, got %#v", local, got)
		}
	}
}

// The host decides whether an origin is a statement or a guess: github.com
// is where a workflow's references resolve unless the repository lives on
// an enterprise instance, which looks itself up first and may fall back to
// github.com -- a choice the workflow file does not record.
func TestOriginHost(t *testing.T) {
	cases := []struct {
		name   string
		target plugin.ExecutionTarget
		want   string
	}{
		{name: "filesystem", target: plugin.ExecutionTarget{Kind: plugin.ExecutionTargetFilesystem, Location: "/src"}, want: githubHost},
		{name: "git repository without url", target: plugin.ExecutionTarget{Kind: plugin.ExecutionTargetGitRepository}, want: githubHost},
		{name: "github.com https", target: plugin.ExecutionTarget{Kind: plugin.ExecutionTargetGitRepository, RepositoryURL: "https://github.com/org/repo"}, want: githubHost},
		{name: "github.com scp-like", target: plugin.ExecutionTarget{Kind: plugin.ExecutionTargetGitRepository, RepositoryURL: "git@github.com:org/repo.git"}, want: githubHost},
		{name: "github.com scp-like without user", target: plugin.ExecutionTarget{Kind: plugin.ExecutionTargetGitRepository, RepositoryURL: "github.com:org/repo.git"}, want: githubHost},
		{name: "github.com ssh scheme", target: plugin.ExecutionTarget{Kind: plugin.ExecutionTargetGitRepository, RepositoryURL: "ssh://git@github.com/org/repo.git"}, want: githubHost},
		{name: "github.com upper case with www", target: plugin.ExecutionTarget{Kind: plugin.ExecutionTargetGitRepository, RepositoryURL: "https://WWW.GitHub.com/org/repo"}, want: githubHost},
		{name: "enterprise server", target: plugin.ExecutionTarget{Kind: plugin.ExecutionTargetGitRepository, RepositoryURL: "https://ghe.example.com/org/repo"}, want: ""},
		{name: "ghe.com", target: plugin.ExecutionTarget{Kind: plugin.ExecutionTargetGitRepository, RepositoryURL: "https://acme.ghe.com/org/repo"}, want: ""},
		{name: "enterprise scp-like", target: plugin.ExecutionTarget{Kind: plugin.ExecutionTargetGitRepository, RepositoryURL: "git@ghe.example.com:org/repo.git"}, want: ""},
		{name: "enterprise scp-like without user", target: plugin.ExecutionTarget{Kind: plugin.ExecutionTargetGitRepository, RepositoryURL: "ghe.example.com:org/repo.git"}, want: ""},
		{name: "bare path", target: plugin.ExecutionTarget{Kind: plugin.ExecutionTargetGitRepository, RepositoryURL: "org/repo"}, want: ""},
		{name: "unparseable url", target: plugin.ExecutionTarget{Kind: plugin.ExecutionTargetGitRepository, RepositoryURL: "::not a url"}, want: ""},
	}
	for _, tc := range cases {
		if got := originHost(tc.target); got != tc.want {
			t.Errorf("%s: originHost(%+v) = %q, want %q", tc.name, tc.target, got, tc.want)
		}
	}
}

// ResolveGraph is where the execution target meets the references: a
// repository cloned from an enterprise host exports no origin at all, and
// one from github.com exports the repository and ref.
func TestResolveGraphOriginsFollowTheTargetHost(t *testing.T) {
	originsOf := func(t *testing.T, target plugin.ExecutionTarget) map[string][]model.DependencyOrigin {
		t.Helper()
		result, err := Detector{}.ResolveGraph(context.Background(), plugin.DetectionRequest{
			ProjectPath:     "testdata/project",
			PackageManager:  model.PackageManagerGitHubActions,
			Ecosystem:       model.EcosystemGitHub,
			ExecutionTarget: target,
		})
		if err != nil {
			t.Fatalf("ResolveGraph() error = %v", err)
		}
		g, err := result.ConsolidatedGraph()
		if err != nil {
			t.Fatalf("ConsolidatedGraph() error = %v", err)
		}
		found := map[string][]model.DependencyOrigin{}
		g.WalkDependencyNodes(func(node *model.DependencyNode) bool {
			found[node.Org+"/"+node.Name] = node.Origins
			return true
		})
		return found
	}

	enterprise := originsOf(t, plugin.ExecutionTarget{Kind: plugin.ExecutionTargetGitRepository, Location: "testdata/project", RepositoryURL: "https://ghe.example.com/org/repo"})
	for id, origins := range enterprise {
		if len(origins) != 0 {
			t.Errorf("enterprise-hosted scan published an origin for %q: %#v", id, origins)
		}
	}

	public := originsOf(t, plugin.ExecutionTarget{Kind: plugin.ExecutionTargetGitRepository, Location: "testdata/project", RepositoryURL: "https://github.com/org/repo"})
	checkout := public["actions/checkout"]
	if len(checkout) != 1 || checkout[0] != (model.DependencyOrigin{Repository: "https://github.com/actions/checkout", Revision: "v4"}) {
		t.Errorf("github.com-hosted scan origins for actions/checkout = %#v", checkout)
	}
}

// "$/path" is defined against the repository root alone. "./path" also
// gets a caller-relative reading, and that reading must not leak into the
// self-repository form: "$/inner" from .github/actions/outer is not the
// nested .github/actions/outer/inner, even when only the nested one exists.
func TestSelfRepositoryReferenceResolvesFromRootOnly(t *testing.T) {
	projectDir := t.TempDir()
	outerDir := filepath.Join(projectDir, ".github", "actions", "outer")
	nestedDir := filepath.Join(outerDir, "inner")
	for _, dir := range []string{filepath.Join(projectDir, ".github", "workflows"), nestedDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("create %s: %v", dir, err)
		}
	}
	files := map[string]string{
		filepath.Join(projectDir, ".github", "workflows", "ci.yml"): "jobs:\n  build:\n    steps:\n      - uses: ./.github/actions/outer\n",
		filepath.Join(outerDir, "action.yml"):                       "runs:\n  using: composite\n  steps:\n    - uses: $/inner\n    - uses: ./inner\n",
		filepath.Join(nestedDir, "action.yml"):                      "runs:\n  using: composite\n  steps: []\n",
	}
	for path, content := range files {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	g, err := depGraphFromRepository(projectDir)
	if err != nil {
		t.Fatalf("depGraphFromRepository() error = %v", err)
	}
	outer, err := localActionNode(".github/actions/outer")
	if err != nil {
		t.Fatalf("localActionNode() error = %v", err)
	}
	depsNodes, err := g.DirectDependencies(outer.NodeID())
	if err != nil {
		t.Fatalf("DirectDependencies() error = %v", err)
	}
	names := map[string]bool{}
	for _, dep := range model.DependencyNodesOf(depsNodes) {
		names[dep.Name] = true
	}
	// "./inner" keeps its caller-relative reading and finds the nested action.
	if !names[".github/actions/outer/inner"] {
		t.Errorf("./inner should resolve caller-relative to the nested action; got %v", names)
	}
	// "$/inner" names <root>/inner, which does not exist, so it stays an
	// unresolved local reference rather than borrowing the nested action.
	if !names["inner"] {
		t.Errorf("$/inner should resolve against the repository root only; got %v", names)
	}
}

func TestActionRepositoryURL(t *testing.T) {
	cases := map[[3]string]string{
		{githubHost, "actions", "checkout"}:                                                                   "https://github.com/actions/checkout",
		{githubHost, "github", "codeql-action/upload-sarif"}:                                                  "https://github.com/github/codeql-action",
		{githubHost, "slsa-framework", "slsa-github-generator/.github/workflows/generator_generic_slsa3.yml"}: "https://github.com/slsa-framework/slsa-github-generator",
		{githubHost, "", "checkout"}:                                                                          "",
		{githubHost, "actions", ""}:                                                                           "",
		{githubHost, "actions", "/checkout"}:                                                                  "",
		{"", "actions", "checkout"}:                                                                           "",
	}
	for input, want := range cases {
		if got := actionRepositoryURL(input[0], input[1], input[2]); got != want {
			t.Errorf("actionRepositoryURL(%q, %q, %q) = %q, want %q", input[0], input[1], input[2], got, want)
		}
	}
}

func TestIsGitCommitSHA(t *testing.T) {
	if !isGitCommitSHA("11bd71901bbe5b1630ceea73d27597364c9af683") {
		t.Fatal("expected 40-hex value to be recognized as a commit SHA")
	}
	for _, value := range []string{"v4", "main", "11bd719", "11bd71901bbe5b1630ceea73d27597364c9afzzz"} {
		if isGitCommitSHA(value) {
			t.Fatalf("value %q must not be treated as a commit SHA", value)
		}
	}
}

// mustDep narrows a graph node to the dependency node a case is asserting
// about, failing rather than panicking when the graph holds something else.
func mustDep(t testing.TB, node model.GraphNode) *model.DependencyNode {
	t.Helper()
	dep, ok := node.(*model.DependencyNode)
	if !ok {
		t.Fatalf("expected a dependency node, got %T", node)
	}
	return dep
}
