package maven

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

// TestMavenTGFMultiModule verifies the parser handles a multi-module reactor,
// where `mvn dependency:tree -DoutputType=tgf` emits one TGF block per module
// (nodes, `#`, edges) concatenated. Regression for a real failure on a
// 13-module reactor: the old single nodes→edges flag dropped every block after
// the first, so their edges referenced ids that were never registered
// ("maven tgf references unknown package"). The fixture has three blocks; the
// assertions cover nodes and edges from the 2nd and 3rd blocks specifically.
func TestMavenTGFMultiModule(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "dependency-tree-multimodule.tgf"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	g, err := depGraphFromMavenTGF(raw)
	if err != nil {
		t.Fatalf("depGraphFromMavenTGF: %v", err)
	}

	for _, want := range []string{
		"com.bomly:module-a@1.0.0",
		"org.apache.commons:commons-lang3@3.12.0",
		"com.bomly:module-b@1.0.0",
		"com.fasterxml.jackson.core:jackson-databind@2.13.0",
		"org.yaml:snakeyaml@1.30",
		"com.bomly:module-c@1.0.0",
		"junit:junit@4.13.2",
		"org.hamcrest:hamcrest-core@1.3",
	} {
		if _, ok := g.Node(want); !ok {
			t.Errorf("missing node %s", want)
		}
	}

	// Edges from the 2nd and 3rd blocks — the ones the old parser lost.
	requireMavenEdge(t, g, "com.bomly:module-b@1.0.0", "com.fasterxml.jackson.core:jackson-databind@2.13.0")
	requireMavenEdge(t, g, "com.fasterxml.jackson.core:jackson-databind@2.13.0", "org.yaml:snakeyaml@1.30")
	requireMavenEdge(t, g, "com.bomly:module-c@1.0.0", "junit:junit@4.13.2")
	requireMavenEdge(t, g, "junit:junit@4.13.2", "org.hamcrest:hamcrest-core@1.3")

	requireMavenScope(t, g, "org.yaml:snakeyaml@1.30", sdk.ScopeRuntime)
	requireMavenScope(t, g, "junit:junit@4.13.2", sdk.ScopeDevelopment)

	// Each reactor module is the scopeless root of its block, so all three
	// module artifacts land in the graph as roots (no incoming edges).
	requireMavenRoots(t, g, "com.bomly:module-a@1.0.0", "com.bomly:module-b@1.0.0", "com.bomly:module-c@1.0.0")
}

// TestMavenTGFInterModuleAndSharedScopes covers the two realistic reactor
// cases the flat fixture omits: a module that depends on another reactor
// module (so the module artifact appears scopeless in its own block and
// scoped in a dependent's block), and a shared dependency that appears with
// different scopes across modules (so its scopes must merge).
func TestMavenTGFInterModuleAndSharedScopes(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "dependency-tree-multimodule-shared.tgf"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	g, err := depGraphFromMavenTGF(raw)
	if err != nil {
		t.Fatalf("depGraphFromMavenTGF: %v", err)
	}

	// Inter-module dependency: module-b depends on module-a. module-a appears
	// scopeless (as a root) in its own block and scoped ("compile") as a
	// dependency in module-b's block; the two occurrences must collapse onto
	// one node and the edge must survive.
	requireMavenEdge(t, g, "com.bomly:module-b@1.0.0", "com.bomly:module-a@1.0.0")

	// Shared dependency seen compile in module-a and test in module-b: both
	// scopes merge onto the single node (runtime wins as the primary scope).
	shared, ok := g.Node("org.apache.commons:commons-lang3@3.12.0")
	if !ok {
		t.Fatalf("missing shared node")
	}
	if !shared.HasScope(sdk.ScopeRuntime) || !shared.HasScope(sdk.ScopeDevelopment) {
		t.Errorf("commons-lang3 scopes = %v, want both runtime and development", shared.Scopes)
	}
}

// TestMavenTGFFixture drives the dependency-tree (TGF) parser against a committed
// fixture captured from `mvn dependency:tree -DoutputType=tgf`, so it exercises
// the real output shape without invoking Maven.
func TestMavenTGFFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "dependency-tree.tgf"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	g, err := depGraphFromMavenTGF(raw)
	if err != nil {
		t.Fatalf("depGraphFromMavenTGF: %v", err)
	}

	const root = "com.bomly:example-app@1.0.0"
	for _, want := range []string{
		root,
		"org.springframework:spring-web@5.3.30",
		"commons-fileupload:commons-fileupload@1.4",
		"commons-io:commons-io@2.11.0",
		"org.mindrot:jbcrypt@0.4",
		"junit:junit@4.13.2",
		"org.hamcrest:hamcrest-core@1.3",
	} {
		if _, ok := g.Node(want); !ok {
			t.Errorf("missing node %s", want)
		}
	}

	requireMavenEdge(t, g, root, "org.springframework:spring-web@5.3.30")
	requireMavenEdge(t, g, "org.springframework:spring-web@5.3.30", "org.springframework:spring-core@5.3.30")
	requireMavenEdge(t, g, "commons-fileupload:commons-fileupload@1.4", "commons-io:commons-io@2.11.0")
	requireMavenEdge(t, g, "junit:junit@4.13.2", "org.hamcrest:hamcrest-core@1.3")

	// compile → runtime, test → development.
	requireMavenScope(t, g, "org.springframework:spring-web@5.3.30", sdk.ScopeRuntime)
	requireMavenScope(t, g, "commons-io:commons-io@2.11.0", sdk.ScopeRuntime)
	requireMavenScope(t, g, "junit:junit@4.13.2", sdk.ScopeDevelopment)
	requireMavenScope(t, g, "org.hamcrest:hamcrest-core@1.3", sdk.ScopeDevelopment)
}

func requireMavenEdge(t *testing.T, g *sdk.Graph, fromID, toID string) {
	t.Helper()
	deps, err := g.DirectDependencies(fromID)
	if err != nil {
		t.Fatalf("dependencies(%s): %v", fromID, err)
	}
	for _, d := range deps {
		if d.ID == toID {
			return
		}
	}
	t.Errorf("expected edge %s → %s", fromID, toID)
}

func requireMavenRoots(t *testing.T, g *sdk.Graph, want ...string) {
	t.Helper()
	got := make(map[string]struct{})
	for _, r := range g.Roots() {
		if r != nil {
			got[r.ID] = struct{}{}
		}
	}
	for _, id := range want {
		if _, ok := got[id]; !ok {
			t.Errorf("expected %s to be a graph root; roots = %v", id, got)
		}
	}
}

func requireMavenScope(t *testing.T, g *sdk.Graph, id string, scope sdk.Scope) {
	t.Helper()
	n, ok := g.Node(id)
	if !ok {
		t.Fatalf("missing node %s", id)
	}
	if got := n.PrimaryScope(); got != scope {
		t.Errorf("%s scope = %q, want %q", id, got, scope)
	}
}
