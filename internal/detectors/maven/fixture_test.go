package maven

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

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
