package gradle

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

// TestGradleDependenciesFixture drives the `gradle dependencies` output parser
// against a committed fixture, exercising the real text-tree shape without
// invoking Gradle.
func TestGradleDependenciesFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "dependencies.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	g, err := depGraphFromGradleOutput(raw, "demo-app")
	if err != nil {
		t.Fatalf("depGraphFromGradleOutput: %v", err)
	}

	for _, want := range []string{
		"org.springframework:spring-web@6.1.3",
		"org.springframework:spring-jcl@6.1.3",
		"com.google.guava:guava@33.0.0-jre",
		"org.apache.commons:commons-lang3@3.14.0",
		"org.junit.jupiter:junit-jupiter@5.10.2",
		"org.mockito:mockito-core@5.10.0",
	} {
		if _, ok := g.Node(want); !ok {
			t.Errorf("missing node %s", want)
		}
	}

	requireGradleEdge(t, g, "demo-app", "com.google.guava:guava@33.0.0-jre")
	requireGradleEdge(t, g, "com.google.guava:guava@33.0.0-jre", "com.google.guava:failureaccess@1.0.2")
	requireGradleEdge(t, g, "org.springframework:spring-core@6.1.3", "org.springframework:spring-jcl@6.1.3")
	requireGradleEdge(t, g, "org.junit.jupiter:junit-jupiter@5.10.2", "org.junit.jupiter:junit-jupiter-api@5.10.2")

	// runtimeClasspath → runtime; testRuntimeClasspath → development.
	requireGradleScope(t, g, "com.google.guava:guava@33.0.0-jre", sdk.ScopeRuntime)
	requireGradleScope(t, g, "org.apache.commons:commons-lang3@3.14.0", sdk.ScopeRuntime)
	requireGradleScope(t, g, "org.junit.jupiter:junit-jupiter@5.10.2", sdk.ScopeDevelopment)
	requireGradleScope(t, g, "org.mockito:mockito-core@5.10.0", sdk.ScopeDevelopment)
}

func requireGradleEdge(t *testing.T, g *sdk.Graph, fromID, toID string) {
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

func requireGradleScope(t *testing.T, g *sdk.Graph, id string, scope sdk.Scope) {
	t.Helper()
	n, ok := g.Node(id)
	if !ok {
		t.Fatalf("missing node %s", id)
	}
	if got := n.PrimaryScope(); got != scope {
		t.Errorf("%s scope = %q, want %q", id, got, scope)
	}
}
