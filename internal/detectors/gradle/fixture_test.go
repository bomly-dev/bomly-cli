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
	parsed, err := depGraphFromGradleOutput(raw, "demo-app", nil)
	if err != nil {
		t.Fatalf("depGraphFromGradleOutput: %v", err)
	}
	g := parsed.graph

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

// TestGradleMultiProjectDependenciesFixture drives the parser against a
// committed multi-project report: per-project banners switch attribution, and
// `project :x` tokens resolve to the subproject's own root node.
func TestGradleMultiProjectDependenciesFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "dependencies-multiproject.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	modules := []gradleModule{
		{ProjectPath: ":app", Dir: "app", Name: "app", Group: "com.acme", ManifestFile: "build.gradle"},
		{ProjectPath: ":lib", Dir: "lib", Name: "lib", Group: "com.acme", ManifestFile: "build.gradle"},
	}
	parsed, err := depGraphFromGradleOutput(raw, "demo", modules)
	if err != nil {
		t.Fatalf("depGraphFromGradleOutput: %v", err)
	}
	g := parsed.graph

	if parsed.rootID != "demo" {
		t.Fatalf("root ID = %q, want demo", parsed.rootID)
	}
	if len(parsed.modules) != 2 {
		t.Fatalf("expected both subprojects to be seen, got %#v", parsed.modules)
	}
	appRoot, libRoot := parsed.modules[0], parsed.modules[1]
	if appRoot.module.ProjectPath != ":app" || libRoot.module.ProjectPath != ":lib" {
		t.Fatalf("unexpected module order: %#v", parsed.modules)
	}

	// Subproject roots are the build's own applications.
	for _, moduleRoot := range parsed.modules {
		node, ok := g.Node(moduleRoot.rootID)
		if !ok {
			t.Fatalf("missing subproject root node %q", moduleRoot.rootID)
		}
		if node.Type != sdk.PackageTypeApplication {
			t.Fatalf("subproject root %q type = %q, want application", moduleRoot.rootID, node.Type)
		}
	}

	// Root project keeps only its own dependency.
	requireGradleEdge(t, g, "demo", "org.apache.commons:commons-lang3@3.14.0")
	rootDeps, err := g.DirectDependencies("demo")
	if err != nil {
		t.Fatalf("dependencies(demo): %v", err)
	}
	if len(rootDeps) != 1 {
		t.Fatalf("expected 1 root project dep, got %d", len(rootDeps))
	}

	// app's tree: guava, the :lib project edge, and the shared commons-lang3.
	requireGradleEdge(t, g, appRoot.rootID, "com.google.guava:guava@33.0.0-jre")
	requireGradleEdge(t, g, appRoot.rootID, libRoot.rootID)
	requireGradleEdge(t, g, appRoot.rootID, "org.apache.commons:commons-lang3@3.14.0")
	requireGradleEdge(t, g, libRoot.rootID, "org.slf4j:slf4j-api@2.0.12")

	// No placeholder nodes — both the resolved `project :lib` token and the
	// declared-only `project lib (n)` form resolve to the subproject root.
	for _, placeholder := range []string{":lib", "lib"} {
		if _, ok := g.Node(placeholder); ok {
			t.Fatalf("expected project token to resolve to the subproject root, found placeholder node %q", placeholder)
		}
	}

	requireGradleScope(t, g, "org.junit.jupiter:junit-jupiter@5.10.2", sdk.ScopeDevelopment)
	requireGradleScope(t, g, "com.google.guava:guava@33.0.0-jre", sdk.ScopeRuntime)
}

// TestGradleMultiProjectUnknownProjectTokenFallsBack pins the degrade path:
// a `project :x` token for a project the settings walk does not know keeps
// today's placeholder-node behavior.
func TestGradleMultiProjectUnknownProjectTokenFallsBack(t *testing.T) {
	raw := []byte(`runtimeClasspath - Runtime classpath of source set 'main'.
\--- project :composite-part
`)
	parsed, err := depGraphFromGradleOutput(raw, "demo", nil)
	if err != nil {
		t.Fatalf("depGraphFromGradleOutput: %v", err)
	}
	if _, ok := parsed.graph.Node(":composite-part"); !ok {
		t.Fatal("expected placeholder node for unknown project token")
	}
	if len(parsed.modules) != 0 {
		t.Fatalf("expected no module roots, got %#v", parsed.modules)
	}
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
