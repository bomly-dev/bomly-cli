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
	g := parsed.rootGraph

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
// committed multi-project report: per-project banners switch which graph the
// sections build into, and `project :x` tokens become project-local reference
// nodes that share the referenced module root's identity.
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

	if parsed.rootID != "demo" {
		t.Fatalf("root ID = %q, want demo", parsed.rootID)
	}
	if len(parsed.modules) != 2 {
		t.Fatalf("expected both subprojects to be seen, got %#v", parsed.modules)
	}
	appEntry, libEntry := parsed.modules[0], parsed.modules[1]
	if appEntry.module.ProjectPath != ":app" || libEntry.module.ProjectPath != ":lib" {
		t.Fatalf("unexpected module order: %#v", parsed.modules)
	}

	// Subproject roots are the build's own first-party applications, and the
	// root project node is first-party too.
	rootNode, ok := parsed.rootGraph.Node(parsed.rootID)
	if !ok || !rootNode.FirstParty {
		t.Fatalf("root project node must be first-party, got %#v", rootNode)
	}
	for _, moduleEntry := range parsed.modules {
		node, ok := moduleEntry.graph.Node(moduleEntry.rootID)
		if !ok {
			t.Fatalf("missing subproject root node %q", moduleEntry.rootID)
		}
		if node.Type != sdk.PackageTypeApplication || !node.FirstParty {
			t.Fatalf("subproject root %q = %#v, want first-party application", moduleEntry.rootID, node.Coordinates)
		}
	}

	// Root project's graph keeps only its own dependency.
	requireGradleEdge(t, parsed.rootGraph, "demo", "org.apache.commons:commons-lang3@3.14.0")
	rootDeps, err := parsed.rootGraph.DirectDependencies("demo")
	if err != nil {
		t.Fatalf("dependencies(demo): %v", err)
	}
	if len(rootDeps) != 1 {
		t.Fatalf("expected 1 root project dep, got %d", len(rootDeps))
	}

	// app's graph: guava, the :lib project reference (with lib's inlined
	// subtree), and the shared commons-lang3.
	appGraph := appEntry.graph
	requireGradleEdge(t, appGraph, appEntry.rootID, "com.google.guava:guava@33.0.0-jre")
	requireGradleEdge(t, appGraph, appEntry.rootID, libEntry.rootID)
	requireGradleEdge(t, appGraph, appEntry.rootID, "org.apache.commons:commons-lang3@3.14.0")
	requireGradleEdge(t, appGraph, libEntry.rootID, "org.slf4j:slf4j-api@2.0.12")

	// The :lib reference in app's graph is a project-local instance carrying
	// the section scope — it shares the ID of lib's own root, but not the
	// node instance, so app-side scopes cannot leak into lib's entry.
	libRef, ok := appGraph.Node(libEntry.rootID)
	if !ok {
		t.Fatalf("missing :lib reference node in app graph")
	}
	libOwnRoot, _ := libEntry.graph.Node(libEntry.rootID)
	if libRef == libOwnRoot {
		t.Fatal("project reference must not share the module root node instance")
	}
	if !libRef.FirstParty || libRef.Type != sdk.PackageTypeApplication {
		t.Fatalf("project reference node = %#v, want first-party application", libRef.Coordinates)
	}
	if got := libRef.PrimaryScope(); got != sdk.ScopeRuntime {
		t.Fatalf(":lib reference scope in app graph = %q, want runtime", got)
	}
	if got := libOwnRoot.PrimaryScope(); got != sdk.ScopeUnknown {
		t.Fatalf("lib's own root scope = %q, want unknown (no app-side leak)", got)
	}

	// lib's graph: only its own dependency, with lib-local scope.
	libGraph := libEntry.graph
	requireGradleEdge(t, libGraph, libEntry.rootID, "org.slf4j:slf4j-api@2.0.12")
	if _, ok := libGraph.Node("com.google.guava:guava@33.0.0-jre"); ok {
		t.Fatal("lib graph must not contain app dependencies")
	}
	if _, ok := libGraph.Node("org.junit.jupiter:junit-jupiter@5.10.2"); ok {
		t.Fatal("lib graph must not contain app test dependencies")
	}

	// No placeholder nodes — both the resolved `project :lib` token and the
	// declared-only `project lib (n)` form resolve to the reference node.
	for _, placeholder := range []string{":lib", "lib"} {
		if _, ok := appGraph.Node(placeholder); ok {
			t.Fatalf("expected project token to resolve to the module identity, found placeholder node %q", placeholder)
		}
	}

	requireGradleScope(t, appGraph, "org.junit.jupiter:junit-jupiter@5.10.2", sdk.ScopeDevelopment)
	requireGradleScope(t, appGraph, "com.google.guava:guava@33.0.0-jre", sdk.ScopeRuntime)
	requireGradleScope(t, appGraph, "org.slf4j:slf4j-api@2.0.12", sdk.ScopeRuntime)
	requireGradleScope(t, libGraph, "org.slf4j:slf4j-api@2.0.12", sdk.ScopeRuntime)
}

// TestGradleMultiProjectRuntimeScopeFilterKeepsProjectEdges reproduces the
// review P1: in a `--scope runtime` scan, the `project :lib` reference inside
// :app's runtime classpath must survive scope filtering along with its
// subtree, because the reference node carries the section's runtime scope.
func TestGradleMultiProjectRuntimeScopeFilterKeepsProjectEdges(t *testing.T) {
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
	result := sdk.DetectionResult{Graphs: &sdk.GraphContainer{
		Entries: subprojectGraphEntries(parsed, sdk.ManifestMetadata{Path: "build.gradle"}, t.TempDir()),
	}}

	filtered, err := sdk.FilterDetectionResultByScope(result, sdk.ScopeRuntime)
	if err != nil {
		t.Fatalf("FilterDetectionResultByScope: %v", err)
	}
	appGraph := filtered.Graphs.Entries[1].Graph
	appEntry := parsed.modules[0]
	libEntry := parsed.modules[1]
	requireGradleEdge(t, appGraph, appEntry.rootID, libEntry.rootID)
	requireGradleEdge(t, appGraph, libEntry.rootID, "org.slf4j:slf4j-api@2.0.12")
	if _, ok := appGraph.Node("org.junit.jupiter:junit-jupiter@5.10.2"); ok {
		t.Fatal("runtime filter must drop the test-only dependency")
	}
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
	if _, ok := parsed.rootGraph.Node(":composite-part"); !ok {
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
