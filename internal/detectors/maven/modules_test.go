package maven

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func writePom(t *testing.T, root, rel, content string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", rel, err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

func TestWalkPomModulesRecursive(t *testing.T) {
	root := t.TempDir()
	writePom(t, root, "pom.xml", `<project>
  <groupId>com.bomly</groupId>
  <artifactId>parent</artifactId>
  <modules>
    <module>module-a</module>
    <module>nested</module>
  </modules>
</project>`)
	writePom(t, root, "module-a/pom.xml", `<project>
  <groupId>com.bomly</groupId>
  <artifactId>module-a</artifactId>
</project>`)
	writePom(t, root, "nested/pom.xml", `<project>
  <groupId>com.bomly</groupId>
  <artifactId>nested-aggregator</artifactId>
  <modules>
    <module>module-b</module>
  </modules>
</project>`)
	writePom(t, root, "nested/module-b/pom.xml", `<project>
  <parent><groupId>com.bomly</groupId></parent>
  <artifactId>module-b</artifactId>
</project>`)

	modules, err := walkPomModules(root)
	if err != nil {
		t.Fatalf("walkPomModules() error = %v", err)
	}
	want := []mavenModule{
		{Dir: "module-a", GroupID: "com.bomly", ArtifactID: "module-a"},
		{Dir: "nested", GroupID: "com.bomly", ArtifactID: "nested-aggregator"},
		{Dir: "nested/module-b", GroupID: "com.bomly", ArtifactID: "module-b"},
	}
	if len(modules) != len(want) {
		t.Fatalf("expected %d modules, got %#v", len(want), modules)
	}
	for i := range want {
		if modules[i] != want[i] {
			t.Fatalf("module %d = %#v, want %#v", i, modules[i], want[i])
		}
	}
}

func TestWalkPomModulesCycleSafe(t *testing.T) {
	root := t.TempDir()
	writePom(t, root, "pom.xml", `<project>
  <groupId>com.bomly</groupId>
  <artifactId>parent</artifactId>
  <modules>
    <module>child</module>
  </modules>
</project>`)
	// child points back at the root — the visited set must break the cycle.
	writePom(t, root, "child/pom.xml", `<project>
  <groupId>com.bomly</groupId>
  <artifactId>child</artifactId>
  <modules>
    <module>..</module>
  </modules>
</project>`)

	modules, err := walkPomModules(root)
	if err != nil {
		t.Fatalf("walkPomModules() error = %v", err)
	}
	if len(modules) != 1 || modules[0].ArtifactID != "child" {
		t.Fatalf("expected only the child module, got %#v", modules)
	}
}

func TestMavenPerModuleEntriesFromTGF(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "dependency-tree-multimodule.tgf"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	depsGraph, err := depGraphFromMavenTGF(raw)
	if err != nil {
		t.Fatalf("depGraphFromMavenTGF() error = %v", err)
	}

	root := t.TempDir()
	writePom(t, root, "pom.xml", `<project>
  <groupId>com.bomly</groupId>
  <artifactId>reactor</artifactId>
  <modules>
    <module>module-a</module>
    <module>module-b</module>
    <module>module-c</module>
  </modules>
</project>`)
	for _, name := range []string{"module-a", "module-b", "module-c"} {
		writePom(t, root, name+"/pom.xml", `<project>
  <parent><groupId>com.bomly</groupId></parent>
  <artifactId>`+name+`</artifactId>
</project>`)
	}

	modules, err := walkPomModules(root)
	if err != nil {
		t.Fatalf("walkPomModules() error = %v", err)
	}
	entries, matched := Detector{}.reactorGraphEntries(depsGraph, modules, sdk.ManifestMetadata{Path: "pom.xml", Kind: "pom.xml"}, root)
	if matched != 3 {
		t.Fatalf("expected 3 matched modules, got %d", matched)
	}
	// The fixture has no aggregator node of its own, so entries are the
	// three module entries only.
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	byPath := map[string]sdk.GraphEntry{}
	for _, entry := range entries {
		byPath[entry.Manifest.Path] = entry
	}
	a, ok := byPath["module-a/pom.xml"]
	if !ok {
		t.Fatalf("expected module-a entry, got %v", byPath)
	}
	if _, ok := a.Graph.Node("com.bomly:module-a@1.0.0"); !ok {
		names := []string{}
		for _, pkg := range a.Graph.Nodes() {
			names = append(names, pkg.ID)
		}
		t.Fatalf("expected module-a root in its entry, got %v", names)
	}
	if a.Graph.Size() != 2 {
		t.Fatalf("expected module-a root + 1 dep, got %d nodes", a.Graph.Size())
	}
	b := byPath["module-b/pom.xml"]
	if b.Graph.Size() != 3 {
		t.Fatalf("expected module-b root + 2 deps, got %d nodes", b.Graph.Size())
	}
}

func TestMavenUnmatchedTGFRootsFallBackToRootEntry(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "dependency-tree-multimodule.tgf"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	depsGraph, err := depGraphFromMavenTGF(raw)
	if err != nil {
		t.Fatalf("depGraphFromMavenTGF() error = %v", err)
	}

	root := t.TempDir()
	// Only module-a is declared; module-b and module-c blocks stay in the
	// root entry.
	writePom(t, root, "pom.xml", `<project>
  <groupId>com.bomly</groupId>
  <artifactId>reactor</artifactId>
  <modules><module>module-a</module></modules>
</project>`)
	writePom(t, root, "module-a/pom.xml", `<project>
  <parent><groupId>com.bomly</groupId></parent>
  <artifactId>module-a</artifactId>
</project>`)

	modules, err := walkPomModules(root)
	if err != nil {
		t.Fatalf("walkPomModules() error = %v", err)
	}
	entries, matched := Detector{}.reactorGraphEntries(depsGraph, modules, sdk.ManifestMetadata{Path: "pom.xml", Kind: "pom.xml"}, root)
	if matched != 1 {
		t.Fatalf("expected 1 matched module, got %d", matched)
	}
	if len(entries) != 2 {
		t.Fatalf("expected root entry + module-a entry, got %d", len(entries))
	}
	rootEntry := entries[0]
	if rootEntry.Manifest.Path != "pom.xml" {
		t.Fatalf("expected first entry to be the root manifest, got %q", rootEntry.Manifest.Path)
	}
	for _, want := range []string{"com.bomly:module-b@1.0.0", "com.bomly:module-c@1.0.0"} {
		if _, ok := rootEntry.Graph.Node(want); !ok {
			t.Fatalf("expected unmatched module root %q in the root entry", want)
		}
	}
	if _, ok := rootEntry.Graph.Node("com.bomly:module-a@1.0.0"); ok {
		t.Fatal("matched module must not stay in the root entry")
	}
}

func TestMavenSingleModuleNoPomModulesKeepsSingleEntry(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "dependency-tree.tgf"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	depsGraph, err := depGraphFromMavenTGF(raw)
	if err != nil {
		t.Fatalf("depGraphFromMavenTGF() error = %v", err)
	}
	root := t.TempDir()
	writePom(t, root, "pom.xml", `<project>
  <groupId>com.bomly</groupId>
  <artifactId>app</artifactId>
</project>`)
	modules, err := walkPomModules(root)
	if err != nil {
		t.Fatalf("walkPomModules() error = %v", err)
	}
	if len(modules) != 0 {
		t.Fatalf("expected no modules for a single-module pom, got %#v", modules)
	}
	// With no modules ResolveGraph keeps the single-entry path; assert the
	// partitioning helper is a no-op here too.
	entries, matched := Detector{}.reactorGraphEntries(depsGraph, modules, sdk.ManifestMetadata{Path: "pom.xml", Kind: "pom.xml"}, root)
	if matched != 0 || entries != nil {
		t.Fatalf("expected no partitioning without modules, got %d entries (matched %d)", len(entries), matched)
	}
}
