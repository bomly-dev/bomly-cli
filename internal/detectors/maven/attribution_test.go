package maven

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	sdk "github.com/bomly-dev/bomly-sdk"
)

// TestMavenSharedDependencyGetsOneRecordPerReactorModule is the reactor form of
// the workspace case: one artifact is a compile dependency of module-a and a
// test dependency of module-b, so the node's scope union and its single
// relationship cannot say which module contributed which. The per-site records
// can.
func TestMavenSharedDependencyGetsOneRecordPerReactorModule(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "dependency-tree-multimodule-shared.tgf"))
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
  </modules>
</project>`)
	for _, name := range []string{"module-a", "module-b"} {
		writePom(t, root, name+"/pom.xml", `<project>
  <parent><groupId>com.bomly</groupId></parent>
  <artifactId>`+name+`</artifactId>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>3.12.0</version>
    </dependency>
  </dependencies>
</project>`)
	}

	modules, err := walkPomModules(root)
	if err != nil {
		t.Fatalf("walkPomModules() error = %v", err)
	}
	entries, matched := Detector{}.reactorGraphEntries(depsGraph, modules, sdk.ManifestMetadata{Path: "pom.xml", Kind: "pom.xml"}, root)
	if matched != 2 {
		t.Fatalf("expected both reactor modules to match, got %d", matched)
	}

	detectors.Attributed(sdk.DetectionResult{Graphs: &sdk.GraphContainer{Entries: entries}})

	shared, ok := depsGraph.DependencyNode("pkg:maven/org.apache.commons/commons-lang3@3.12.0")
	if !ok || shared == nil {
		t.Fatal("expected the shared commons-lang3 node")
	}
	byRoot := map[string]sdk.PackageLocation{}
	for _, location := range shared.Locations {
		byRoot[location.ModuleRoot] = location
	}
	for _, want := range []string{"module-a", "module-b"} {
		location, ok := byRoot[want]
		if !ok {
			t.Fatalf("expected a record for reactor module %q, got %+v", want, shared.Locations)
		}
		if location.Relationship != sdk.DependencyRelationshipDirect {
			t.Fatalf("%s declares commons-lang3 in its own pom: want direct, got %q", want, location.Relationship)
		}
		if location.RealPath != want+"/pom.xml" {
			t.Fatalf("%s record points at %q, want its own pom", want, location.RealPath)
		}
		// Maven passes no per-module declarations, so the node's mixed union
		// is not this site's scope and nothing is claimed. Empty here is the
		// deliberate answer, not an oversight.
		if len(location.Scopes) != 0 {
			t.Fatalf("%s: want no site scopes while the union mixes modules, got %v", want, location.Scopes)
		}
	}
}
