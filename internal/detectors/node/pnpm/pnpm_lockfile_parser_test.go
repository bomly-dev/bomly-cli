package pnpm

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func writePNPMProject(t *testing.T, lockfile, manifest string) string {
	t.Helper()
	dir := t.TempDir()
	if manifest == "" {
		manifest = `{"name":"demo","version":"1.0.0"}`
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), []byte(lockfile), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestPNPMLockfileSelectsProjectDocument(t *testing.T) {
	dir := writePNPMProject(t, `lockfileVersion: '9.0'
packages:
  ignored@1.0.0: {}
---
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      selected:
        version: 2.0.0
packages:
  selected@2.0.0: {}
snapshots:
  selected@2.0.0: {}
`, "")
	graphs, err := depGraphFromPNPMLockfile(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := graphs.graph.Node("selected@2.0.0"); !ok {
		t.Fatal("expected package from project document")
	}
	if _, ok := graphs.graph.Node("ignored@1.0.0"); ok {
		t.Fatal("must not merge an unrelated YAML document")
	}
}

func TestPNPMLockfileParsesLegacyScopedPeerKey(t *testing.T) {
	dir := writePNPMProject(t, `lockfileVersion: 5.4
dependencies:
  '@scope/pkg': 1.2.3
packages:
  /@scope/pkg/1.2.3_peer@2.0.0: {}
`, "")
	graphs, err := depGraphFromPNPMLockfile(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := graphs.graph.Node("@scope/pkg@1.2.3"); !ok {
		t.Fatalf("nodes = %#v", graphs.graph.Nodes())
	}
}

func TestPNPMLockfileVersion6ImporterObjectAndAlias(t *testing.T) {
	dir := writePNPMProject(t, `lockfileVersion: '6.0'
importers:
  .:
    dependencies:
      local-alias:
        specifier: npm:real-package@1.2.3
        version: npm:real-package@1.2.3
packages:
  /real-package@1.2.3: {}
`, "")
	graphs, err := depGraphFromPNPMLockfile(dir)
	if err != nil {
		t.Fatal(err)
	}
	root, ok := graphs.graph.Node(graphs.rootID)
	if !ok {
		t.Fatal("root missing")
	}
	dependencies, err := graphs.graph.DirectDependencies(root.ID)
	if err != nil || len(dependencies) != 1 || dependencies[0].Name != "real-package" {
		t.Fatalf("dependencies = %#v, err=%v", dependencies, err)
	}
}

func TestPNPMLockfileSeparatesWorkspaceAndPackageWithSameName(t *testing.T) {
	dir := writePNPMProject(t, `lockfileVersion: '9.0'
importers:
  .: {}
  packages/cloudflare:
    dependencies:
      cloudflare:
        version: 4.0.0
packages:
  cloudflare@4.0.0: {}
snapshots:
  cloudflare@4.0.0: {}
`, `{"name":"root","version":"1.0.0"}`)
	memberDir := filepath.Join(dir, "packages", "cloudflare")
	if err := os.MkdirAll(memberDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(memberDir, "package.json"), []byte(`{"name":"cloudflare","version":"4.0.0"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := LockfileDetector{}.ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: dir})
	if err != nil {
		t.Fatalf("ResolveGraph() error = %v", err)
	}
	if len(result.Graphs.Entries) != 2 {
		t.Fatalf("entries = %d", len(result.Graphs.Entries))
	}
	member := result.Graphs.Entries[1].Graph
	if _, ok := member.Node("workspace:packages/cloudflare"); !ok {
		t.Fatalf("workspace node missing: %#v", member.Nodes())
	}
	if _, ok := member.Node("cloudflare@4.0.0"); !ok {
		t.Fatal("registry package with the same name missing")
	}
}

func TestPNPMLockfileClassifiesLinkPackage(t *testing.T) {
	dir := writePNPMProject(t, `lockfileVersion: '9.0'
importers:
  .: {}
packages:
  '@example/local@link:packages/local': {}
snapshots:
  '@example/local@link:packages/local': {}
`, "")
	graphs, err := depGraphFromPNPMLockfile(dir)
	if err != nil {
		t.Fatal(err)
	}
	dependency, ok := graphs.graph.Node("@example/local@packages/local")
	if !ok || dependency.Source != sdk.DependencySourceWorkspace {
		t.Fatalf("dependency = %#v", dependency)
	}
}
