package bun

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestDepGraphFromBunLockfile(t *testing.T) {
	project := t.TempDir()
	lockfile := `{
		// Bun text lockfiles are JSONC.
		"lockfileVersion": 1,
		"workspaces": {
			"": {"name":"root-app","dependencies":{"alias":"npm:real-package@^2.0.0","local":"workspace:*"},"devDependencies":{"tool":"^1.0.0"},},
			"packages/local": {"name":"local","version":"1.0.0","dependencies":{"real-package":"2.1.0"},},
		},
		"packages": {
			"alias": ["real-package@2.1.0", "https://registry.example.test/real-package.tgz", {"dependencies":{"child":"1.0.0"}}, "sha512-abc"],
			"child": ["child@1.0.0", "", {"dependencies":{"tool":"2.0.0"}}, "sha512-def"],
			"tool": ["tool@1.2.0", "", {"optionalDependencies":{"child":"1.0.0"}}, ""],
			"tool@2.0.0": ["tool@2.0.0", "", {}, ""],
		},
	}`
	if err := os.WriteFile(filepath.Join(project, "bun.lock"), []byte(lockfile), 0o600); err != nil {
		t.Fatal(err)
	}

	graphs, err := depGraphFromBunLockfile(project)
	if err != nil {
		t.Fatalf("parse Bun lockfile: %v", err)
	}
	if len(graphs.modules) != 1 {
		t.Fatalf("expected one workspace module, got %d", len(graphs.modules))
	}
	realPackage := dependencyByNameVersion(graphs.graph, "real-package", "2.1.0")
	if realPackage == nil || realPackage.Source != sdk.DependencySourceRegistry {
		t.Fatalf("expected mirrored registry package, got %#v", realPackage)
	}
	if len(realPackage.Digests) != 1 || realPackage.Digests[0].Value != "abc" {
		t.Fatalf("expected tuple integrity metadata, got %#v", realPackage.Digests)
	}
	root, _ := graphs.graph.Node(graphs.rootID)
	assertEdge(t, graphs.graph, root, realPackage)
	workspace, _ := graphs.graph.Node(graphs.modules[0].rootID)
	assertEdge(t, graphs.graph, root, workspace)
	assertEdge(t, graphs.graph, workspace, realPackage)
	tool := dependencyByNameVersion(graphs.graph, "tool", "1.2.0")
	if tool == nil || tool.PrimaryScope() != sdk.ScopeDevelopment {
		t.Fatalf("expected exact dev dependency version and scope, got %#v", tool)
	}
	assertEdge(t, graphs.graph, realPackage, dependencyByNameVersion(graphs.graph, "child", "1.0.0"))
	assertEdge(t, graphs.graph, dependencyByNameVersion(graphs.graph, "child", "1.0.0"), dependencyByNameVersion(graphs.graph, "tool", "2.0.0"))
}

func TestNormalizeJSONCPreservesStringContents(t *testing.T) {
	input := []byte(`{"url":"https://example.test/a/*literal*/",/* remove */"text":"comma,}",}`)
	got, err := normalizeJSONC(input)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"url":"https://example.test/a/*literal*/","text":"comma,}"}`
	if string(got) != want {
		t.Fatalf("normalized JSONC = %s, want %s", got, want)
	}
}

func TestDepGraphFromBunLockfileRejectsUnsupportedVersion(t *testing.T) {
	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, "bun.lock"), []byte(`{"lockfileVersion":2,"packages":{"x":["x@1.0.0"]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := depGraphFromBunLockfile(project); err == nil {
		t.Fatal("expected unsupported lockfile version error")
	}
}

func FuzzNormalizeJSONC(f *testing.F) {
	f.Add([]byte(`{"lockfileVersion":1,"packages":{},}`))
	f.Add([]byte(`{"url":"https://example.test/a//b","value":"/* literal */"}`))
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = normalizeJSONC(input)
	})
}

func dependencyByNameVersion(graph *sdk.Graph, name, version string) *sdk.Dependency {
	var found *sdk.Dependency
	graph.WalkNodes(func(dep *sdk.Dependency) bool {
		if dep.Name == name && dep.Version == version {
			found = dep
			return false
		}
		return true
	})
	return found
}

func assertEdge(t *testing.T, graph *sdk.Graph, from, to *sdk.Dependency) {
	t.Helper()
	if from == nil || to == nil {
		t.Fatalf("edge endpoint is nil: from=%#v to=%#v", from, to)
	}
	children, err := graph.DirectDependencies(from.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, child := range children {
		if child.ID == to.ID {
			return
		}
	}
	t.Fatalf("expected edge %s -> %s", from.ID, to.ID)
}
