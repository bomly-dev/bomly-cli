package sbt

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestDetectorResolveGraphFromFixture(t *testing.T) {
	projectDir := filepath.Join("testdata", "project")
	detector := Detector{}
	result, err := detector.ResolveGraph(context.Background(), sdk.DetectionRequest{
		ProjectPath:    projectDir,
		PackageManager: sdk.PackageManagerSBT,
		Ecosystem:      sdk.EcosystemScala,
	})
	if err != nil {
		t.Fatalf("ResolveGraph returned error: %v", err)
	}
	graph := result.Graphs.Entries[0].Graph
	if graph == nil {
		t.Fatal("expected graph")
	}
	config, ok := graph.Node("com.typesafe:config@1.4.3")
	if !ok {
		t.Fatalf("expected config package, got %v", graph.Nodes())
	}
	if config.PURL != "pkg:maven/com.typesafe/config@1.4.3" {
		t.Fatalf("expected config PURL, got %q", config.PURL)
	}
	scalatest, ok := graph.Node("org.scalatest:scalatest@3.2.18")
	if !ok {
		t.Fatalf("expected scalatest package, got %v", graph.Nodes())
	}
	if string(scalatest.PrimaryScope()) != string(sdk.ScopeDevelopment) {
		t.Fatalf("expected scalatest development scope, got %q", string(scalatest.PrimaryScope()))
	}
}

func TestDepGraphFromSBTDependencyTreePreservesScalaArtifactSuffix(t *testing.T) {
	raw := []byte(`[info] +-org.typelevel:cats-core_2.13:2.10.0 [S]
[info]   +-org.typelevel:cats-kernel_2.13:2.10.0 [S]
`)
	graph, err := depGraphFromSBTDependencyTree(raw)
	if err != nil {
		t.Fatalf("depGraphFromSBTDependencyTree returned error: %v", err)
	}

	core, ok := graph.Node("org.typelevel:cats-core_2.13@2.10.0")
	if !ok {
		t.Fatalf("expected cats-core_2.13 package, got %v", graph.Nodes())
	}
	if core.PURL != "pkg:maven/org.typelevel/cats-core_2.13@2.10.0" {
		t.Fatalf("expected suffixed Maven PURL, got %q", core.PURL)
	}

	children, err := graph.DirectDependencies(core.ID)
	if err != nil {
		t.Fatalf("core dependencies: %v", err)
	}
	if len(children) != 1 || children[0].Name != "cats-kernel_2.13" {
		t.Fatalf("expected cats-kernel_2.13 child, got %#v", children)
	}
}
