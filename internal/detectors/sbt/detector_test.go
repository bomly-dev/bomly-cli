package sbt

import (
	"context"
	"path/filepath"
	"testing"

	model "github.com/bomly-dev/bomly-cli/sdk"
)

func TestDetectorResolveGraphFromFixture(t *testing.T) {
	projectDir := filepath.Join("testdata", "project")
	detector := Detector{}
	result, err := detector.ResolveGraph(context.Background(), model.DetectionRequest{
		ProjectPath:    projectDir,
		PackageManager: model.PackageManagerSBT,
		Ecosystem:      model.EcosystemScala,
	})
	if err != nil {
		t.Fatalf("ResolveGraph returned error: %v", err)
	}
	graph := result.Graphs.Entries[0].Graph
	if graph == nil {
		t.Fatal("expected graph")
	}
	config, ok := graph.Package("com.typesafe:config@1.4.3")
	if !ok {
		t.Fatalf("expected config package, got %v", graph.Packages())
	}
	if config.PURL != "pkg:maven/com.typesafe/config@1.4.3" {
		t.Fatalf("expected config PURL, got %q", config.PURL)
	}
	scalatest, ok := graph.Package("org.scalatest:scalatest@3.2.18")
	if !ok {
		t.Fatalf("expected scalatest package, got %v", graph.Packages())
	}
	if scalatest.Scope != string(model.ScopeDevelopment) {
		t.Fatalf("expected scalatest development scope, got %q", scalatest.Scope)
	}
}
