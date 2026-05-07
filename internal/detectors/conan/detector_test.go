package conan

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestDetectorResolveGraphFromFixture(t *testing.T) {
	projectDir := filepath.Join("testdata", "project")
	detector := Detector{}
	result, err := detector.ResolveGraph(context.Background(), sdk.DetectionRequest{
		ProjectPath:    projectDir,
		PackageManager: sdk.PackageManagerConan,
		Ecosystem:      sdk.EcosystemCPP,
	})
	if err != nil {
		t.Fatalf("ResolveGraph returned error: %v", err)
	}
	graph := result.Graphs.Entries[0].Graph
	if graph == nil {
		t.Fatal("expected graph")
	}
	zlib, ok := graph.Package("zlib@1.2.13")
	if !ok {
		t.Fatalf("expected zlib package, got %v", graph.Packages())
	}
	if zlib.PURL != "pkg:conan/zlib@1.2.13" {
		t.Fatalf("expected zlib PURL, got %q", zlib.PURL)
	}
	cmake, ok := graph.Package("cmake@3.27.0")
	if !ok {
		t.Fatalf("expected cmake package, got %v", graph.Packages())
	}
	if cmake.Scope != string(sdk.ScopeDevelopment) {
		t.Fatalf("expected cmake development scope, got %q", cmake.Scope)
	}
}

func TestDetectorResolveGraphFromConanfilePy(t *testing.T) {
	projectDir := t.TempDir()
	raw := []byte(`from conan import ConanFile

class Demo(ConanFile):
    def requirements(self):
        self.requires("fmt/10.2.1")
`)
	if err := os.WriteFile(filepath.Join(projectDir, "conanfile.py"), raw, 0o644); err != nil {
		t.Fatalf("write conanfile.py: %v", err)
	}
	detector := Detector{}
	result, err := detector.ResolveGraph(context.Background(), sdk.DetectionRequest{
		ProjectPath:    projectDir,
		PackageManager: sdk.PackageManagerConan,
		Ecosystem:      sdk.EcosystemCPP,
	})
	if err != nil {
		t.Fatalf("ResolveGraph returned error: %v", err)
	}
	graph := result.Graphs.Entries[0].Graph
	if _, ok := graph.Package("fmt@10.2.1"); !ok {
		t.Fatalf("expected fmt package, got %v", graph.Packages())
	}
}
