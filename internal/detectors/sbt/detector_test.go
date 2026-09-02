package sbt

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/testnodes"
	"github.com/bomly-dev/bomly-sdk"
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
	config, ok := testnodes.FindDep(graph, "com.typesafe:config@1.4.3")
	if !ok {
		t.Fatalf("expected config package, got %v", graph.DependencyNodes())
	}
	if !testnodes.Is(config, "pkg:maven/com.typesafe/config@1.4.3") {
		t.Fatalf("expected config PURL, got %q", config.NodeID())
	}
	scalatest, ok := testnodes.FindDep(graph, "org.scalatest:scalatest@3.2.18")
	if !ok {
		t.Fatalf("expected scalatest package, got %v", graph.DependencyNodes())
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

	core, ok := testnodes.FindDep(graph, "org.typelevel:cats-core_2.13@2.10.0")
	if !ok {
		t.Fatalf("expected cats-core_2.13 package, got %v", graph.DependencyNodes())
	}
	if !testnodes.Is(core, "pkg:maven/org.typelevel/cats-core_2.13@2.10.0") {
		t.Fatalf("expected suffixed Maven PURL, got %q", core.NodeID())
	}

	children, err := graph.DirectDependencies(core.NodeID())
	if err != nil {
		t.Fatalf("core dependencies: %v", err)
	}
	if len(children) != 1 || mustDep(t, children[0]).Name != "cats-kernel_2.13" {
		t.Fatalf("expected cats-kernel_2.13 child, got %#v", children)
	}
}

func TestNativeDetectorApplicable_SkipsOldSBTWithoutDependencyGraphPlugin(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "build.sbt"), []byte(`libraryDependencies += "org.mindrot" % "jbcrypt" % "0.3m"`), 0o644); err != nil {
		t.Fatalf("write build.sbt: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(projectDir, "project"), 0o755); err != nil {
		t.Fatalf("mkdir project: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "project", "build.properties"), []byte("sbt.version = 0.13.16\n"), 0o644); err != nil {
		t.Fatalf("write build.properties: %v", err)
	}

	applicable, err := (NativeDetector{WorkingDir: projectDir}).Applicable(context.Background(), sdk.DetectionRequest{ProjectPath: projectDir})
	if err != nil {
		t.Fatalf("Applicable() error = %v", err)
	}
	if applicable {
		t.Fatalf("expected old sbt project without dependency graph plugin to skip native detector")
	}
}

func TestNativeDetectorReadyRequiresJava(t *testing.T) {
	binDir := t.TempDir()
	writeExecutable(t, binDir, "sbt", successScript())
	writeExecutable(t, binDir, "java", failingJavaScript())
	t.Setenv("PATH", binDir)

	detector := NativeDetector{}
	err := detector.Ready(context.Background(), sdk.DetectionRequest{})
	if err == nil {
		t.Fatal("expected detector to be not ready without a usable Java runtime")
	}
	if !strings.Contains(err.Error(), "diagnostic bytes:") ||
		strings.Contains(err.Error(), "Unable to locate a Java Runtime") {
		t.Fatalf("expected secret-safe Java runtime reason, got %q", err)
	}
}

func TestNativeDetectorReadyRequiresSBT(t *testing.T) {
	binDir := t.TempDir()
	writeExecutable(t, binDir, "java", successScript())
	t.Setenv("PATH", binDir)

	detector := NativeDetector{}
	err := detector.Ready(context.Background(), sdk.DetectionRequest{})
	if err == nil {
		t.Fatal("expected detector to be not ready without sbt")
	}
	if !strings.Contains(err.Error(), "sbt executable not found") {
		t.Fatalf("expected missing sbt reason, got %q", err)
	}
}

func TestNativeDetectorReadyWithSBTAndJava(t *testing.T) {
	binDir := t.TempDir()
	writeExecutable(t, binDir, "sbt", successScript())
	writeExecutable(t, binDir, "java", successScript())
	t.Setenv("PATH", binDir)

	detector := NativeDetector{}
	if err := detector.Ready(context.Background(), sdk.DetectionRequest{}); err != nil {
		t.Fatalf("expected detector to be ready, got %v", err)
	}
}

func writeExecutable(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if runtime.GOOS == "windows" {
		path += ".cmd"
	}
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatalf("write executable %s: %v", name, err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o755); err != nil {
			t.Fatalf("chmod executable %s: %v", name, err)
		}
	}
	return path
}

func successScript() string {
	if runtime.GOOS == "windows" {
		return "@echo off\r\necho ok 1>&2\r\n"
	}
	return "#!/bin/sh\necho ok >&2\n"
}

func failingJavaScript() string {
	if runtime.GOOS == "windows" {
		return "@echo off\r\necho The operation couldn't be completed. Unable to locate a Java Runtime. 1>&2\r\nexit /b 1\r\n"
	}
	return "#!/bin/sh\necho \"The operation couldn't be completed. Unable to locate a Java Runtime.\" >&2\nexit 1\n"
}

func TestNativeDetectorApplicable_AllowsOldSBTWithDependencyGraphPlugin(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "build.sbt"), []byte(`libraryDependencies += "org.mindrot" % "jbcrypt" % "0.3m"`), 0o644); err != nil {
		t.Fatalf("write build.sbt: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(projectDir, "project"), 0o755); err != nil {
		t.Fatalf("mkdir project: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "project", "build.properties"), []byte("sbt.version = 0.13.16\n"), 0o644); err != nil {
		t.Fatalf("write build.properties: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "project", "plugins.sbt"), []byte(`addSbtPlugin("net.virtual-void" % "sbt-dependency-graph" % "0.9.2")`), 0o644); err != nil {
		t.Fatalf("write plugins.sbt: %v", err)
	}

	applicable, err := (NativeDetector{WorkingDir: projectDir}).Applicable(context.Background(), sdk.DetectionRequest{ProjectPath: projectDir})
	if err != nil {
		t.Fatalf("Applicable() error = %v", err)
	}
	if !applicable {
		t.Fatalf("expected old sbt project with dependency graph plugin to use native detector")
	}
}

func TestNativeDetectorApplicable_AllowsModernSBT(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "build.sbt"), []byte(`libraryDependencies += "org.mindrot" % "jbcrypt" % "0.3m"`), 0o644); err != nil {
		t.Fatalf("write build.sbt: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(projectDir, "project"), 0o755); err != nil {
		t.Fatalf("mkdir project: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "project", "build.properties"), []byte("sbt.version = 1.10.0\n"), 0o644); err != nil {
		t.Fatalf("write build.properties: %v", err)
	}

	applicable, err := (NativeDetector{WorkingDir: projectDir}).Applicable(context.Background(), sdk.DetectionRequest{ProjectPath: projectDir})
	if err != nil {
		t.Fatalf("Applicable() error = %v", err)
	}
	if !applicable {
		t.Fatalf("expected modern sbt project to use native detector")
	}
}

// mustDep narrows a graph node to the dependency node a case is asserting
// about, failing rather than panicking when the graph holds something else.
func mustDep(t testing.TB, node sdk.GraphNode) *sdk.DependencyNode {
	t.Helper()
	dep, ok := node.(*sdk.DependencyNode)
	if !ok {
		t.Fatalf("expected a dependency node, got %T", node)
	}
	return dep
}
