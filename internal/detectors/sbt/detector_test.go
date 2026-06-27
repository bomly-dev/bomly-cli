package sbt

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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
	if detector.Ready() {
		t.Fatal("expected detector to be not ready without a usable Java runtime")
	}
	if reason := detector.ReadyReason(); !strings.Contains(reason, "Unable to locate a Java Runtime") {
		t.Fatalf("expected Java runtime reason, got %q", reason)
	}
}

func TestNativeDetectorReadyRequiresSBT(t *testing.T) {
	binDir := t.TempDir()
	writeExecutable(t, binDir, "java", successScript())
	t.Setenv("PATH", binDir)

	detector := NativeDetector{}
	if detector.Ready() {
		t.Fatal("expected detector to be not ready without sbt")
	}
	if reason := detector.ReadyReason(); !strings.Contains(reason, "sbt executable not found") {
		t.Fatalf("expected missing sbt reason, got %q", reason)
	}
}

func TestNativeDetectorReadyWithSBTAndJava(t *testing.T) {
	binDir := t.TempDir()
	writeExecutable(t, binDir, "sbt", successScript())
	writeExecutable(t, binDir, "java", successScript())
	t.Setenv("PATH", binDir)

	detector := NativeDetector{}
	if !detector.Ready() {
		t.Fatalf("expected detector to be ready, reason=%q", detector.ReadyReason())
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
