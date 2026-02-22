package gradle

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/bomly/bomly-cli/internal/detectors"
)

func TestDetectorApplicable_BuildGradleKTS(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "build.gradle.kts"), []byte("plugins {}\n"), 0o644); err != nil {
		t.Fatalf("write build.gradle.kts: %v", err)
	}

	detector := Detector{WorkingDir: projectDir}
	applicable, err := detector.Applicable(context.Background(), detectors.ResolveGraphRequest{ProjectPath: projectDir})
	if err != nil {
		t.Fatalf("Applicable() error = %v", err)
	}
	if !applicable {
		t.Fatalf("expected detector to be applicable")
	}
}

func TestDetectorCommandSpec_PrefersWrapper(t *testing.T) {
	projectDir := t.TempDir()
	wrapperName := "gradlew"
	if runtime.GOOS == "windows" {
		wrapperName = "gradlew.bat"
	}
	if err := os.WriteFile(filepath.Join(projectDir, wrapperName), []byte("echo wrapper\n"), 0o755); err != nil {
		t.Fatalf("write wrapper: %v", err)
	}

	detector := Detector{WorkingDir: projectDir}
	executable, _, err := detector.commandSpec(projectDir)
	if err != nil {
		t.Fatalf("commandSpec() error = %v", err)
	}

	if runtime.GOOS == "windows" {
		if executable != "cmd" {
			t.Fatalf("expected cmd wrapper execution, got %q", executable)
		}
		return
	}

	if executable != filepath.Join(projectDir, "gradlew") {
		t.Fatalf("expected wrapper executable, got %q", executable)
	}
}

func TestDepGraphFromGradleOutput(t *testing.T) {
	raw := []byte(`runtimeClasspath - Runtime classpath of source set 'main'.
+--- org.springframework:spring-core:6.1.1
|    \--- org.springframework:spring-jcl:6.1.1
\--- com.google.guava:guava:33.0.0-jre
     +--- com.google.guava:failureaccess:1.0.2
     \--- org.checkerframework:checker-qual:3.41.0

testRuntimeClasspath - Test runtime classpath of source set 'test'.
\--- org.junit:junit-bom:5.10.2
`)

	g, err := depGraphFromGradleOutput(raw, "demo")
	if err != nil {
		t.Fatalf("depGraphFromGradleOutput() error = %v", err)
	}

	if g.Size() != 7 {
		t.Fatalf("expected 7 packages, got %d", g.Size())
	}

	rootDeps, err := g.Dependencies("demo")
	if err != nil {
		t.Fatalf("dependencies(root) error = %v", err)
	}
	if len(rootDeps) != 3 {
		t.Fatalf("expected 3 root deps, got %d", len(rootDeps))
	}

	guavaDeps, err := g.Dependencies("com.google.guava:guava@33.0.0-jre")
	if err != nil {
		t.Fatalf("dependencies(guava) error = %v", err)
	}
	if len(guavaDeps) != 2 {
		t.Fatalf("expected 2 guava deps, got %d", len(guavaDeps))
	}

	if _, ok := g.Package("org.springframework:spring-jcl@6.1.1"); !ok {
		t.Fatalf("expected transitive dependency package")
	}
	guava, _ := g.Package("com.google.guava:guava@33.0.0-jre")
	if guava.Ecosystem != "maven" || guava.Org != "com.google.guava" || guava.Name != "guava" || guava.BuildSystem != "gradle" {
		t.Fatalf("unexpected gradle coordinates: %#v", guava)
	}
	if guava.Scope != string(detectors.ScopeRuntime) {
		t.Fatalf("expected runtime scope for guava, got %q", guava.Scope)
	}
	junit, ok := g.Package("org.junit:junit-bom@5.10.2")
	if !ok {
		t.Fatal("expected junit package")
	}
	if junit.Scope != string(detectors.ScopeDevelopment) {
		t.Fatalf("expected development scope for junit, got %q", junit.Scope)
	}
}

func TestDepGraphFromGradleOutput_UsesResolvedVersion(t *testing.T) {
	raw := []byte(`runtimeClasspath - Runtime classpath of source set 'main'.
\--- org.slf4j:slf4j-api:1.7.30 -> 2.0.12
`)

	g, err := depGraphFromGradleOutput(raw, "demo")
	if err != nil {
		t.Fatalf("depGraphFromGradleOutput() error = %v", err)
	}

	if _, ok := g.Package("org.slf4j:slf4j-api@2.0.12"); !ok {
		t.Fatalf("expected resolved version package to exist")
	}
}
