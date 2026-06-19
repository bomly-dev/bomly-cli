package gradle

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestDetectorApplicable_BuildGradleKTS(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "build.gradle.kts"), []byte("plugins {}\n"), 0o644); err != nil {
		t.Fatalf("write build.gradle.kts: %v", err)
	}

	detector := Detector{WorkingDir: projectDir}
	applicable, err := detector.Applicable(context.Background(), sdk.DetectionRequest{ProjectPath: projectDir})
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

func TestDetectorCommandSpec_MakesUnixWrapperExecutable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix-only executable-bit behavior")
	}

	projectDir := t.TempDir()
	wrapperPath := filepath.Join(projectDir, "gradlew")
	if err := os.WriteFile(wrapperPath, []byte("echo wrapper\n"), 0o644); err != nil {
		t.Fatalf("write wrapper: %v", err)
	}

	detector := Detector{WorkingDir: projectDir}
	executable, _, err := detector.commandSpec(projectDir)
	if err != nil {
		t.Fatalf("commandSpec() error = %v", err)
	}
	if executable != wrapperPath {
		t.Fatalf("expected wrapper executable, got %q", executable)
	}

	info, err := os.Stat(wrapperPath)
	if err != nil {
		t.Fatalf("stat wrapper: %v", err)
	}
	if info.Mode()&0o111 == 0 {
		t.Fatalf("expected wrapper to be executable, mode=%#o", info.Mode().Perm())
	}
}

func TestGradleScopedDependenciesArgs(t *testing.T) {
	tests := []struct {
		name   string
		scope  sdk.Scope
		want   []string
		isZero bool
	}{
		{
			name:  "runtime selects runtimeClasspath",
			scope: sdk.ScopeRuntime,
			want:  []string{"dependencies", "--console=plain", "--configuration", "runtimeClasspath"},
		},
		{
			name:  "development selects testRuntimeClasspath",
			scope: sdk.ScopeDevelopment,
			want:  []string{"dependencies", "--console=plain", "--configuration", "testRuntimeClasspath"},
		},
		{
			name:   "unknown resolves all configurations",
			scope:  sdk.ScopeUnknown,
			isZero: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := []string{"dependencies", "--console=plain"}
			got := gradleScopedDependenciesArgs(base, tt.scope)
			if tt.isZero {
				if got != nil {
					t.Fatalf("gradleScopedDependenciesArgs() = %#v, want nil", got)
				}
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("gradleScopedDependenciesArgs() = %#v, want %#v", got, tt.want)
			}
			if !reflect.DeepEqual(base, []string{"dependencies", "--console=plain"}) {
				t.Fatalf("base args mutated: %#v", base)
			}
		})
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

	rootDeps, err := g.DirectDependencies("demo")
	if err != nil {
		t.Fatalf("dependencies(root) error = %v", err)
	}
	if len(rootDeps) != 3 {
		t.Fatalf("expected 3 root deps, got %d", len(rootDeps))
	}

	guavaDeps, err := g.DirectDependencies("com.google.guava:guava@33.0.0-jre")
	if err != nil {
		t.Fatalf("dependencies(guava) error = %v", err)
	}
	if len(guavaDeps) != 2 {
		t.Fatalf("expected 2 guava deps, got %d", len(guavaDeps))
	}

	if _, ok := g.Node("org.springframework:spring-jcl@6.1.1"); !ok {
		t.Fatalf("expected transitive dependency package")
	}
	guava, _ := g.Node("com.google.guava:guava@33.0.0-jre")
	if guava.Ecosystem != "maven" || guava.Org != "com.google.guava" || guava.Name != "guava" || guava.PackageManager != "gradle" {
		t.Fatalf("unexpected gradle coordinates: %#v", guava)
	}
	if string(guava.PrimaryScope()) != string(sdk.ScopeRuntime) {
		t.Fatalf("expected runtime scope for guava, got %q", string(guava.PrimaryScope()))
	}
	junit, ok := g.Node("org.junit:junit-bom@5.10.2")
	if !ok {
		t.Fatal("expected junit package")
	}
	if string(junit.PrimaryScope()) != string(sdk.ScopeDevelopment) {
		t.Fatalf("expected development scope for junit, got %q", string(junit.PrimaryScope()))
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

	if _, ok := g.Node("org.slf4j:slf4j-api@2.0.12"); !ok {
		t.Fatalf("expected resolved version package to exist")
	}
}

func TestGradleRootName_ReadsSettingsGradle(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "settings.gradle"), []byte("rootProject.name = 'example-java-gradle'\n"), 0o644); err != nil {
		t.Fatalf("write settings.gradle: %v", err)
	}

	if got := gradleRootName(projectDir); got != "example-java-gradle" {
		t.Fatalf("gradleRootName() = %q, want example-java-gradle", got)
	}
}

func TestGradleRootName_ReadsSettingsGradleKts(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "settings.gradle.kts"), []byte("rootProject.name = \"example-kts\"\n"), 0o644); err != nil {
		t.Fatalf("write settings.gradle.kts: %v", err)
	}

	if got := gradleRootName(projectDir); got != "example-kts" {
		t.Fatalf("gradleRootName() = %q, want example-kts", got)
	}
}

func TestRunDependencies_UsesSettingsGradleRootName(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture is unix-only")
	}

	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "settings.gradle"), []byte("rootProject.name = 'example-java-gradle'\n"), 0o644); err != nil {
		t.Fatalf("write settings.gradle: %v", err)
	}
	gradlePath := filepath.Join(projectDir, "gradle-fixture")
	script := "#!/bin/sh\ncat <<'OUT'\nruntimeClasspath - Runtime classpath of source set 'main'.\n\\--- org.springframework:spring-core:6.1.1\nOUT\n"
	if err := os.WriteFile(gradlePath, []byte(script), 0o755); err != nil {
		t.Fatalf("write gradle fixture: %v", err)
	}

	g, err := (Detector{}).runDependencies(&bytes.Buffer{}, projectDir, false, gradlePath, nil)
	if err != nil {
		t.Fatalf("runDependencies() error = %v", err)
	}
	if _, ok := g.Node("example-java-gradle"); !ok {
		t.Fatalf("expected settings.gradle root node")
	}
	if _, ok := g.Node(filepath.Base(projectDir)); ok {
		t.Fatalf("did not expect temp directory root node")
	}
}
