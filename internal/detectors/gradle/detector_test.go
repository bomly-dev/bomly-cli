package gradle

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
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
	executable, _, err := detector.commandSpec(projectDir, nil)
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
	executable, _, err := detector.commandSpec(projectDir, nil)
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

func TestDetectorReadyRequiresJava(t *testing.T) {
	binDir := t.TempDir()
	writeExecutable(t, binDir, "gradle", successScript())
	writeExecutable(t, binDir, "java", failingJavaScript())
	t.Setenv("PATH", binDir)

	detector := Detector{}
	err := detector.Ready(context.Background(), sdk.DetectionRequest{})
	if err == nil {
		t.Fatal("expected detector to be not ready without a usable Java runtime")
	}
	if !strings.Contains(err.Error(), "Unable to locate a Java Runtime") {
		t.Fatalf("expected Java runtime reason, got %q", err)
	}
}

func TestDetectorReadyRequiresGradleRunner(t *testing.T) {
	binDir := t.TempDir()
	writeExecutable(t, binDir, "java", successScript())
	t.Setenv("PATH", binDir)

	detector := Detector{}
	err := detector.Ready(context.Background(), sdk.DetectionRequest{})
	if err == nil {
		t.Fatal("expected detector to be not ready without gradle")
	}
	if !strings.Contains(err.Error(), "gradle executable not found") {
		t.Fatalf("expected missing gradle reason, got %q", err)
	}
}

func TestDetectorReadyWithWrapperAndJava(t *testing.T) {
	projectDir := t.TempDir()
	binDir := t.TempDir()
	writeExecutable(t, projectDir, "gradlew", successScript())
	writeExecutable(t, binDir, "java", successScript())
	t.Setenv("PATH", binDir)

	detector := Detector{}
	if err := detector.Ready(context.Background(), sdk.DetectionRequest{ProjectPath: projectDir}); err != nil {
		t.Fatalf("expected detector to be ready, got %v", err)
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

	parsed, err := depGraphFromGradleOutput(raw, "demo", nil)
	if err != nil {
		t.Fatalf("depGraphFromGradleOutput() error = %v", err)
	}
	g := parsed.rootGraph

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

	parsed, err := depGraphFromGradleOutput(raw, "demo", nil)
	if err != nil {
		t.Fatalf("depGraphFromGradleOutput() error = %v", err)
	}

	if _, ok := parsed.rootGraph.Node("org.slf4j:slf4j-api@2.0.12"); !ok {
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

	parsed, err := (Detector{}).runDependencies(context.Background(), &bytes.Buffer{}, projectDir, false, gradlePath, nil, nil)
	if err != nil {
		t.Fatalf("runDependencies() error = %v", err)
	}
	if _, ok := parsed.rootGraph.Node("example-java-gradle"); !ok {
		t.Fatalf("expected settings.gradle root node")
	}
	if _, ok := parsed.rootGraph.Node(filepath.Base(projectDir)); ok {
		t.Fatalf("did not expect temp directory root node")
	}
}

func TestResolveGraphMultiProjectEmitsPerModuleEntries(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture is unix-only")
	}

	projectDir := t.TempDir()
	writeGradleFile(t, projectDir, "settings.gradle", "rootProject.name = 'demo'\ninclude(\":app\", \":lib\")\n")
	writeGradleFile(t, projectDir, "build.gradle", "group = \"com.acme\"\n")
	writeGradleFile(t, projectDir, "app/build.gradle", "dependencies {}\n")
	writeGradleFile(t, projectDir, "lib/build.gradle", "dependencies {}\n")

	fixture, err := os.ReadFile(filepath.Join("testdata", "dependencies-multiproject.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	argsFile := filepath.Join(projectDir, "gradle-args.txt")
	script := "#!/bin/sh\necho \"$@\" > " + argsFile + "\ncat <<'FIXTURE_EOF'\n" + string(fixture) + "FIXTURE_EOF\n"
	if err := os.WriteFile(filepath.Join(projectDir, "gradlew"), []byte(script), 0o755); err != nil {
		t.Fatalf("write gradlew fixture: %v", err)
	}

	result, err := (Detector{}).ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: projectDir})
	if err != nil {
		t.Fatalf("ResolveGraph() error = %v", err)
	}

	recordedArgs, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("read recorded args: %v", err)
	}
	for _, want := range []string{"dependencies", ":app:dependencies", ":lib:dependencies", "--console=plain"} {
		if !strings.Contains(string(recordedArgs), want) {
			t.Fatalf("expected gradle args to contain %q, got %q", want, string(recordedArgs))
		}
	}

	entries := result.Graphs.Entries
	if len(entries) != 3 {
		t.Fatalf("expected root + 2 subproject entries, got %d", len(entries))
	}
	paths := []string{entries[1].Manifest.Path, entries[2].Manifest.Path}
	if !reflect.DeepEqual(paths, []string{"app/build.gradle", "lib/build.gradle"}) {
		t.Fatalf("module manifest paths = %v", paths)
	}
	if entries[1].Manifest.Kind != sdk.ManifestKind("build.gradle") {
		t.Fatalf("module manifest kind = %q", entries[1].Manifest.Kind)
	}

	// Root entry: root project node + its own dependency only.
	if _, ok := entries[0].Graph.Node("org.apache.commons:commons-lang3@3.14.0"); !ok {
		t.Fatal("root entry must contain the root project's own dependency")
	}
	if _, ok := entries[0].Graph.Node("com.google.guava:guava@33.0.0-jre"); ok {
		t.Fatal("root entry must not absorb subproject dependencies")
	}

	// app entry: its deps plus the lib subtree through the project edge.
	appGraph := entries[1].Graph
	for _, want := range []string{"com.google.guava:guava@33.0.0-jre", "org.slf4j:slf4j-api@2.0.12"} {
		if _, ok := appGraph.Node(want); !ok {
			t.Fatalf("app entry missing %s", want)
		}
	}

	// lib entry: rooted at an application-typed node with only its own dep.
	libGraph := entries[2].Graph
	if _, ok := libGraph.Node("com.google.guava:guava@33.0.0-jre"); ok {
		t.Fatal("lib entry must not contain app dependencies")
	}
	libRoots := libGraph.Roots()
	if len(libRoots) != 1 || libRoots[0].Type != sdk.PackageTypeApplication || libRoots[0].Name != "lib" {
		t.Fatalf("unexpected lib entry root: %#v", libRoots)
	}
}

// TestResolveGraphSingleProjectStillSingleEntry pins the regression contract:
// a build without subprojects keeps exactly one graph entry.
func TestResolveGraphSingleProjectStillSingleEntry(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture is unix-only")
	}

	projectDir := t.TempDir()
	writeGradleFile(t, projectDir, "settings.gradle", "rootProject.name = 'demo'\n")
	writeGradleFile(t, projectDir, "build.gradle", "dependencies {}\n")
	script := "#!/bin/sh\ncat <<'OUT'\nruntimeClasspath - Runtime classpath of source set 'main'.\n\\--- org.springframework:spring-core:6.1.1\nOUT\n"
	if err := os.WriteFile(filepath.Join(projectDir, "gradlew"), []byte(script), 0o755); err != nil {
		t.Fatalf("write gradlew fixture: %v", err)
	}

	result, err := (Detector{}).ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: projectDir})
	if err != nil {
		t.Fatalf("ResolveGraph() error = %v", err)
	}
	if len(result.Graphs.Entries) != 1 {
		t.Fatalf("expected a single graph entry, got %d", len(result.Graphs.Entries))
	}
}

// TestResolveGraphMultiTaskFailureRetriesRootOnly pins the degrade path: when
// the multi-task invocation fails (e.g. stale settings naming a removed
// subproject), the detector retries the root-only report.
func TestResolveGraphMultiTaskFailureRetriesRootOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture is unix-only")
	}

	projectDir := t.TempDir()
	writeGradleFile(t, projectDir, "settings.gradle", "rootProject.name = 'demo'\ninclude(\":gone\")\n")
	writeGradleFile(t, projectDir, "build.gradle", "dependencies {}\n")
	writeGradleFile(t, projectDir, "gone/build.gradle", "")
	script := `#!/bin/sh
case "$@" in
*:gone:dependencies*) echo "Project 'gone' not found" >&2; exit 1 ;;
esac
cat <<'OUT'
runtimeClasspath - Runtime classpath of source set 'main'.
\--- org.springframework:spring-core:6.1.1
OUT
`
	if err := os.WriteFile(filepath.Join(projectDir, "gradlew"), []byte(script), 0o755); err != nil {
		t.Fatalf("write gradlew fixture: %v", err)
	}

	result, err := (Detector{}).ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: projectDir})
	if err != nil {
		t.Fatalf("ResolveGraph() error = %v", err)
	}
	if len(result.Graphs.Entries) != 1 {
		t.Fatalf("expected root-only fallback single entry, got %d", len(result.Graphs.Entries))
	}
	if _, ok := result.Graphs.Entries[0].Graph.Node("org.springframework:spring-core@6.1.1"); !ok {
		t.Fatal("expected root-only graph from the fallback run")
	}
}

// TestResolveGraphMultiTaskFailureFallbackKeepsScope pins the review finding:
// when the multi-project invocation fails and the detector degrades to the
// root project, a --scope runtime scan must retry with the scoped
// --configuration arguments, never a silently unscoped report.
func TestResolveGraphMultiTaskFailureFallbackKeepsScope(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture is unix-only")
	}

	projectDir := t.TempDir()
	writeGradleFile(t, projectDir, "settings.gradle", "rootProject.name = 'demo'\ninclude(\":gone\")\n")
	writeGradleFile(t, projectDir, "build.gradle", "dependencies {}\n")
	writeGradleFile(t, projectDir, "gone/build.gradle", "")
	argsLog := filepath.Join(projectDir, "gradle-args.log")
	script := `#!/bin/sh
echo "$@" >> ` + argsLog + `
case "$@" in
*:gone:dependencies*) echo "Project 'gone' not found" >&2; exit 1 ;;
esac
cat <<'OUT'
runtimeClasspath - Runtime classpath of source set 'main'.
\--- org.springframework:spring-core:6.1.1
OUT
`
	if err := os.WriteFile(filepath.Join(projectDir, "gradlew"), []byte(script), 0o755); err != nil {
		t.Fatalf("write gradlew fixture: %v", err)
	}

	result, err := (Detector{}).ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: projectDir, ScopeFilter: sdk.ScopeRuntime})
	if err != nil {
		t.Fatalf("ResolveGraph() error = %v", err)
	}
	if len(result.Graphs.Entries) != 1 {
		t.Fatalf("expected root-only fallback single entry, got %d", len(result.Graphs.Entries))
	}

	recorded, err := os.ReadFile(argsLog)
	if err != nil {
		t.Fatalf("read recorded args: %v", err)
	}
	invocations := strings.Split(strings.TrimSpace(string(recorded)), "\n")
	last := invocations[len(invocations)-1]
	if strings.Contains(last, ":gone:dependencies") {
		t.Fatalf("fallback invocation still targets the failing subproject: %q", last)
	}
	if !strings.Contains(last, "--configuration runtimeClasspath") {
		t.Fatalf("root-only fallback dropped the requested scope, last invocation: %q", last)
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
