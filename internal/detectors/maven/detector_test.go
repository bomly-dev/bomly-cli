package maven

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestDepGraphFromMavenTGF(t *testing.T) {
	raw := []byte(`1 com.example:demo-app:jar:1.0.0
2 ch.qos.logback:logback-classic:jar:1.5.6:compile
3 ch.qos.logback:logback-core:jar:1.5.6:compile
4 org.slf4j:slf4j-api:jar:2.0.13:compile
#
1 2 compile
2 3 compile
2 4 compile
`)

	g, err := depGraphFromMavenTGF(raw)
	if err != nil {
		t.Fatalf("depGraphFromMavenTGF() error = %v", err)
	}

	if g.Size() != 4 {
		t.Fatalf("expected 4 packages, got %d", g.Size())
	}

	rootDeps, err := g.DirectDependencies("com.example:demo-app@1.0.0")
	if err != nil {
		t.Fatalf("dependencies(root) error = %v", err)
	}
	if len(rootDeps) != 1 || rootDeps[0].ID != "ch.qos.logback:logback-classic@1.5.6" {
		t.Fatalf("unexpected root deps: %#v", rootDeps)
	}

	logbackDeps, err := g.DirectDependencies("ch.qos.logback:logback-classic@1.5.6")
	if err != nil {
		t.Fatalf("dependencies(logback-classic) error = %v", err)
	}
	if len(logbackDeps) != 2 {
		t.Fatalf("expected 2 transitive deps, got %d", len(logbackDeps))
	}
	if logbackDeps[0].ID != "ch.qos.logback:logback-core@1.5.6" || logbackDeps[1].ID != "org.slf4j:slf4j-api@2.0.13" {
		t.Fatalf("unexpected logback deps: %#v", logbackDeps)
	}
}

func TestDepGraphFromMavenTGF_WithMavenLogPrefixes(t *testing.T) {
	raw := []byte(`Found "C:\\Users\\ahmed\\repos\\examples\\example-java-maven\\.mvn\\wrapper\\maven-wrapper.jar"
[INFO] Scanning for projects...
[INFO]
[INFO] --- maven-dependency-plugin:2.8:tree (default-cli) @ example-java-maven ---
[INFO] 319144230 com.srcclr:example-java-maven:jar:1.0-SNAPSHOT
[INFO] 1268237485 org.apache.struts:struts2-core:jar:2.5.12:compile
[INFO] 1983948209 org.freemarker:freemarker:jar:2.3.23:compile
[INFO] 1778257620 org.mindrot:jbcrypt:jar:0.3m:compile
[INFO] #
[INFO] 1268237485 1983948209 compile
[INFO] 319144230 1268237485 compile
[INFO] 319144230 1778257620 compile
[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
`)

	g, err := depGraphFromMavenTGF(raw)
	if err != nil {
		t.Fatalf("depGraphFromMavenTGF() error = %v", err)
	}

	if g.Size() != 4 {
		t.Fatalf("expected 4 packages, got %d", g.Size())
	}

	rootDeps, err := g.DirectDependencies("com.srcclr:example-java-maven@1.0-SNAPSHOT")
	if err != nil {
		t.Fatalf("dependencies(root) error = %v", err)
	}
	if len(rootDeps) != 2 {
		t.Fatalf("expected 2 root deps, got %d", len(rootDeps))
	}
	if rootDeps[0].ID != "org.apache.struts:struts2-core@2.5.12" || rootDeps[1].ID != "org.mindrot:jbcrypt@0.3m" {
		t.Fatalf("unexpected root deps: %#v", rootDeps)
	}

	strutsDeps, err := g.DirectDependencies("org.apache.struts:struts2-core@2.5.12")
	if err != nil {
		t.Fatalf("dependencies(struts2-core) error = %v", err)
	}
	if len(strutsDeps) != 1 || strutsDeps[0].ID != "org.freemarker:freemarker@2.3.23" {
		t.Fatalf("unexpected struts deps: %#v", strutsDeps)
	}
}

func TestNodeFromMavenCoords_WithClassifier(t *testing.T) {
	node, err := nodeFromMavenCoords("com.example:demo-artifact:jar:sources:1.0.0:test")
	if err != nil {
		t.Fatalf("nodeFromMavenCoords() error = %v", err)
	}
	if node.Name != "demo-artifact:sources" {
		t.Fatalf("expected classifier in package name, got %q", node.Name)
	}
	if node.Org != "com.example" || node.Ecosystem != "maven" || node.PackageManager != "maven" {
		t.Fatalf("unexpected maven package: %#v", node)
	}
	if node.QualifiedName() != "com.example:demo-artifact:sources" {
		t.Fatalf("unexpected qualified name %q", node.QualifiedName())
	}
	if node.ID != "com.example:demo-artifact:sources@1.0.0" {
		t.Fatalf("unexpected package id %q", node.ID)
	}
	if string(node.PrimaryScope()) != string(sdk.ScopeDevelopment) {
		t.Fatalf("expected development scope, got %q", string(node.PrimaryScope()))
	}
}

func TestMavenDetectorApplicable(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "pom.xml"), []byte("<project/>\n"), 0o644); err != nil {
		t.Fatalf("write pom.xml: %v", err)
	}

	detector := Detector{WorkingDir: projectDir}
	applicable, err := detector.Applicable(context.Background(), sdk.DetectionRequest{ProjectPath: projectDir})
	if err != nil {
		t.Fatalf("Applicable() error = %v", err)
	}
	if !applicable {
		t.Fatal("expected pom.xml to make detector applicable")
	}
}

func TestMavenDependencyTreeArgsScopeFilter(t *testing.T) {
	tests := []struct {
		name      string
		prefix    []string
		scope     sdk.Scope
		want      []string
		unchanged []string
	}{
		{
			name:  "unknown resolves full tree",
			scope: sdk.ScopeUnknown,
			want:  []string{"dependency:tree", "-DoutputType=tgf"},
		},
		{
			name:   "runtime selects runtime scope",
			prefix: []string{"./mvnw"},
			scope:  sdk.ScopeRuntime,
			want:   []string{"./mvnw", "dependency:tree", "-DoutputType=tgf", "-Dscope=runtime"},
		},
		{
			name:      "development selects test scope",
			prefix:    []string{"-f", "demo/pom.xml"},
			scope:     sdk.ScopeDevelopment,
			want:      []string{"-f", "demo/pom.xml", "dependency:tree", "-DoutputType=tgf", "-Dscope=test"},
			unchanged: []string{"-f", "demo/pom.xml"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mavenDependencyTreeArgs(tt.prefix, tt.scope)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("mavenDependencyTreeArgs() = %#v, want %#v", got, tt.want)
			}
			if tt.unchanged != nil && !reflect.DeepEqual(tt.prefix, tt.unchanged) {
				t.Fatalf("prefix was mutated: %#v, want %#v", tt.prefix, tt.unchanged)
			}
		})
	}
}

func TestMavenDetectorResolveRunner_PrefersWrapper(t *testing.T) {
	projectDir := t.TempDir()
	wrapperPath := filepath.Join(projectDir, "mvnw")
	if runtime.GOOS == "windows" {
		wrapperPath = filepath.Join(projectDir, "mvnw.cmd")
	}
	if err := os.WriteFile(wrapperPath, []byte("wrapper\n"), 0o644); err != nil {
		t.Fatalf("write wrapper: %v", err)
	}
	t.Setenv("PATH", "")

	detector := Detector{WorkingDir: projectDir}
	executable, prefixArgs, err := detector.resolveRunner()
	if err != nil {
		t.Fatalf("resolveRunner() error = %v", err)
	}

	if runtime.GOOS == "windows" {
		if executable != "cmd" {
			t.Fatalf("expected cmd executable, got %q", executable)
		}
		if len(prefixArgs) != 2 || prefixArgs[1] != wrapperPath {
			t.Fatalf("expected wrapper path in prefix args, got %#v", prefixArgs)
		}
		return
	}

	if executable != wrapperPath {
		t.Fatalf("expected wrapper executable %q, got %q", wrapperPath, executable)
	}
	if len(prefixArgs) != 0 {
		t.Fatalf("expected no prefix args for unix wrapper, got %#v", prefixArgs)
	}
}

func TestMavenDetectorResolveRunner_FallsBackToInstalledMaven(t *testing.T) {
	originalLookPath := execLookPath
	t.Cleanup(func() { execLookPath = originalLookPath })
	execLookPath = func(file string) (string, error) {
		if file == "mvn" {
			return filepath.Join(t.TempDir(), "mvn"), nil
		}
		return "", os.ErrNotExist
	}

	detector := Detector{WorkingDir: t.TempDir()}
	executable, prefixArgs, err := detector.resolveRunner()
	if err != nil {
		t.Fatalf("resolveRunner() error = %v", err)
	}
	if executable != "mvn" {
		t.Fatalf("expected mvn executable, got %q", executable)
	}
	if len(prefixArgs) != 0 {
		t.Fatalf("expected no prefix args, got %#v", prefixArgs)
	}
}
