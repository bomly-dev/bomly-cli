package jvmreach

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	model "github.com/bomly-dev/bomly-cli/sdk"
)

func jvmProjectFixture(name string) string {
	path, err := filepath.Abs(filepath.Join("testdata", "projects", name))
	if err != nil {
		return filepath.Join("testdata", "projects", name)
	}
	return path
}

func TestLibraryRunnerWalksJVMTestdata(t *testing.T) {
	got, err := NewRunner(nil).Run(context.Background(), jvmProjectFixture("dynamic"))
	if err != nil {
		t.Fatal(err)
	}
	for _, coord := range []string{
		"com.fasterxml.jackson.core:jackson-databind",
		"org.apache.logging.log4j:log4j-api",
		"org.apache.logging.log4j:log4j-core",
	} {
		if _, ok := got.ImportedArtifacts[coord]; !ok {
			t.Fatalf("missing artifact %q: %v", coord, got.ImportedArtifacts)
		}
	}
	if _, ok := got.ImportedArtifacts["com.google.guava:guava"]; ok {
		t.Fatalf("nested child module import leaked into parent scan: %v", got.ImportedArtifacts)
	}
	if _, ok := got.RawImports["com.fasterxml.jackson.databind.ObjectMapper"]; !ok {
		t.Fatalf("raw imports = %v", got.RawImports)
	}
	if got.SourceFiles != 1 || !got.DynamicImportsDetected {
		t.Fatalf("result = %+v, want one source and dynamic imports", got)
	}
}

func TestJVMDynamicImportDetectionFromTestdata(t *testing.T) {
	if !detectDynamicImports(jvmProjectFixture("dynamic")) {
		t.Fatal("dynamic fixture was not detected")
	}
	if detectDynamicImports(jvmProjectFixture("static")) {
		t.Fatal("literal reflection and ignored build output should remain static")
	}
}

func TestJVMDescriptorAndRunnerResult(t *testing.T) {
	a := Analyzer{}
	if !a.Ready() || a.Descriptor().Name != Name {
		t.Fatalf("descriptor = %+v ready=%v", a.Descriptor(), a.Ready())
	}
	if !(RunnerResult{SourceFiles: 1}).hasResult() || (RunnerResult{}).hasResult() {
		t.Fatal("runner result actionability mismatch")
	}
}

func TestJVMStandaloneApplyRunnerResult(t *testing.T) {
	g := model.New()
	pkg := model.NewPackage(model.Package{
		Name:            "jackson-databind",
		Org:             "com.fasterxml.jackson.core",
		Ecosystem:       string(model.EcosystemMaven),
		Vulnerabilities: []model.PackageVulnerability{{ID: "GHSA-1"}},
	})
	if err := g.AddPackage(pkg); err != nil {
		t.Fatal(err)
	}
	got := applyRunnerResult(g, jvmProjectFixture("dynamic"), RunnerResult{
		ImportedArtifacts: map[string]struct{}{"com.fasterxml.jackson.core:jackson-databind": {}},
		SourceFiles:       1,
	}, time.Time{})
	if got.reachable != 1 || pkg.Vulnerabilities[0].Reachability.Status != model.ReachabilityReachable {
		t.Fatalf("outcome = %+v reachability=%+v", got, pkg.Vulnerabilities[0].Reachability)
	}
}

func TestJVMFailureReasons(t *testing.T) {
	tests := map[string]string{
		"runner not implemented":              "missing-toolchain",
		"project dir not accessible":          "no-project-root",
		"context deadline exceeded":           "cancelled",
		"unexpected source scanner condition": "runner-error",
	}
	for message, want := range tests {
		if got := failureReason(errors.New(message)); got != want {
			t.Fatalf("failureReason(%q) = %q, want %q", message, got, want)
		}
	}
	if got := failureReason(nil); got != "" {
		t.Fatalf("failureReason(nil) = %q", got)
	}
	runner := NewRunner(nil)
	if runner.Name() != "library" || runner.Version() != runnerSchemaVersion {
		t.Fatalf("runner = %q version=%q", runner.Name(), runner.Version())
	}
}
