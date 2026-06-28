package pyreach

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	model "github.com/bomly-dev/bomly-cli/sdk"
)

func pythonFixture(parts ...string) string {
	all := append([]string{"testdata"}, parts...)
	path, err := filepath.Abs(filepath.Join(all...))
	if err != nil {
		return filepath.Join(all...)
	}
	return path
}

func TestDiscoverProjectRootsFromTestdata(t *testing.T) {
	root := pythonFixture("project")
	g := model.New()
	pkg := model.NewDependency(model.Dependency{Coordinates: model.Coordinates{Name: "requests",
		Ecosystem: model.EcosystemPython}, Locations: []model.PackageLocation{{RealPath: filepath.Join(root, "pkg", "helpers.py")}},
	})
	if err := g.AddNode(pkg); err != nil {
		t.Fatal(err)
	}
	got := discoverProjectRoots(model.AnalyzeRequest{
		Graph:       g,
		ProjectPath: filepath.Join(root, "app.py"),
		ExecutionTarget: model.ExecutionTarget{
			Location: filepath.Join(root, "pkg"),
		},
	})
	if !reflect.DeepEqual(got, []string{root}) {
		t.Fatalf("roots = %v, want [%s]", got, root)
	}
	requirementsRoot := pythonFixture("requirements-project")
	if got := findProjectRoot(filepath.Join(requirementsRoot, "src", "app.py")); got != requirementsRoot {
		t.Fatalf("requirements*.txt root = %q, want %q", got, requirementsRoot)
	}
}

func TestLibraryRunnerWalksPythonTestdata(t *testing.T) {
	got, err := NewRunner(nil).Run(context.Background(), pythonFixture("project"))
	if err != nil {
		t.Fatal(err)
	}
	for _, dist := range []string{"requests", "pyyaml", "flask", "numpy"} {
		if _, ok := got.ImportedDistributions[dist]; !ok {
			t.Fatalf("missing distribution %q: %v", dist, got.ImportedDistributions)
		}
	}
	for _, dist := range []string{"os", "never-seen"} {
		if _, ok := got.ImportedDistributions[dist]; ok {
			t.Fatalf("unexpected distribution %q: %v", dist, got.ImportedDistributions)
		}
	}
	if !got.DynamicImportsDetected {
		t.Fatal("dynamic import fixture was not detected")
	}
	sort.Strings(got.SkippedDirs)
	if !reflect.DeepEqual(got.SkippedDirs, []string{"build"}) {
		t.Fatalf("skipped dirs = %v, want [build]", got.SkippedDirs)
	}
}

func TestPythonDynamicImportDetectionFromTestdata(t *testing.T) {
	if !detectDynamicImports(pythonFixture("project")) {
		t.Fatal("dynamic fixture was not detected")
	}
	if detectDynamicImports(pythonFixture("static-project")) {
		t.Fatal("literal import and ignored dist fixture should remain static")
	}
}

func TestPythonDescriptorAndFailureReasons(t *testing.T) {
	a := Analyzer{}
	if err := a.Ready(context.Background(), model.AnalyzeRequest{}); err != nil || a.Descriptor().Name != Name {
		t.Fatalf("descriptor = %+v ready_err=%v", a.Descriptor(), a.Ready(context.Background(), model.AnalyzeRequest{}))
	}
	if !(RunnerResult{SourceFiles: 1}).hasResult() || (RunnerResult{}).hasResult() {
		t.Fatal("runner result actionability mismatch")
	}
	tests := map[string]string{
		"runner not found":            "missing-toolchain",
		"project dir not accessible":  "no-project-root",
		"context canceled":            "cancelled",
		"unexpected parser condition": "runner-error",
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
