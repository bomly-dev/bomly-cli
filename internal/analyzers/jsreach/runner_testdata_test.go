package jsreach

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	model "github.com/bomly-dev/bomly-cli/sdk"
	"github.com/evanw/esbuild/pkg/api"
)

func jsProjectFixture(name string) string {
	path, err := filepath.Abs(filepath.Join("testdata", "projects", name))
	if err != nil {
		return filepath.Join("testdata", "projects", name)
	}
	return path
}

func TestDiscoverEntryPointsFromTestdata(t *testing.T) {
	root := jsProjectFixture("entrypoints")
	got, err := discoverEntryPoints(root)
	if err != nil {
		t.Fatal(err)
	}
	for i := range got {
		got[i], _ = filepath.Rel(root, got[i])
		got[i] = filepath.ToSlash(got[i])
	}
	sort.Strings(got)
	want := []string{"browser.js", "cjs.js", "cli.js", "esm.js", "util.js"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("entry points = %v, want %v", got, want)
	}
}

func TestLibraryRunnerWalksJSTestdata(t *testing.T) {
	got, err := NewRunner(nil).Run(context.Background(), jsProjectFixture("entrypoints"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"lodash", "react", "@scope/pkg", "chalk", "commander"} {
		if _, ok := got.ImportedPackages[name]; !ok {
			t.Fatalf("missing package %q: %v", name, got.ImportedPackages)
		}
	}
	if !got.DynamicImportsDetected {
		t.Fatal("dynamic import fixture was not detected")
	}
}

func TestJSDynamicImportDetectionFromTestdata(t *testing.T) {
	if !detectDynamicImports(jsProjectFixture("entrypoints")) {
		t.Fatal("dynamic fixture was not detected")
	}
	if detectDynamicImports(jsProjectFixture("static")) {
		t.Fatal("ignored build output should not mark static fixture dynamic")
	}
}

func TestJSDescriptorAndRunnerResult(t *testing.T) {
	a := Analyzer{}
	if !a.Ready() || a.Descriptor().Name != Name {
		t.Fatalf("descriptor = %+v ready=%v", a.Descriptor(), a.Ready())
	}
	if !(RunnerResult{EntryPoints: []string{"index.js"}}).hasResult() || (RunnerResult{}).hasResult() {
		t.Fatal("runner result actionability mismatch")
	}
}

func TestJSStandaloneApplyRunnerResult(t *testing.T) {
	const purl = "pkg:npm/lodash"
	g := model.New()
	pkg := model.NewDependency(model.Dependency{Coordinates: model.Coordinates{Name: "lodash", Ecosystem: model.EcosystemNPM, PURL: purl}})
	if err := g.AddNode(pkg); err != nil {
		t.Fatal(err)
	}
	reg := model.NewPackageRegistry()
	reg.Ensure(purl).Vulnerabilities = []model.Vulnerability{{ID: "GHSA-1"}}
	req := model.AnalyzeRequest{Graph: g, Registry: reg}
	got := applyRunnerResult(req, jsProjectFixture("entrypoints"), RunnerResult{
		ImportedPackages: map[string]struct{}{"lodash": {}},
		EntryPoints:      []string{"index.js"},
	}, time.Time{})
	vulns := reg.Ensure(purl).Vulnerabilities
	if got.reachable != 1 || vulns[0].Reachability == nil || vulns[0].Reachability.Status != model.ReachabilityReachable {
		t.Fatalf("outcome = %+v reachability=%+v", got, vulns[0].Reachability)
	}
}

func TestJSFailureReasonsAndMessageSummary(t *testing.T) {
	tests := map[string]string{
		"runner not implemented":             "missing-toolchain",
		"no resolvable entry points":         "no-entry-points",
		"context deadline exceeded":          "cancelled",
		"unexpected esbuild parser behavior": "runner-error",
	}
	for message, want := range tests {
		if got := failureReason(errors.New(message)); got != want {
			t.Fatalf("failureReason(%q) = %q, want %q", message, got, want)
		}
	}
	if got := failureReason(nil); got != "" {
		t.Fatalf("failureReason(nil) = %q", got)
	}
	messages := []api.Message{{Text: "first"}, {Text: "second"}, {Text: "third"}}
	if got := summarizeMessages(messages, 2); got != "first; second (+1 more)" {
		t.Fatalf("summary = %q", got)
	}
	if got := summarizeMessages(nil, 2); got != "" {
		t.Fatalf("empty summary = %q", got)
	}
}
