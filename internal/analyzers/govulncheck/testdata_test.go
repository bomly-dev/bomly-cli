package govulncheck

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	model "github.com/bomly-dev/bomly-cli/sdk"
)

func goFixture(parts ...string) string {
	all := append([]string{"testdata"}, parts...)
	path, err := filepath.Abs(filepath.Join(all...))
	if err != nil {
		return filepath.Join(all...)
	}
	return path
}

func TestDiscoverModuleRootsFromTestdata(t *testing.T) {
	root := goFixture("module")
	g := model.New()
	pkg := model.NewDependency(model.Dependency{Coordinates: model.Coordinates{Name: "example.com/lib",
		Ecosystem: model.EcosystemGo}, Locations: []model.PackageLocation{{RealPath: filepath.Join(root, "nested", "file.go")}},
	})
	if err := g.AddNode(pkg); err != nil {
		t.Fatal(err)
	}
	got := discoverModuleRoots(model.AnalyzeRequest{
		Graph:       g,
		ProjectPath: filepath.Join(root, "main.go"),
		ExecutionTarget: model.ExecutionTarget{
			Location: filepath.Join(root, "nested"),
		},
	})
	if !reflect.DeepEqual(got, []string{root}) {
		t.Fatalf("roots = %v, want [%s]", got, root)
	}
	if got := findGoModRoot(filepath.Join(root, "nested", "file.go")); got != root {
		t.Fatalf("findGoModRoot() = %q, want %q", got, root)
	}
}

func TestParseGovulncheckJSONFromTestdataRecoversAfterMalformedRecord(t *testing.T) {
	data, err := os.ReadFile(goFixture("govulncheck.json"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseGovulncheckJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	finding := got.Findings["GO-2024-1234"]
	if !finding.CalledBy || !finding.ImportedBy || finding.FixedIn != "v1.2.3" {
		t.Fatalf("finding = %+v", finding)
	}
	if len(finding.CallPaths) != 2 || len(finding.Symbols) != 1 {
		t.Fatalf("finding evidence = %+v, want two paths and one deduplicated symbol", finding)
	}
	if finding.Symbols[0].Kind != "method" {
		t.Fatalf("symbol = %+v, want method", finding.Symbols[0])
	}
	if _, ok := got.Findings["GO-2024-9999"]; !ok {
		t.Fatal("record after malformed fixture line was not parsed")
	}
}

func TestGovulncheckDescriptorAndRunnerHelpers(t *testing.T) {
	a := Analyzer{}
	if !a.Ready() || a.Descriptor().Name != Name {
		t.Fatalf("descriptor = %+v ready=%v", a.Descriptor(), a.Ready())
	}
	if !(Finding{OSV: "GO-1", ImportedBy: true}).hasResult() {
		t.Fatal("imported finding should be actionable")
	}
	if (Finding{OSV: "GO-1"}).hasResult() {
		t.Fatal("finding without reachability evidence should not be actionable")
	}
	for _, err := range []error{errors.New("exit status 3"), errors.New("vulnerabilities found")} {
		if !isVulnsFound(err) {
			t.Fatalf("isVulnsFound(%q) = false", err)
		}
	}
	if isVulnsFound(errors.New("exit status 1")) || isVulnsFound(nil) {
		t.Fatal("non-vulnerability errors must not match")
	}
	if got := truncateStderr("abcdef", 3); got != "abc..." {
		t.Fatalf("truncateStderr = %q", got)
	}
	if got := NewRunner(nil).Name(); got != "library" {
		t.Fatalf("runner name = %q, want library", got)
	}
}

func TestGovulncheckFailureReasons(t *testing.T) {
	tests := map[string]string{
		"go executable not found":              "missing-toolchain",
		"context deadline exceeded":            "cancelled",
		"no Go files in fixture":               "no-go-packages",
		"missing go.sum entry":                 "module-resolution-failed",
		"errors parsing go.mod: syntax error":  "invalid-go-mod",
		"compile failed: undefined: Something": "build-failed",
		"unexpected output":                    "runner-error",
	}
	for message, want := range tests {
		if got := failureReason(errors.New(message)); got != want {
			t.Fatalf("failureReason(%q) = %q, want %q", message, got, want)
		}
	}
	if got := failureReason(nil); got != "" {
		t.Fatalf("failureReason(nil) = %q", got)
	}
}

func TestGovulncheckAnalyzerMarksUnknownWithoutModuleRoot(t *testing.T) {
	const purl = "pkg:golang/example.com/lib"
	g := model.New()
	pkg := model.NewDependency(model.Dependency{Coordinates: model.Coordinates{Name: "example.com/lib",
		Ecosystem: model.EcosystemGo,
		PURL:      purl},
	})
	if err := g.AddNode(pkg); err != nil {
		t.Fatal(err)
	}
	reg := model.NewPackageRegistry()
	reg.Ensure(purl).Vulnerabilities = []model.Vulnerability{{ID: "GO-1"}}
	if _, err := (Analyzer{DisableCache: true}).Analyze(context.Background(), model.AnalyzeRequest{Graph: g, Registry: reg}); err != nil {
		t.Fatal(err)
	}
	got := reg.Ensure(purl).Vulnerabilities[0].Reachability
	if got == nil || got.Status != model.ReachabilityUnknown || got.Reason != "no-module-root-discovered" {
		t.Fatalf("reachability = %+v", got)
	}
}

func TestGovulncheckLookupFindingAndImportedModuleAliases(t *testing.T) {
	runResult := RunnerResult{Findings: map[string]Finding{
		"GO-1": {OSV: "GO-1", Aliases: []string{"CVE-1"}},
	}}
	tests := []model.Vulnerability{
		{ID: "GO-1"},
		{ID: "CVE-1"},
		{ID: "GHSA-1", Aliases: []string{"GO-1"}},
		{ID: "GHSA-2", Aliases: []string{"CVE-1"}},
	}
	for _, vuln := range tests {
		if _, ok := lookupFinding(runResult, &vuln); !ok {
			t.Fatalf("lookupFinding(%+v) missed", vuln)
		}
	}
	pkg := model.NewDependency(model.Dependency{Coordinates: model.Coordinates{Name: "example.com/lib"}})
	if !packageImportedByModule(pkg, map[string]struct{}{"example.com/lib": {}}) {
		t.Fatal("package name was not matched against imported module set")
	}
	if packageImportedByModule(pkg, map[string]struct{}{"example.com/other": {}}) {
		t.Fatal("unrelated imported module matched")
	}
}
