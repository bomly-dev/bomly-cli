package govulncheck

import (
	"context"
	"reflect"
	"testing"

	model "github.com/bomly-dev/bomly-sdk"
	"github.com/bomly-dev/bomly-sdk/conformance"
)

// TestConformance runs the SDK conformance suite against the module. No
// manifest is supplied: the analyzer ships embedded in the CLI, not as a
// packaged plugin.
func TestConformance(t *testing.T) {
	conformance.Test(t, conformance.Config{Module: Module()})
}

// TestModuleDescriptorMatchesAnalyzer pins the module descriptor to the
// analyzer's own Descriptor so the two can never drift.
func TestModuleDescriptorMatchesAnalyzer(t *testing.T) {
	if !reflect.DeepEqual(Module().Analyzer.Descriptor, Analyzer{}.Descriptor()) {
		t.Fatal("module descriptor differs from Analyzer{}.Descriptor()")
	}
}

// clearAnalyzedAt blanks the wall-clock annotation timestamps so two runs of
// the same analysis compare equal.
func clearAnalyzedAt(reg *model.PackageRegistry) {
	for _, pkg := range reg.All() {
		for i := range pkg.Vulnerabilities {
			if r := pkg.Vulnerabilities[i].Reachability; r != nil {
				r.AnalyzedAt = ""
			}
		}
	}
}

// TestPackageUpdatesEquivalence verifies the package-updates delta protocol:
// applying the returned PackageUpdates onto a pristine copy of the input
// registry yields exactly the registry the legacy in-place path produces.
func TestPackageUpdatesEquivalence(t *testing.T) {
	moduleDir := newGoModuleDir(t)
	vuln := model.Vulnerability{ID: "GO-2024-1", Source: "osv", ParsedSeverity: "high"}
	runnerResult := RunnerResult{
		Findings: map[string]Finding{
			"GO-2024-1": {
				OSV:        "GO-2024-1",
				CalledBy:   true,
				ImportedBy: true,
				Symbols:    []model.AffectedSymbol{{Symbol: "Decode", Package: "example.com/lib"}},
			},
		},
	}

	legacyGraph, legacyReg := newGoGraph(moduleDir, vuln)
	legacy := Analyzer{DisableCache: true, Runner: &fakeRunner{result: runnerResult}}
	legacyRes, err := legacy.Analyze(context.Background(), model.AnalyzeRequest{
		Graph: legacyGraph, Registry: legacyReg, ProjectPath: moduleDir,
	})
	if err != nil {
		t.Fatalf("legacy Analyze err: %v", err)
	}
	if len(legacyRes.PackageUpdates) != 0 {
		t.Fatalf("legacy path returned %d package updates, want 0", len(legacyRes.PackageUpdates))
	}

	deltaGraph, deltaReg := newGoGraph(moduleDir, vuln)
	delta := Analyzer{DisableCache: true, Runner: &fakeRunner{result: runnerResult}}
	deltaRes, err := delta.Analyze(context.Background(), model.AnalyzeRequest{
		Graph: deltaGraph, Registry: deltaReg, ProjectPath: moduleDir,
		AcceptPackageUpdates: true,
	})
	if err != nil {
		t.Fatalf("delta Analyze err: %v", err)
	}
	if deltaRes.Registry != nil {
		t.Fatal("delta path returned a full registry; want PackageUpdates only")
	}
	if len(deltaRes.PackageUpdates) == 0 {
		t.Fatal("delta path returned no package updates")
	}

	_, pristineReg := newGoGraph(moduleDir, vuln)
	merged := model.ApplyPackageUpdates(pristineReg, deltaRes.PackageUpdates)

	clearAnalyzedAt(legacyReg)
	clearAnalyzedAt(merged)
	if !reflect.DeepEqual(legacyReg.All(), merged.All()) {
		t.Fatalf("delta-applied registry differs from legacy registry:\nlegacy: %+v\nmerged: %+v",
			legacyReg.All(), merged.All())
	}
}
