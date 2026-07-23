package mcp

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestCompactScanInventoryCapIsDeterministicAndCounted(t *testing.T) {
	dependencies := make([]output.ScanDependency, 0, maxInventoryEntries+17)
	for i := maxInventoryEntries + 16; i >= 0; i-- {
		dependencies = append(dependencies, output.ScanDependency{
			ID:      fmt.Sprintf("dep-%03d", i),
			Name:    fmt.Sprintf("package-%03d", i),
			Version: "1.0.0",
		})
	}
	run := ScanRunResult{Response: output.ScanResponse{
		Manifests: []output.ScanManifest{{Path: "package.json", Dependencies: dependencies}},
	}}
	first := BuildCompactScan(run)
	second := BuildCompactScan(run)
	if !reflect.DeepEqual(first, second) {
		t.Fatal("compact inventory changed for identical input")
	}
	if len(first.Packages) != maxInventoryEntries {
		t.Fatalf("inventory length = %d, want %d", len(first.Packages), maxInventoryEntries)
	}
	if first.Truncation == nil || !first.Truncation.Truncated || first.Truncation.OmittedPackages != 17 {
		t.Fatalf("inventory truncation = %#v", first.Truncation)
	}
	if first.Packages[0] != "package-000@1.0.0" ||
		first.Packages[len(first.Packages)-1] != "package-199@1.0.0" {
		t.Fatalf("inventory is not sorted before truncation: first=%q last=%q", first.Packages[0], first.Packages[len(first.Packages)-1])
	}
}

func TestCompactScanCapsDiagnosticsWithVisibleMarker(t *testing.T) {
	diagnostics := make([]Diagnostic, maxDiagnosticsReported+9)
	for i := range diagnostics {
		diagnostics[i] = Diagnostic{Stage: "detect", Source: fmt.Sprintf("source-%02d", i), Message: "degraded"}
	}
	response := BuildCompactScan(ScanRunResult{Diagnostics: diagnostics})
	if len(response.Diagnostics) != maxDiagnosticsReported+1 {
		t.Fatalf("diagnostics length = %d, want %d", len(response.Diagnostics), maxDiagnosticsReported+1)
	}
	last := response.Diagnostics[len(response.Diagnostics)-1]
	if last.Stage != "meta" || last.Message == "" {
		t.Fatalf("missing visible diagnostic truncation marker: %#v", last)
	}
}

func TestCompactRemediationCapsAliasesAndFindingsWithCounters(t *testing.T) {
	in := remediationFixture(t)
	pkg, ok := in.Registry.Get("pkg:npm/lib-a@1.0.0")
	if !ok {
		t.Fatal("fixture package missing")
	}
	pkg.Vulnerabilities[0].Aliases = []string{"CVE-1", "CVE-2", "CVE-3", "CVE-4", "CVE-5"}
	for i := 0; i < maxFindingsPerGroup+6; i++ {
		id := fmt.Sprintf("GHSA-extra-%02d", i)
		pkg.Vulnerabilities = append(pkg.Vulnerabilities, sdk.Vulnerability{
			ID:             id,
			Aliases:        []string{"A-1", "A-2", "A-3", "A-4"},
			ParsedSeverity: sdk.SeverityLow,
			FixState:       sdk.FixStateFixed,
			FixedIn:        "1.2.0",
		})
		in.Findings = append(in.Findings, sdk.Finding{
			ID:              id,
			VulnerabilityID: id,
			Kind:            sdk.FindingKindVulnerability,
			Severity:        sdk.SeverityLow,
			PackageRef:      pkg.PURL,
			DependencyRefs:  append([]string(nil), in.Findings[0].DependencyRefs...),
		})
	}
	result := buildRemediations(in)
	direct := groupByAction(t, result.Remediations, ActionDirectBump)
	if len(direct.Fixes) != maxFindingsPerGroup {
		t.Fatalf("fix count = %d, want %d", len(direct.Fixes), maxFindingsPerGroup)
	}
	if result.Truncation == nil || result.Truncation.OmittedFindings != 7 {
		t.Fatalf("finding truncation = %#v", result.Truncation)
	}
	for _, finding := range direct.Fixes {
		if len(finding.Aliases) > maxAliases {
			t.Fatalf("aliases exceeded cap: %#v", finding.Aliases)
		}
	}
}
