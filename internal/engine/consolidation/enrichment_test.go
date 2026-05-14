package consolidation

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestSyncPackageEnrichmentMergesReachabilityIntoExistingVuln(t *testing.T) {
	dst := &sdk.Package{
		Name: "lib", Version: "1.2.3", Ecosystem: "go",
		Vulnerabilities: []sdk.PackageVulnerability{
			{ID: "CVE-2024-0001", Source: "osv", Severity: "high"},
		},
	}
	src := &sdk.Package{
		Name: "lib", Version: "1.2.3", Ecosystem: "go",
		Vulnerabilities: []sdk.PackageVulnerability{
			{
				ID: "CVE-2024-0001", Source: "osv", Severity: "high",
				Reachability: &sdk.Reachability{
					Status:   sdk.ReachabilityReachable,
					Tier:     sdk.TierSymbol,
					Analyzer: "govulncheck",
				},
				AffectedSymbols: []sdk.AffectedSymbol{
					{Symbol: "Decode", Package: "lib"},
				},
			},
		},
	}

	syncPackageEnrichment(dst, src)

	if len(dst.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vuln after merge, got %d", len(dst.Vulnerabilities))
	}
	v := dst.Vulnerabilities[0]
	if v.Reachability == nil {
		t.Fatal("Reachability not propagated to existing vuln entry")
	}
	if v.Reachability.Status != sdk.ReachabilityReachable {
		t.Errorf("status = %q, want reachable", v.Reachability.Status)
	}
	if len(v.AffectedSymbols) != 1 || v.AffectedSymbols[0].Symbol != "Decode" {
		t.Errorf("AffectedSymbols not propagated: %+v", v.AffectedSymbols)
	}
	// Verify the merged Reachability is a deep copy, not aliasing src.
	src.Vulnerabilities[0].Reachability.Status = sdk.ReachabilityUnreachable
	if dst.Vulnerabilities[0].Reachability.Status != sdk.ReachabilityReachable {
		t.Error("merge did not deep-copy Reachability — mutation leaked from src")
	}
}

func TestSyncPackageEnrichmentDoesNotOverwriteExistingReachability(t *testing.T) {
	dst := &sdk.Package{
		Name: "lib", Version: "1.2.3", Ecosystem: "go",
		Vulnerabilities: []sdk.PackageVulnerability{
			{
				ID: "CVE-2024-0001", Source: "osv", Severity: "high",
				Reachability: &sdk.Reachability{Status: sdk.ReachabilityReachable, Analyzer: "first"},
			},
		},
	}
	src := &sdk.Package{
		Name: "lib", Version: "1.2.3", Ecosystem: "go",
		Vulnerabilities: []sdk.PackageVulnerability{
			{
				ID: "CVE-2024-0001", Source: "osv", Severity: "high",
				Reachability: &sdk.Reachability{Status: sdk.ReachabilityUnreachable, Analyzer: "second"},
			},
		},
	}
	syncPackageEnrichment(dst, src)
	if dst.Vulnerabilities[0].Reachability.Analyzer != "first" {
		t.Errorf("merge clobbered existing Reachability: %+v", dst.Vulnerabilities[0].Reachability)
	}
}
