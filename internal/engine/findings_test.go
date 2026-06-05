package engine

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestDeduplicateFindingsKeepsHighestPrioritySource(t *testing.T) {
	const pkgRef = "pkg:npm/pkg@1.0.0"
	findings := []sdk.Finding{
		{ID: "CVE-1", VulnerabilityID: "CVE-1", Kind: sdk.FindingKindVulnerability, Source: "osv", PackageRef: pkgRef},
		{ID: "CVE-1", VulnerabilityID: "CVE-1", Kind: sdk.FindingKindVulnerability, Source: "grype", PackageRef: pkgRef},
		{ID: "POLICY-1", Kind: sdk.FindingKindLicense, Source: "license", PackageRef: pkgRef},
	}

	got := DeduplicateFindings(findings)
	if len(got) != 2 {
		t.Fatalf("expected 2 findings, got %#v", got)
	}
	if got[0].Source != "grype" {
		t.Fatalf("expected grype finding to win, got %#v", got[0])
	}
	if got[1].ID != "POLICY-1" {
		t.Fatalf("expected non-vulnerability finding to pass through, got %#v", got[1])
	}
}
