package remediation

import (
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestEvaluateReturnsDeterministicPackageProposals(t *testing.T) {
	graph := sdk.New()
	for _, pkg := range []*sdk.Package{
		sdk.NewPackage(sdk.Package{
			Name:    "zeta",
			Version: "1.0.0",
			Vulnerabilities: []sdk.PackageVulnerability{{
				ID:            "CVE-Z",
				FixedVersions: []string{"1.2.0", "1.1.0"},
			}},
		}),
		sdk.NewPackage(sdk.Package{Name: "root", Version: "1.0.0"}),
		sdk.NewPackage(sdk.Package{
			Name:    "alpha",
			Version: "2.0.0",
			Vulnerabilities: []sdk.PackageVulnerability{{
				ID:      "CVE-A",
				FixedIn: "2.0.1",
			}},
		}),
	} {
		if err := graph.AddPackage(pkg); err != nil {
			t.Fatalf("AddPackage() error = %v", err)
		}
	}

	result := Evaluate(graph)
	if len(result.Proposals) != 2 {
		t.Fatalf("len(Proposals) = %d, want 2", len(result.Proposals))
	}
	if result.Proposals[0].PackageName != "alpha" || result.Proposals[1].PackageName != "zeta" {
		t.Fatalf("proposal order = %#v, want alpha then zeta", result.Proposals)
	}
	if got := result.Proposals[1].ProposedVersion; got != "1.1.0" {
		t.Fatalf("zeta ProposedVersion = %q, want 1.1.0", got)
	}
	if result.ProposedCount() != 2 || result.UnavailableCount() != 0 {
		t.Fatalf("counts = proposed %d unavailable %d", result.ProposedCount(), result.UnavailableCount())
	}
}

func TestProposePackageAggregatesMinimumAcrossVulnerabilities(t *testing.T) {
	pkg := sdk.NewPackage(sdk.Package{Name: "lodash", Version: "4.17.19"})
	proposal := ProposePackage(pkg, []sdk.PackageVulnerability{
		{ID: "CVE-B", FixedIn: "4.17.21"},
		{ID: "CVE-A", FixedVersions: []string{"4.17.20", "4.17.22"}},
	})
	if proposal.Status != StatusProposed {
		t.Fatalf("Status = %q, want proposed: %s", proposal.Status, proposal.Reason)
	}
	if proposal.ProposedVersion != "4.17.21" {
		t.Fatalf("ProposedVersion = %q, want 4.17.21", proposal.ProposedVersion)
	}
	if got := strings.Join(proposal.VulnerabilityIDs, ","); got != "CVE-A,CVE-B" {
		t.Fatalf("VulnerabilityIDs = %q, want sorted IDs", got)
	}
	if proposal.ConstraintCompatibility != ConstraintCompatibilityUnknown {
		t.Fatalf("ConstraintCompatibility = %q, want unknown", proposal.ConstraintCompatibility)
	}
}

func TestProposePackageRejectsIncompleteOrInvalidEvidence(t *testing.T) {
	tests := []struct {
		name            string
		version         string
		vulnerabilities []sdk.PackageVulnerability
		wantReason      string
	}{
		{
			name:            "missing fixed version",
			version:         "1.0.0",
			vulnerabilities: []sdk.PackageVulnerability{{ID: "CVE-MISSING"}},
			wantReason:      "no locally attached fixed version",
		},
		{
			name:            "invalid installed version",
			version:         "latest",
			vulnerabilities: []sdk.PackageVulnerability{{ID: "CVE-INSTALLED", FixedIn: "1.0.1"}},
			wantReason:      "installed version",
		},
		{
			name:            "invalid fixed version",
			version:         "1.0.0",
			vulnerabilities: []sdk.PackageVulnerability{{ID: "CVE-FIXED", FixedVersions: []string{"1.0.1", "next"}}},
			wantReason:      "not semver-compatible",
		},
		{
			name:            "older fixed version",
			version:         "2.0.0",
			vulnerabilities: []sdk.PackageVulnerability{{ID: "CVE-OLDER", FixedIn: "1.9.9"}},
			wantReason:      "newer than installed version",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			proposal := ProposePackage(sdk.NewPackage(sdk.Package{Name: "demo", Version: tc.version}), tc.vulnerabilities)
			if proposal.Status != StatusInsufficientLocalData {
				t.Fatalf("Status = %q, want insufficient_local_data", proposal.Status)
			}
			if proposal.ProposedVersion != "" {
				t.Fatalf("ProposedVersion = %q, want empty", proposal.ProposedVersion)
			}
			if !strings.Contains(proposal.Reason, tc.wantReason) {
				t.Fatalf("Reason = %q, want substring %q", proposal.Reason, tc.wantReason)
			}
		})
	}
}

func TestEvaluateNilGraph(t *testing.T) {
	result := Evaluate(nil)
	if len(result.Proposals) != 0 || len(result.ByPackageID) != 0 {
		t.Fatalf("Evaluate(nil) = %#v, want empty result", result)
	}
}
