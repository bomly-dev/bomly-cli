package output

import (
	"testing"

	"github.com/bomly-dev/bomly-sdk/model"
)

// TestFailingFindingCountKeepsSuppressedFindingNonBlocking verifies accepted
// findings remain visible without affecting the policy exit status.
func TestFailingFindingCountKeepsSuppressedFindingNonBlocking(t *testing.T) {
	findings := []model.Finding{
		{ID: "fail", PolicyStatus: model.FindingPolicyStatusFail},
		{ID: "warn", PolicyStatus: model.FindingPolicyStatusWarn},
		{ID: "suppressed", PolicyStatus: model.FindingPolicyStatusSuppressed},
	}
	if got := FailingFindingCount(findings); got != 1 {
		t.Fatalf("FailingFindingCount() = %d, want 1", got)
	}
}

// TestFindingsWithSeverityKeepsStableRuleID verifies that the findings a
// document carries keep the package-specific rule identity required to
// author baseline entries, and that a severity the finding did not state is
// filled from the advisory it references.
func TestFindingsWithSeverityKeepsStableRuleID(t *testing.T) {
	registry := model.NewPackageRegistry()
	registry.Add(&model.Package{
		Coordinates:     model.Coordinates{PURL: "pkg:npm/example@1.0.0", Ecosystem: model.EcosystemNPM, Name: "example", Version: "1.0.0"},
		Vulnerabilities: []model.Vulnerability{{ID: "GHSA-example", ParsedSeverity: model.SeverityHigh}},
	})
	findings := FindingsWithSeverity([]model.Finding{
		{ID: "package:denied:example", RuleID: "denied-package", Kind: model.FindingKindPackage, PackageRef: "pkg:npm/example@1.0.0"},
		{ID: "GHSA-example", Kind: model.FindingKindVulnerability, PackageRef: "pkg:npm/example@1.0.0", VulnerabilityID: "GHSA-example"},
	}, registry)
	if len(findings) != 2 || findings[0].RuleID != "denied-package" {
		t.Fatalf("document findings = %#v", findings)
	}
	if findings[1].Severity != model.SeverityHigh {
		t.Fatalf("severity was not filled from the advisory: %#v", findings[1])
	}
}
