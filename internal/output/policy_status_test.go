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

// TestFindingsFromScanExposesStableRuleID verifies structured output includes
// the package-specific rule identity required to author baseline entries.
func TestFindingsFromScanExposesStableRuleID(t *testing.T) {
	findings := FindingsFromScan([]model.Finding{{
		ID: "package:denied:example", RuleID: "denied-package",
		Kind: model.FindingKindPackage, PackageRef: "pkg:npm/example@1.0.0",
	}}, nil)
	if len(findings) != 1 || findings[0].RuleID != "denied-package" {
		t.Fatalf("projected findings = %#v", findings)
	}
}
