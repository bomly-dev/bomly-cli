package output

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

// TestFailingFindingCountKeepsSuppressedFindingNonBlocking verifies accepted
// findings remain visible without affecting the policy exit status.
func TestFailingFindingCountKeepsSuppressedFindingNonBlocking(t *testing.T) {
	findings := []sdk.Finding{
		{ID: "fail", PolicyStatus: sdk.FindingPolicyStatusFail},
		{ID: "warn", PolicyStatus: sdk.FindingPolicyStatusWarn},
		{ID: "suppressed", PolicyStatus: sdk.FindingPolicyStatusSuppressed},
	}
	if got := FailingFindingCount(findings); got != 1 {
		t.Fatalf("FailingFindingCount() = %d, want 1", got)
	}
}

// TestFindingsFromScanExposesStableRuleID verifies structured output includes
// the package-specific rule identity required to author baseline entries.
func TestFindingsFromScanExposesStableRuleID(t *testing.T) {
	findings := FindingsFromScan([]sdk.Finding{{
		ID: "package:denied:example", RuleID: "denied-package",
		Kind: sdk.FindingKindPackage, PackageRef: "pkg:npm/example@1.0.0",
	}}, nil)
	if len(findings) != 1 || findings[0].RuleID != "denied-package" {
		t.Fatalf("projected findings = %#v", findings)
	}
}
