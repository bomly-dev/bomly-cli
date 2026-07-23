package output

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestFailingFindingCountKeepsSuppressedFindingNonBlocking(t *testing.T) {
	findings := []sdk.Finding{
		{ID: "fail", Disposition: sdk.FindingDispositionFail},
		{ID: "warn", Disposition: sdk.FindingDispositionWarn},
		{ID: "suppressed", Disposition: sdk.FindingDispositionSuppressed},
	}
	if got := FailingFindingCount(findings); got != 1 {
		t.Fatalf("FailingFindingCount() = %d, want 1", got)
	}
}
