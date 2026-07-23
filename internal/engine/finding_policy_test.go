package engine

import (
	"context"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

type fixedPolicyResolver struct{ status sdk.FindingDisposition }

func (r fixedPolicyResolver) ResolveFindingPolicy(context.Context, sdk.Finding, *sdk.PackageRegistry) (sdk.FindingPolicyDecision, bool) {
	return sdk.FindingPolicyDecision{Status: r.status, Source: "test"}, true
}

func TestResolveFindingPolicyStatusesKeepsFindingEvidence(t *testing.T) {
	original := sdk.Finding{ID: "CVE-1", Title: "title", Reasons: []string{"reason"}, PackageRef: "pkg:npm/example@1.0.0", Disposition: sdk.FindingDispositionFail}
	resolved := resolveFindingPolicyStatuses(context.Background(), []sdk.Finding{original}, nil, []sdk.FindingPolicyResolver{fixedPolicyResolver{status: sdk.FindingDispositionSuppressed}})
	if len(resolved) != 1 || resolved[0].Disposition != sdk.FindingDispositionSuppressed {
		t.Fatalf("resolved findings = %#v", resolved)
	}
	if resolved[0].ID != original.ID || resolved[0].Title != original.Title || len(resolved[0].Reasons) != 1 || resolved[0].PackageRef != original.PackageRef {
		t.Fatalf("resolver rewrote finding evidence: %#v", resolved[0])
	}
}

func TestResolveFindingPolicyStatusesUsesLeastSuppressiveDecision(t *testing.T) {
	findings := []sdk.Finding{{ID: "one", Disposition: sdk.FindingDispositionFail}}
	resolved := resolveFindingPolicyStatuses(context.Background(), findings, nil, []sdk.FindingPolicyResolver{
		fixedPolicyResolver{status: sdk.FindingDispositionSuppressed},
		fixedPolicyResolver{status: sdk.FindingDispositionWarn},
	})
	if resolved[0].Disposition != sdk.FindingDispositionWarn {
		t.Fatalf("disposition = %q, want warn", resolved[0].Disposition)
	}
}

func TestResolveFindingPolicyStatusesRejectsUnknownStatus(t *testing.T) {
	findings := []sdk.Finding{{ID: "one", Disposition: sdk.FindingDispositionFail}}
	resolved := resolveFindingPolicyStatuses(context.Background(), findings, nil, []sdk.FindingPolicyResolver{
		fixedPolicyResolver{status: sdk.FindingDisposition("invalid")},
	})
	if resolved[0].Disposition != sdk.FindingDispositionFail {
		t.Fatalf("policy status = %q, want fail", resolved[0].Disposition)
	}
}
