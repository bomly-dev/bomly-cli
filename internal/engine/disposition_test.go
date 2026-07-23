package engine

import (
	"context"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

type fixedDispositionResolver struct{ disposition sdk.FindingDisposition }

func (r fixedDispositionResolver) ResolveFinding(context.Context, sdk.Finding, *sdk.PackageRegistry) (FindingDispositionDecision, bool) {
	return FindingDispositionDecision{Disposition: r.disposition, Source: "test"}, true
}

func TestResolveFindingDispositionsKeepsFindingEvidence(t *testing.T) {
	original := sdk.Finding{ID: "CVE-1", Title: "title", Reasons: []string{"reason"}, PackageRef: "pkg:npm/example@1.0.0", Disposition: sdk.FindingDispositionFail}
	resolved := resolveFindingDispositions(context.Background(), []sdk.Finding{original}, nil, []FindingDispositionResolver{fixedDispositionResolver{disposition: sdk.FindingDispositionSuppressed}})
	if len(resolved) != 1 || resolved[0].Disposition != sdk.FindingDispositionSuppressed {
		t.Fatalf("resolved findings = %#v", resolved)
	}
	if resolved[0].ID != original.ID || resolved[0].Title != original.Title || len(resolved[0].Reasons) != 1 || resolved[0].PackageRef != original.PackageRef {
		t.Fatalf("resolver rewrote finding evidence: %#v", resolved[0])
	}
}

func TestResolveFindingDispositionsUsesLeastSuppressiveDecision(t *testing.T) {
	findings := []sdk.Finding{{ID: "one", Disposition: sdk.FindingDispositionFail}}
	resolved := resolveFindingDispositions(context.Background(), findings, nil, []FindingDispositionResolver{
		fixedDispositionResolver{disposition: sdk.FindingDispositionSuppressed},
		fixedDispositionResolver{disposition: sdk.FindingDispositionWarn},
	})
	if resolved[0].Disposition != sdk.FindingDispositionWarn {
		t.Fatalf("disposition = %q, want warn", resolved[0].Disposition)
	}
}
