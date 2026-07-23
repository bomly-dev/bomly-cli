package engine

import (
	"context"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

type fixedPolicyResolver struct{ status sdk.FindingPolicyStatus }

func (r fixedPolicyResolver) ResolveFindingPolicy(context.Context, sdk.Finding, *sdk.PackageRegistry) (sdk.FindingPolicyDecision, bool) {
	return sdk.FindingPolicyDecision{Status: r.status, Source: "test"}, true
}

func TestResolveFindingPolicyStatusesKeepsFindingEvidence(t *testing.T) {
	original := sdk.Finding{ID: "CVE-1", Title: "title", Reasons: []string{"reason"}, PackageRef: "pkg:npm/example@1.0.0", PolicyStatus: sdk.FindingPolicyStatusFail}
	resolved := resolveFindingPolicyStatuses(context.Background(), []sdk.Finding{original}, nil, []sdk.FindingPolicyResolver{fixedPolicyResolver{status: sdk.FindingPolicyStatusSuppressed}})
	if len(resolved) != 1 || resolved[0].PolicyStatus != sdk.FindingPolicyStatusSuppressed {
		t.Fatalf("resolved findings = %#v", resolved)
	}
	if resolved[0].ID != original.ID || resolved[0].Title != original.Title || len(resolved[0].Reasons) != 1 || resolved[0].PackageRef != original.PackageRef {
		t.Fatalf("resolver rewrote finding evidence: %#v", resolved[0])
	}
}

func TestResolveFindingPolicyStatusesUsesLeastSuppressiveDecision(t *testing.T) {
	findings := []sdk.Finding{{ID: "one", PolicyStatus: sdk.FindingPolicyStatusFail}}
	resolved := resolveFindingPolicyStatuses(context.Background(), findings, nil, []sdk.FindingPolicyResolver{
		fixedPolicyResolver{status: sdk.FindingPolicyStatusSuppressed},
		fixedPolicyResolver{status: sdk.FindingPolicyStatusWarn},
	})
	if resolved[0].PolicyStatus != sdk.FindingPolicyStatusWarn {
		t.Fatalf("policy status = %q, want warn", resolved[0].PolicyStatus)
	}
}

func TestResolveFindingPolicyStatusesRejectsUnknownStatus(t *testing.T) {
	findings := []sdk.Finding{{ID: "one", PolicyStatus: sdk.FindingPolicyStatusFail}}
	resolved := resolveFindingPolicyStatuses(context.Background(), findings, nil, []sdk.FindingPolicyResolver{
		fixedPolicyResolver{status: sdk.FindingPolicyStatus("invalid")},
	})
	if resolved[0].PolicyStatus != sdk.FindingPolicyStatusFail {
		t.Fatalf("policy status = %q, want fail", resolved[0].PolicyStatus)
	}
}

func TestApplyFindingPolicyLogsBaselineEvaluationStats(t *testing.T) {
	core, observed := observer.New(zap.InfoLevel)
	pipeline := NewPipeline(nil, zap.New(core))
	findings := []sdk.Finding{{ID: "one", PolicyStatus: sdk.FindingPolicyStatusFail}}
	resolved := pipeline.applyFindingPolicy(context.Background(), findings, nil, PipelineRequest{
		FindingPolicyResolvers: []sdk.FindingPolicyResolver{
			fixedPolicyResolver{status: sdk.FindingPolicyStatusSuppressed},
		},
		BaselineEvaluation: &BaselineEvaluation{
			Path:      "/checkout/.bomly/baseline.json",
			Entries:   4,
			Automatic: true,
		},
	})
	if resolved[0].PolicyStatus != sdk.FindingPolicyStatusSuppressed {
		t.Fatalf("policy status = %q, want suppressed", resolved[0].PolicyStatus)
	}
	logs := observed.FilterMessage("baseline: policy evaluation completed")
	if logs.Len() != 1 {
		t.Fatalf("baseline evaluation logs = %#v", observed.All())
	}
	fields := logs.All()[0].ContextMap()
	if fields["entries"] != int64(4) || fields["findings_evaluated"] != int64(1) || fields["findings_accepted"] != int64(1) || fields["automatic"] != true {
		t.Fatalf("baseline evaluation stats = %#v", fields)
	}
}
