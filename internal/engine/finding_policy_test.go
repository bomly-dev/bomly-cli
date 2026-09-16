package engine

import (
	"context"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/bomly-dev/bomly-sdk/model"
)

type fixedPolicyResolver struct{ status model.FindingPolicyStatus }

func (r fixedPolicyResolver) ResolveFindingPolicy(context.Context, model.Finding, *model.PackageRegistry) (model.FindingPolicyDecision, bool) {
	return model.FindingPolicyDecision{Status: r.status, Source: "test"}, true
}

func TestResolveFindingPolicyStatusesKeepsFindingEvidence(t *testing.T) {
	original := model.Finding{ID: "CVE-1", Title: "title", Reasons: []string{"reason"}, PackageRef: "pkg:npm/example@1.0.0", PolicyStatus: model.FindingPolicyStatusFail}
	resolved := resolveFindingPolicyStatuses(context.Background(), []model.Finding{original}, nil, []model.FindingPolicyResolver{fixedPolicyResolver{status: model.FindingPolicyStatusSuppressed}})
	if len(resolved) != 1 || resolved[0].PolicyStatus != model.FindingPolicyStatusSuppressed {
		t.Fatalf("resolved findings = %#v", resolved)
	}
	if resolved[0].ID != original.ID || resolved[0].Title != original.Title || len(resolved[0].Reasons) != 1 || resolved[0].PackageRef != original.PackageRef {
		t.Fatalf("resolver rewrote finding evidence: %#v", resolved[0])
	}
}

func TestResolveFindingPolicyStatusesUsesLeastSuppressiveDecision(t *testing.T) {
	findings := []model.Finding{{ID: "one", PolicyStatus: model.FindingPolicyStatusFail}}
	resolved := resolveFindingPolicyStatuses(context.Background(), findings, nil, []model.FindingPolicyResolver{
		fixedPolicyResolver{status: model.FindingPolicyStatusSuppressed},
		fixedPolicyResolver{status: model.FindingPolicyStatusWarn},
	})
	if resolved[0].PolicyStatus != model.FindingPolicyStatusWarn {
		t.Fatalf("policy status = %q, want warn", resolved[0].PolicyStatus)
	}
}

func TestResolveFindingPolicyStatusesRejectsUnknownStatus(t *testing.T) {
	findings := []model.Finding{{ID: "one", PolicyStatus: model.FindingPolicyStatusFail}}
	resolved := resolveFindingPolicyStatuses(context.Background(), findings, nil, []model.FindingPolicyResolver{
		fixedPolicyResolver{status: model.FindingPolicyStatus("invalid")},
	})
	if resolved[0].PolicyStatus != model.FindingPolicyStatusFail {
		t.Fatalf("policy status = %q, want fail", resolved[0].PolicyStatus)
	}
}

func TestApplyFindingPolicyLogsBaselineEvaluationStats(t *testing.T) {
	core, observed := observer.New(zap.InfoLevel)
	pipeline := NewPipeline(nil, zap.New(core))
	findings := []model.Finding{{ID: "one", PolicyStatus: model.FindingPolicyStatusFail}}
	resolved := pipeline.applyFindingPolicy(context.Background(), findings, nil, PipelineRequest{
		FindingPolicyResolvers: []model.FindingPolicyResolver{
			fixedPolicyResolver{status: model.FindingPolicyStatusSuppressed},
		},
		BaselineEvaluation: &BaselineEvaluation{
			Path:      "/checkout/.bomly/baseline.json",
			Entries:   4,
			Automatic: true,
		},
	})
	if resolved[0].PolicyStatus != model.FindingPolicyStatusSuppressed {
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
