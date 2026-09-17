package engine

import (
	"context"

	"github.com/bomly-dev/bomly-sdk/model"
)

func resolveFindingPolicyStatuses(ctx context.Context, findings []model.Finding, registry *model.PackageRegistry, resolvers []model.FindingPolicyResolver) []model.Finding {
	if len(findings) == 0 || len(resolvers) == 0 {
		return findings
	}
	out := make([]model.Finding, len(findings))
	for idx, finding := range findings {
		out[idx] = finding.Clone()
		var selected model.FindingPolicyDecision
		selectedRank := 0
		matched := false
		for _, resolver := range resolvers {
			if resolver == nil {
				continue
			}
			decision, ok := resolver.ResolveFindingPolicy(ctx, out[idx], registry)
			rank, known := model.FindingPolicyStatusRank(decision.Status)
			if !ok || decision.Status == "" || !known {
				continue
			}
			if !matched || rank > selectedRank {
				selected = decision
				selectedRank = rank
				matched = true
			}
		}
		if matched {
			out[idx].PolicyStatus = selected.Status
		}
	}
	return out
}
