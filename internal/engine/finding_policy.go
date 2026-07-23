package engine

import (
	"context"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func resolveFindingPolicyStatuses(ctx context.Context, findings []sdk.Finding, registry *sdk.PackageRegistry, resolvers []sdk.FindingPolicyResolver) []sdk.Finding {
	if len(findings) == 0 || len(resolvers) == 0 {
		return findings
	}
	out := make([]sdk.Finding, len(findings))
	for idx, finding := range findings {
		out[idx] = finding.Clone()
		var selected sdk.FindingPolicyDecision
		selectedRank := 0
		matched := false
		for _, resolver := range resolvers {
			if resolver == nil {
				continue
			}
			decision, ok := resolver.ResolveFindingPolicy(ctx, out[idx], registry)
			rank, known := sdk.FindingPolicyStatusRank(decision.Status)
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
			out[idx].Disposition = selected.Status
		}
	}
	return out
}
