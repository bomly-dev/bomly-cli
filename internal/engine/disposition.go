package engine

import (
	"context"

	"github.com/bomly-dev/bomly-cli/sdk"
)

// FindingDispositionDecision is a resolver's proposed disposition for one
// finding. Source and Reason are diagnostic provenance and are not projected
// into report documents.
type FindingDispositionDecision struct {
	Disposition sdk.FindingDisposition
	Source      string
	Reason      string
}

// FindingDispositionResolver optionally refines finding dispositions as part
// of the audit stage. Resolvers never remove or rewrite finding evidence.
type FindingDispositionResolver interface {
	ResolveFinding(context.Context, sdk.Finding, *sdk.PackageRegistry) (FindingDispositionDecision, bool)
}

func resolveFindingDispositions(ctx context.Context, findings []sdk.Finding, registry *sdk.PackageRegistry, resolvers []FindingDispositionResolver) []sdk.Finding {
	if len(findings) == 0 || len(resolvers) == 0 {
		return findings
	}
	out := make([]sdk.Finding, len(findings))
	for idx, finding := range findings {
		out[idx] = finding.Clone()
		var selected FindingDispositionDecision
		matched := false
		for _, resolver := range resolvers {
			if resolver == nil {
				continue
			}
			decision, ok := resolver.ResolveFinding(ctx, out[idx], registry)
			if !ok || decision.Disposition == "" {
				continue
			}
			if !matched || dispositionRank(decision.Disposition) > dispositionRank(selected.Disposition) {
				selected = decision
				matched = true
			}
		}
		if matched {
			out[idx].Disposition = selected.Disposition
		}
	}
	return out
}

func dispositionRank(disposition sdk.FindingDisposition) int {
	switch disposition {
	case sdk.FindingDispositionSuppressed:
		return 1
	case sdk.FindingDispositionWarn:
		return 2
	case sdk.FindingDispositionFail:
		return 3
	default:
		return 4
	}
}
