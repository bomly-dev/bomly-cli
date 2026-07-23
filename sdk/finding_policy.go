package sdk

import "context"

// FindingPolicyDecision is a resolver's proposed policy status for one
// finding. Source and Reason provide diagnostic provenance.
type FindingPolicyDecision struct {
	Status FindingPolicyStatus
	Source string
	Reason string
}

// FindingPolicyResolver may refine a finding's policy status during auditing.
// Resolvers must not remove findings or rewrite their evidence.
type FindingPolicyResolver interface {
	ResolveFindingPolicy(context.Context, Finding, *PackageRegistry) (FindingPolicyDecision, bool)
}

// FindingPolicyStatusRank returns the enforcement rank for a finding policy
// status. An omitted status retains the historical fail behavior. The boolean
// is false for unknown values.
func FindingPolicyStatusRank(status FindingPolicyStatus) (int, bool) {
	switch status {
	case FindingPolicyStatusSuppressed:
		return 1, true
	case FindingPolicyStatusWarn:
		return 2, true
	case "", FindingPolicyStatusFail:
		return 3, true
	default:
		return 0, false
	}
}
