package engine

import (
	"fmt"

	"github.com/bomly-dev/bomly-cli/sdk"
)

// registryMatchRequest builds the matcher-facing graph without mutating the
// complete pipeline graph or package registry retained for later stages.
func registryMatchRequest(req sdk.MatchRequest) (sdk.MatchRequest, error) {
	filtered := sdk.New()
	if req.Graph == nil {
		req.Graph = filtered
		return req, nil
	}

	eligible := make(map[string]*sdk.Dependency)
	for _, dependency := range req.Graph.Nodes() {
		if !dependency.RegistryMatchEligible() {
			continue
		}
		clone := dependency.Clone()
		if err := filtered.AddNode(clone); err != nil {
			return sdk.MatchRequest{}, fmt.Errorf("add registry-match dependency %q: %w", dependency.ID, err)
		}
		eligible[dependency.ID] = clone
	}
	var edgeErr error
	req.Graph.WalkEdges(func(from, to *sdk.Dependency) bool {
		if _, ok := eligible[from.ID]; !ok {
			return true
		}
		if _, ok := eligible[to.ID]; !ok {
			return true
		}
		if err := filtered.AddEdge(from.ID, to.ID); err != nil {
			edgeErr = fmt.Errorf("add registry-match dependency edge %q -> %q: %w", from.ID, to.ID, err)
		}
		return edgeErr == nil
	})
	if edgeErr != nil {
		return sdk.MatchRequest{}, edgeErr
	}

	if req.Target != nil {
		target, ok := eligible[req.Target.ID]
		if !ok {
			// A targeted match must never widen to all other eligible packages
			// when the requested occurrence itself is ineligible.
			req.Graph = sdk.New()
			req.Target = nil
			return req, nil
		}
		req.Target = target
	}
	req.Graph = filtered
	return req, nil
}
