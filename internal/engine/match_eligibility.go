package engine

import (
	"fmt"

	"github.com/bomly-dev/bomly-sdk"
)

// registryMatchRequest builds the matcher-facing graph without mutating the
// complete pipeline graph or package registry retained for later stages.
func registryMatchRequest(req sdk.MatchRequest) (sdk.MatchRequest, error) {
	filtered := sdk.New()
	if req.Graph == nil {
		req.Graph = filtered
		return req, nil
	}

	eligible := make(map[string]*sdk.DependencyNode)
	for _, dependency := range req.Graph.DependencyNodes() {
		if !dependency.RegistryMatchEligible() {
			continue
		}
		clone := dependency.Clone()
		if err := filtered.AddNode(clone); err != nil {
			return sdk.MatchRequest{}, fmt.Errorf("add registry-match dependency %q: %w", dependency.NodeID(), err)
		}
		eligible[dependency.NodeID()] = clone
	}
	var edgeErr error
	req.Graph.WalkEdges(func(from, to sdk.GraphNode) bool {
		if _, ok := eligible[from.NodeID()]; !ok {
			return true
		}
		if _, ok := eligible[to.NodeID()]; !ok {
			return true
		}
		if err := filtered.AddEdge(from.NodeID(), to.NodeID()); err != nil {
			edgeErr = fmt.Errorf("add registry-match dependency edge %q -> %q: %w", from.NodeID(), to.NodeID(), err)
		}
		return edgeErr == nil
	})
	if edgeErr != nil {
		return sdk.MatchRequest{}, edgeErr
	}

	if req.Target != nil {
		target, ok := eligible[req.Target.NodeID()]
		if !ok {
			// A targeted match must never widen to all other eligible
			// packages when the requested node itself is ineligible.
			req.Graph = sdk.New()
			req.Target = nil
			return req, nil
		}
		req.Target = target
	}
	req.Graph = filtered
	return req, nil
}
