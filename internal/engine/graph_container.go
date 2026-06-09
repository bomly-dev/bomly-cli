package engine

import (
	"github.com/bomly-dev/bomly-cli/sdk"
)

// SingleGraphContainer wraps a single graph entry.
func SingleGraphContainer(g *sdk.Graph, manifest sdk.ManifestMetadata) *sdk.GraphContainer {
	return sdk.SingleGraphContainer(g, manifest)
}

// ConsolidatedGraphResult describes a merged view above per-subproject graph results.
type ConsolidatedGraphResult struct {
	ExecutionTarget sdk.ExecutionTarget
	Graph           *sdk.Graph
	Subprojects     []sdk.ConsolidatedSubproject
}
