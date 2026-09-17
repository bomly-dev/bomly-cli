package engine

import (
	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

// SingleGraphContainer wraps a single graph entry.
func SingleGraphContainer(g *model.Graph, manifest model.ManifestMetadata) *model.GraphContainer {
	return model.SingleGraphContainer(g, manifest)
}

// ConsolidatedGraphResult describes a merged view above per-subproject graph results.
type ConsolidatedGraphResult struct {
	ExecutionTarget plugin.ExecutionTarget
	Graph           *model.Graph
	Subprojects     []plugin.ConsolidatedSubproject
}
