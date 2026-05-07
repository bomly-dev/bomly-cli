package engine

import (
	"github.com/bomly-dev/bomly-cli/internal/detectors"
	model "github.com/bomly-dev/bomly-cli/sdk"
)

// SingleGraphContainer wraps a single graph entry.
func SingleGraphContainer(g *model.Graph, manifest model.ManifestMetadata) *model.GraphContainer {
	return model.SingleGraphContainer(g, manifest)
}

// InferManifestMetadata determines the manifest metadata for detectors that naturally resolve one graph.
func InferManifestMetadata(req model.DetectionRequest, evidencePatterns []string) model.ManifestMetadata {
	return detectors.InferManifestMetadata(req, evidencePatterns)
}

// ConsolidatedGraphResult describes a merged view above per-subproject graph results.
type ConsolidatedGraphResult struct {
	ExecutionTarget model.ExecutionTarget
	Graph           *model.Graph
	Subprojects     []model.ConsolidatedSubproject
}

// ConsolidateGraphContainerEntry ensures one entry is present.
func ConsolidateGraphContainerEntry(container *model.GraphContainer) (*model.Graph, error) {
	return model.ConsolidateGraphContainerEntry(container)
}
