package engine

import (
	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// SingleGraphContainer wraps a single graph entry.
func SingleGraphContainer(g *sdk.Graph, manifest sdk.ManifestMetadata) *sdk.GraphContainer {
	return sdk.SingleGraphContainer(g, manifest)
}

// InferManifestMetadata determines the manifest metadata for detectors that naturally resolve one graph.
func InferManifestMetadata(req sdk.DetectionRequest, evidencePatterns []string) sdk.ManifestMetadata {
	return detectors.InferManifestMetadata(req, evidencePatterns)
}

// ConsolidatedGraphResult describes a merged view above per-subproject graph results.
type ConsolidatedGraphResult struct {
	ExecutionTarget sdk.ExecutionTarget
	Graph           *sdk.Graph
	Subprojects     []sdk.ConsolidatedSubproject
}

// ConsolidateGraphContainerEntry ensures one entry is present.
func ConsolidateGraphContainerEntry(container *sdk.GraphContainer) (*sdk.Graph, error) {
	return sdk.ConsolidateGraphContainerEntry(container)
}
