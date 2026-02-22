package scan

import (
	"errors"

	"github.com/bomly/bomly-cli/internal/detectors"
	"github.com/bomly/bomly-cli/internal/model"
)

// ManifestMetadata is an alias for model.ManifestMetadata.
type ManifestMetadata = model.ManifestMetadata

// GraphEntry is an alias for model.GraphEntry.
type GraphEntry = model.GraphEntry

// GraphContainer is an alias for model.GraphContainer.
type GraphContainer = model.GraphContainer

// SingleGraphContainer wraps a single graph entry.
func SingleGraphContainer(g *model.Graph, manifest ManifestMetadata) *GraphContainer {
	return detectors.SingleGraphContainer(g, manifest)
}

// InferManifestMetadata determines the manifest metadata for detectors that naturally resolve one graph.
func InferManifestMetadata(req ResolveGraphRequest) ManifestMetadata {
	return detectors.InferManifestMetadata(req)
}

// ConsolidatedGraphResult describes a merged view above per-subproject graph results.
type ConsolidatedGraphResult struct {
	ExecutionTarget ExecutionTarget
	Graph           *model.Graph
	Subprojects     []ConsolidatedSubproject
}

// ConsolidateGraphContainerEntry ensures one entry is present.
func ConsolidateGraphContainerEntry(container *GraphContainer) (*model.Graph, error) {
	return model.ConsolidateGraphContainerEntry(container)
}

func validateGraphEntry(entry GraphEntry) error {
	if entry.Graph == nil {
		return errors.New("graph entry graph is nil")
	}
	return nil
}
