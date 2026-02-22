//go:build bomly_external_syft

package sbom

import (
	"fmt"

	"github.com/bomly-dev/bomly-cli/internal/sbom"
	model "github.com/bomly-dev/bomly-cli/sdk"
)

// decodeSyftJSONGraphs falls back to generic SBOM parsing when the Syft library
// is not compiled in. This uses the standard SPDX/CycloneDX decoder path.
func decodeSyftJSONGraphs(data []byte, sbomPath string) (*model.GraphContainer, error) {
	doc, _, err := sbom.UnmarshalAutoJSON(data)
	if err != nil {
		return nil, fmt.Errorf("decode syft sbom %q (external mode): %w", sbomPath, err)
	}
	depsGraph, err := sbom.ToGraph(doc)
	if err != nil {
		return nil, fmt.Errorf("convert syft sbom %q to graph: %w", sbomPath, err)
	}
	return &model.GraphContainer{
		Entries: []model.GraphEntry{{
			Graph:    depsGraph,
			Manifest: model.ManifestMetadata{Kind: "sbom"},
		}},
	}, nil
}
