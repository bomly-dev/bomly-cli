//go:build bomly_external_syft

package sbom

import (
	"fmt"

	"github.com/bomly-dev/bomly-cli/internal/sbom"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// decodeSyftJSONGraphs falls back to generic SBOM parsing when the Syft library
// is not compiled in. This uses the standard SPDX/CycloneDX decoder path.
func decodeSyftJSONGraphs(data []byte, sbomPath string) (*sdk.GraphContainer, error) {
	doc, _, err := sbom.UnmarshalAutoJSON(data)
	if err != nil {
		return nil, fmt.Errorf("decode syft sbom %q (external mode): %w", sbomPath, err)
	}
	depsGraph, err := sbom.ToGraph(doc)
	if err != nil {
		return nil, fmt.Errorf("convert syft sbom %q to graph: %w", sbomPath, err)
	}
	return &sdk.GraphContainer{
		Entries: []sdk.GraphEntry{{
			Graph:    depsGraph,
			Manifest: sdk.ManifestMetadata{Kind: "sbom"},
		}},
	}, nil
}
