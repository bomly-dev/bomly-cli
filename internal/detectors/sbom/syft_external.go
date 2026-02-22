//go:build !bomly_builtin_syft

package sbom

import (
	"fmt"

	"github.com/bomly/bomly-cli/internal/detectors"
	bomlysbom "github.com/bomly/bomly-cli/internal/sbom"
)

// decodeSyftJSONGraphs falls back to generic SBOM parsing when the Syft library
// is not compiled in. This uses the standard SPDX/CycloneDX decoder path.
func decodeSyftJSONGraphs(data []byte, sbomPath string) (*detectors.GraphContainer, error) {
	doc, _, err := bomlysbom.UnmarshalAutoJSON(data)
	if err != nil {
		return nil, fmt.Errorf("decode syft sbom %q (external mode): %w", sbomPath, err)
	}
	depsGraph, err := bomlysbom.ToGraph(doc)
	if err != nil {
		return nil, fmt.Errorf("convert syft sbom %q to graph: %w", sbomPath, err)
	}
	return &detectors.GraphContainer{
		Entries: []detectors.GraphEntry{{
			Graph:    depsGraph,
			Manifest: detectors.ManifestMetadata{Kind: "sbom"},
		}},
	}, nil
}
