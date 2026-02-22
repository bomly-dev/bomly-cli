//go:build bomly_builtin_syft

package sbom

import (
	"bytes"
	"fmt"

	syftjson "github.com/anchore/syft/syft/format/syftjson"
	"github.com/bomly/bomly-cli/internal/detectors"
	syftdetector "github.com/bomly/bomly-cli/internal/detectors/syft"
)

// decodeSyftJSONGraphs decodes a Syft-format JSON SBOM into a graph container
// using the Syft library directly.
func decodeSyftJSONGraphs(data []byte, sbomPath string) (*detectors.GraphContainer, error) {
	decoded, _, _, err := syftjson.NewFormatDecoder().Decode(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("decode syft sbom %q: %w", sbomPath, err)
	}
	graphs, err := syftdetector.GraphContainerFromSBOM(decoded, detectors.PackageManagerSBOM)
	if err != nil {
		return nil, fmt.Errorf("map syft sbom %q to graph: %w", sbomPath, err)
	}
	return graphs, nil
}
