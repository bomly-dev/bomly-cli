//go:build !bomly_external_syft

package sbom

import (
	"bytes"
	"fmt"

	"github.com/anchore/syft/syft/format/syftjson"
	syftdetector "github.com/bomly-dev/bomly-cli/internal/detectors/syft"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// decodeSyftJSONGraphs decodes a Syft-format JSON SBOM into a graph container
// using the Syft library directly.
func decodeSyftJSONGraphs(data []byte, sbomPath string) (*sdk.GraphContainer, error) {
	decoded, _, _, err := syftjson.NewFormatDecoder().Decode(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("decode syft sbom %q: %w", sbomPath, err)
	}
	graphs, err := syftdetector.GraphContainerFromSBOM(decoded, sdk.PackageManagerSBOM)
	if err != nil {
		return nil, fmt.Errorf("map syft sbom %q to graph: %w", sbomPath, err)
	}
	return graphs, nil
}
