package sbom

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/bomly-dev/bomly-cli/sdk"
)

var (
	ErrNilDocument       = errors.New("sbom document is nil")
	ErrUnsupportedTarget = errors.New("unsupported sbom target")
	ErrUnsupportedFormat = errors.New("unsupported sbom format")
	ErrMalformedJSON     = errors.New("malformed sbom json")
)

type codec interface {
	encodeJSON(doc *Document, opts EncodeOptions) ([]byte, error)
	decodeJSON(data []byte) (*Document, error)
}

var codecs = map[Target]codec{
	TargetSPDX23JSON:      spdx23Codec{},
	TargetCycloneDX14JSON: cycloneDXCodec{version: TargetCycloneDX14JSON},
	TargetCycloneDX15JSON: cycloneDXCodec{version: TargetCycloneDX15JSON},
	TargetCycloneDX16JSON: cycloneDXCodec{version: TargetCycloneDX16JSON},
}

// MarshalJSON renders the intermediate SBOM document to a target JSON format.
func MarshalJSON(doc *Document, target Target, opts EncodeOptions) ([]byte, error) {
	if doc == nil {
		return nil, ErrNilDocument
	}
	c, ok := codecs[target]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedTarget, target)
	}
	return c.encodeJSON(doc, opts)
}

// UnmarshalJSON parses a target JSON SBOM into the intermediate document model.
func UnmarshalJSON(data []byte, target Target) (*Document, error) {
	c, ok := codecs[target]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedTarget, target)
	}
	return c.decodeJSON(data)
}

// DetectJSONTarget identifies the supported SBOM JSON format represented by data.
func DetectJSONTarget(data []byte) (Target, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || !json.Valid(trimmed) {
		return "", ErrMalformedJSON
	}

	if id, _ := syftjson.NewFormatDecoder().Identify(bytes.NewReader(trimmed)); id == syftjson.ID {
		return TargetSyftJSON, nil
	}

	var sniff struct {
		SPDXVersion string `json:"spdxVersion"`
		BOMFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
	}
	if err := json.Unmarshal(trimmed, &sniff); err != nil {
		return "", ErrMalformedJSON
	}

	switch {
	case sniff.SPDXVersion == "SPDX-2.3":
		return TargetSPDX23JSON, nil
	case sniff.BOMFormat == "CycloneDX":
		switch sniff.SpecVersion {
		case "1.4":
			return TargetCycloneDX14JSON, nil
		case "1.5":
			return TargetCycloneDX15JSON, nil
		case "1.6":
			return TargetCycloneDX16JSON, nil
		}
		return "", ErrUnsupportedFormat
	}

	return "", ErrUnsupportedFormat
}

// UnmarshalAutoJSON parses a supported SBOM JSON payload without requiring the caller to preselect a target.
func UnmarshalAutoJSON(data []byte) (*Document, Target, error) {
	target, err := DetectJSONTarget(data)
	if err != nil {
		return nil, "", err
	}
	if target == TargetSyftJSON {
		return nil, target, nil
	}

	doc, err := UnmarshalJSON(data, target)
	if err != nil {
		return nil, "", err
	}
	return doc, target, nil
}

// MarshalDepGraphJSON converts a dependency graph directly into a target JSON SBOM.
func MarshalDepGraphJSON(g *sdk.Graph, target Target, buildOpts BuildOptions, encodeOpts EncodeOptions) ([]byte, error) {
	doc, err := FromDepGraph(g, buildOpts)
	if err != nil {
		return nil, err
	}
	return MarshalJSON(doc, target, encodeOpts)
}
