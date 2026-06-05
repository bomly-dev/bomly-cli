package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Format identifies a supported output format.
type Format string

const (
	// FormatJSON renders structured JSON output.
	FormatJSON Format = "json"
	// FormatMarkdown renders a Markdown report.
	FormatMarkdown Format = "markdown"
	// FormatText renders a human-readable text format.
	FormatText Format = "text"
	// FormatSARIF renders SARIF 2.1.0 output for vulnerability findings.
	FormatSARIF Format = "sarif"
	// FormatSPDX renders an SPDX 2.3 JSON SBOM.
	FormatSPDX Format = "spdx"
	// FormatCycloneDX renders a CycloneDX 1.6 JSON SBOM.
	FormatCycloneDX Format = "cyclonedx"
)

// IsSBOM reports whether the format is a standard SBOM artifact.
func (f Format) IsSBOM() bool {
	return f == FormatSPDX || f == FormatCycloneDX
}

// Renderers provides alternative renderers for human-readable formats.
type Renderers struct {
	Markdown func(io.Writer) error
	Text     func(io.Writer) error
}

// ParseFormat validates a format value.
func ParseFormat(value string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case string(FormatJSON):
		return FormatJSON, nil
	case string(FormatMarkdown), "md":
		return FormatMarkdown, nil
	case string(FormatText):
		return FormatText, nil
	case string(FormatSARIF):
		return FormatSARIF, nil
	case string(FormatSPDX), "spdx-json":
		return FormatSPDX, nil
	case string(FormatCycloneDX), "cyclonedx-json":
		return FormatCycloneDX, nil
	default:
		return "", fmt.Errorf("unsupported format %q", value)
	}
}

// Write renders payload in the requested format.
func Write(w io.Writer, format Format, payload any, renderers Renderers) error {
	switch format {
	case FormatJSON:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(payload)
	case FormatMarkdown:
		if renderers.Markdown == nil {
			return fmt.Errorf("markdown output is not implemented")
		}
		return renderers.Markdown(w)
	case FormatText:
		if renderers.Text == nil {
			return fmt.Errorf("text output is not implemented")
		}
		return renderers.Text(w)
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}
