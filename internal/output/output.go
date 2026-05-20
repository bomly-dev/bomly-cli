package output

import (
	"encoding/json"
	"fmt"
	"io"
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
)

// Renderers provides alternative renderers for human-readable formats.
type Renderers struct {
	Markdown func(io.Writer) error
	Text     func(io.Writer) error
}

// ParseFormat validates a format value.
func ParseFormat(value string) (Format, error) {
	switch Format(value) {
	case FormatJSON, FormatMarkdown, FormatText, FormatSARIF:
		return Format(value), nil
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
