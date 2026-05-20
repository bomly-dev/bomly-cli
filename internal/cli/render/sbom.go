package render

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/sbom"
)

// OutputFormat identifies one additional output target.
type OutputFormat string

const (
	OutputFormatMarkdown  OutputFormat = "markdown"
	OutputFormatSARIF     OutputFormat = "sarif"
	OutputFormatSPDX      OutputFormat = "spdx"
	OutputFormatCycloneDX OutputFormat = "cyclonedx"
)

// OutputSpec describes one parsed -o argument: an output format and the
// destination path (empty path means stdout).
type OutputSpec struct {
	Format OutputFormat
	Target sbom.Target
	Label  string
	Path   string
}

// IsSBOM reports whether this output is a standard SBOM artifact.
func (s OutputSpec) IsSBOM() bool {
	return s.Format == OutputFormatSPDX || s.Format == OutputFormatCycloneDX
}

// ParseOutputFormat normalizes a user-supplied output format string.
func ParseOutputFormat(value string) (OutputFormat, sbom.Target, string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "markdown", "md":
		return OutputFormatMarkdown, "", "markdown", nil
	case "sarif":
		return OutputFormatSARIF, "", "sarif", nil
	case "spdx", "spdx-json":
		return OutputFormatSPDX, sbom.TargetSPDX23JSON, "spdx", nil
	case "cyclonedx", "cyclonedx-json":
		return OutputFormatCycloneDX, sbom.TargetCycloneDX16JSON, "cyclonedx", nil
	default:
		return "", "", "", fmt.Errorf("unsupported output format %q", value)
	}
}

// ParseOutputSpecs parses one or more -o values of the form
// "<format>[=<path>]". At most one entry may target stdout (omitted path).
func ParseOutputSpecs(values []string) ([]OutputSpec, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("at least one -o <format>[=<path>] output is required")
	}

	specs := make([]OutputSpec, 0, len(values))
	stdoutCount := 0
	for _, value := range values {
		rawValue := strings.TrimSpace(value)
		if rawValue == "" {
			return nil, fmt.Errorf("output target cannot be empty")
		}

		formatValue, pathValue, hasPath := strings.Cut(rawValue, "=")
		format, target, label, err := ParseOutputFormat(formatValue)
		if err != nil {
			return nil, err
		}

		spec := OutputSpec{Format: format, Target: target, Label: label}
		if hasPath {
			spec.Path = strings.TrimSpace(pathValue)
			if spec.Path == "" {
				return nil, fmt.Errorf("output target %q is missing a file path", rawValue)
			}
		} else {
			stdoutCount++
		}
		specs = append(specs, spec)
	}

	if stdoutCount > 1 {
		return nil, fmt.Errorf("multiple stdout outputs are not supported")
	}

	return specs, nil
}

// WriteOutputDocument writes a generated document to spec.Path (or to
// stdout when spec.Path is empty).
func WriteOutputDocument(stdout io.Writer, spec OutputSpec, document []byte) error {
	if spec.Path == "" {
		if _, err := stdout.Write(document); err != nil {
			return fmt.Errorf("write %s output to stdout: %w", spec.Label, err)
		}
		if _, err := io.WriteString(stdout, "\n"); err != nil {
			return fmt.Errorf("terminate %s output: %w", spec.Label, err)
		}
		return nil
	}

	if parent := strings.TrimSpace(filepath.Dir(spec.Path)); parent != "." && parent != "" {
		if err := os.MkdirAll(parent, 0o755); err != nil {
			return fmt.Errorf("create %s output directory: %w", spec.Label, err)
		}
	}
	if err := os.WriteFile(spec.Path, append(document, '\n'), 0o644); err != nil {
		return fmt.Errorf("write %s output to %s: %w", spec.Label, spec.Path, err)
	}
	return nil
}
