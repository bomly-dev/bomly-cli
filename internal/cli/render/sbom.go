package render

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/sbom"
)

// SBOMOutputSpec describes one parsed -o argument: an output format (target +
// human-readable label) and the destination path (empty path means stdout).
type SBOMOutputSpec struct {
	Target sbom.Target
	Label  string
	Path   string
}

// ParseSBOMFormat normalizes a user-supplied format string ("spdx-json",
// "cyclonedx-json") into a target codec plus the canonical label.
func ParseSBOMFormat(value string) (sbom.Target, string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "spdx-json":
		return sbom.TargetSPDX23JSON, "spdx-json", nil
	case "cyclonedx-json":
		return sbom.TargetCycloneDX16JSON, "cyclonedx-json", nil
	default:
		return "", "", fmt.Errorf("unsupported sbom format %q", value)
	}
}

// ParseSBOMOutputSpecs parses one or more -o values of the form
// "<format>[=<path>]". At most one entry may target stdout (omitted path).
func ParseSBOMOutputSpecs(values []string) ([]SBOMOutputSpec, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("at least one -o <format>[=<path>] output is required")
	}

	specs := make([]SBOMOutputSpec, 0, len(values))
	stdoutCount := 0
	for _, value := range values {
		rawValue := strings.TrimSpace(value)
		if rawValue == "" {
			return nil, fmt.Errorf("sbom output cannot be empty")
		}

		formatValue, pathValue, hasPath := strings.Cut(rawValue, "=")
		target, label, err := ParseSBOMFormat(formatValue)
		if err != nil {
			return nil, err
		}

		spec := SBOMOutputSpec{Target: target, Label: label}
		if hasPath {
			spec.Path = strings.TrimSpace(pathValue)
			if spec.Path == "" {
				return nil, fmt.Errorf("sbom output %q is missing a file path", rawValue)
			}
		} else {
			stdoutCount++
		}
		specs = append(specs, spec)
	}

	if stdoutCount > 1 {
		return nil, fmt.Errorf("multiple stdout sbom outputs are not supported")
	}

	return specs, nil
}

// WriteSBOMDocument writes a generated SBOM document to spec.Path (or to
// stdout when spec.Path is empty).
func WriteSBOMDocument(stdout io.Writer, spec SBOMOutputSpec, document []byte) error {
	if spec.Path == "" {
		if _, err := stdout.Write(document); err != nil {
			return fmt.Errorf("write %s sbom to stdout: %w", spec.Label, err)
		}
		if _, err := io.WriteString(stdout, "\n"); err != nil {
			return fmt.Errorf("terminate %s sbom output: %w", spec.Label, err)
		}
		return nil
	}

	if err := os.WriteFile(spec.Path, append(document, '\n'), 0o644); err != nil {
		return fmt.Errorf("write %s sbom to %s: %w", spec.Label, spec.Path, err)
	}
	return nil
}
