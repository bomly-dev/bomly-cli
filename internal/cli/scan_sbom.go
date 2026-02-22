package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/sbom"
)

type sbomOutputSpec struct {
	target sbom.Target
	label  string
	path   string
}

func parseSBOMFormat(value string) (sbom.Target, string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "spdx-json":
		return sbom.TargetSPDX23JSON, "spdx-json", nil
	case "cyclonedx-json":
		return sbom.TargetCycloneDX16JSON, "cyclonedx-json", nil
	default:
		return "", "", fmt.Errorf("unsupported sbom format %q", value)
	}
}

func parseSBOMOutputSpecs(values []string) ([]sbomOutputSpec, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("at least one -o <format>[=<path>] output is required")
	}

	specs := make([]sbomOutputSpec, 0, len(values))
	stdoutCount := 0
	for _, value := range values {
		rawValue := strings.TrimSpace(value)
		if rawValue == "" {
			return nil, fmt.Errorf("sbom output cannot be empty")
		}

		formatValue, pathValue, hasPath := strings.Cut(rawValue, "=")
		target, label, err := parseSBOMFormat(formatValue)
		if err != nil {
			return nil, err
		}

		spec := sbomOutputSpec{target: target, label: label}
		if hasPath {
			spec.path = strings.TrimSpace(pathValue)
			if spec.path == "" {
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

func writeSBOMDocument(stdout io.Writer, spec sbomOutputSpec, document []byte) error {
	if spec.path == "" {
		if _, err := stdout.Write(document); err != nil {
			return fmt.Errorf("write %s sbom to stdout: %w", spec.label, err)
		}
		if _, err := io.WriteString(stdout, "\n"); err != nil {
			return fmt.Errorf("terminate %s sbom output: %w", spec.label, err)
		}
		return nil
	}

	if err := os.WriteFile(spec.path, append(document, '\n'), 0o644); err != nil {
		return fmt.Errorf("write %s sbom to %s: %w", spec.label, spec.path, err)
	}
	return nil
}
