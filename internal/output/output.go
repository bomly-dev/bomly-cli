package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/bomly/bomly-cli/internal/model"
)

// SchemaVersion is the current CLI output schema version.
const SchemaVersion = "1.0"

// Format identifies a supported output format.
type Format string

const (
	// FormatJSON renders structured JSON output.
	FormatJSON Format = "json"
	// FormatText renders a human-readable text format.
	FormatText Format = "text"
	// FormatSARIF renders SARIF 2.1.0 output for vulnerability findings.
	FormatSARIF Format = "sarif"
)

// Metadata captures execution metadata shared by all command outputs.
type Metadata struct {
	DurationMS int64 `json:"duration_ms"`
}

// ProjectDescriptor describes the project being analyzed.
type ProjectDescriptor struct {
	Name           string `json:"name,omitempty"`
	Path           string `json:"path"`
	Ecosystem      string `json:"ecosystem"`
	PackageManager string `json:"package_manager,omitempty"`
}

// LicenseRef identifies one package license in command outputs.
type LicenseRef struct {
	Value          string `json:"value,omitempty"`
	SPDXExpression string `json:"spdxExpression,omitempty"`
	Type           string `json:"type,omitempty"`
}

// Identifier returns the most useful license identifier for display.
func (l LicenseRef) Identifier() string {
	switch {
	case strings.TrimSpace(l.SPDXExpression) != "":
		return strings.TrimSpace(l.SPDXExpression)
	case strings.TrimSpace(l.Value) != "":
		return strings.TrimSpace(l.Value)
	default:
		return ""
	}
}

// PackageRef identifies a package in command outputs.
type PackageRef struct {
	Name     string         `json:"name"`
	Version  string         `json:"version,omitempty"`
	Scope    string         `json:"scope,omitempty"`
	Purl     string         `json:"purl,omitempty"`
	ID       string         `json:"id,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
	Licenses []LicenseRef   `json:"licenses"`
}

// Renderers provides alternative renderers for human-readable formats.
type Renderers struct {
	Text func(io.Writer) error
}

// PackageFromGraphPackage converts a model package into a package reference.
func PackageFromGraphPackage(pkg *model.Package) PackageRef {
	if pkg == nil {
		return PackageRef{Licenses: []LicenseRef{}}
	}
	ref := PackageRef{
		Name:     pkg.DisplayName(),
		Version:  pkg.Version,
		Scope:    pkg.Scope,
		Purl:     pkg.PURL,
		ID:       pkg.ID,
		Metadata: cloneMetadata(pkg.Metadata),
		Licenses: LicenseRefsFromGraphLicenses(pkg.Licenses),
	}
	return ref
}

func cloneMetadata(src map[string]any) map[string]any {
	if len(src) == 0 {
		return nil
	}
	clone := make(map[string]any, len(src))
	for key, value := range src {
		clone[key] = value
	}
	return clone
}

// LicenseRefsFromGraphLicenses converts graph licenses into output-friendly values.
func LicenseRefsFromGraphLicenses(licenses []model.PackageLicense) []LicenseRef {
	if len(licenses) == 0 {
		return []LicenseRef{}
	}
	out := make([]LicenseRef, 0, len(licenses))
	for _, license := range licenses {
		out = append(out, LicenseRef{
			Value:          license.Value,
			SPDXExpression: license.SPDXExpression,
			Type:           license.Type,
		})
	}
	return out
}

// ParseFormat validates a format value.
func ParseFormat(value string) (Format, error) {
	switch Format(value) {
	case FormatJSON, FormatText, FormatSARIF:
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
	case FormatText:
		if renderers.Text == nil {
			return fmt.Errorf("text output is not implemented")
		}
		return renderers.Text(w)
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}
