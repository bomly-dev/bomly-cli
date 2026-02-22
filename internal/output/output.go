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

// VulnerabilityRef identifies one package vulnerability in command outputs.
type VulnerabilityRef struct {
	ID                   string               `json:"id"`
	Source               string               `json:"source"`
	Title                string               `json:"title,omitempty"`
	Severity             string               `json:"severity,omitempty"`
	SeveritySource       string               `json:"severity_source,omitempty"`
	Aliases              []string             `json:"aliases,omitempty"`
	Description          string               `json:"description,omitempty"`
	Reasons              []string             `json:"reasons,omitempty"`
	CVSS                 []model.CVSSScore    `json:"cvss,omitempty"`
	FixedIn              string               `json:"fixed_in,omitempty"`
	AffectedVersionRange string               `json:"affected_version_range,omitempty"`
	References           []model.Reference    `json:"references,omitempty"`
	KEVExploited         bool                 `json:"kev_exploited,omitempty"`
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
	Name            string             `json:"name"`
	Version         string             `json:"version,omitempty"`
	Scope           string             `json:"scope,omitempty"`
	Purl            string             `json:"purl,omitempty"`
	ID              string             `json:"id,omitempty"`
	Metadata        map[string]any     `json:"metadata,omitempty"`
	Licenses        []LicenseRef       `json:"licenses"`
	Vulnerabilities []VulnerabilityRef `json:"vulnerabilities"`
}

// Renderers provides alternative renderers for human-readable formats.
type Renderers struct {
	Text func(io.Writer) error
}

// PackageFromGraphPackage converts a model package into a package reference.
func PackageFromGraphPackage(pkg *model.Package) PackageRef {
	if pkg == nil {
		return PackageRef{Licenses: []LicenseRef{}, Vulnerabilities: []VulnerabilityRef{}}
	}
	ref := PackageRef{
		Name:            pkg.DisplayName(),
		Version:         pkg.Version,
		Scope:           pkg.Scope,
		Purl:            pkg.PURL,
		ID:              pkg.ID,
		Metadata:        cloneMetadata(pkg.Metadata),
		Licenses:        LicenseRefsFromGraphLicenses(pkg.Licenses),
		Vulnerabilities: VulnerabilityRefsFromPackageVulnerabilities(pkg.Vulnerabilities),
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

// VulnerabilityRefsFromPackageVulnerabilities converts package vulnerability enrichment into output-friendly values.
func VulnerabilityRefsFromPackageVulnerabilities(vulnerabilities []model.PackageVulnerability) []VulnerabilityRef {
	if len(vulnerabilities) == 0 {
		return []VulnerabilityRef{}
	}
	out := make([]VulnerabilityRef, 0, len(vulnerabilities))
	for _, vulnerability := range vulnerabilities {
		out = append(out, VulnerabilityRef{
			ID:                   vulnerability.ID,
			Source:               vulnerability.Source,
			Title:                vulnerability.Title,
			Severity:             vulnerability.Severity,
			SeveritySource:       vulnerability.SeveritySource,
			Aliases:              append([]string(nil), vulnerability.Aliases...),
			Description:          vulnerability.Description,
			Reasons:              append([]string(nil), vulnerability.Reasons...),
			CVSS:                 append([]model.CVSSScore(nil), vulnerability.CVSS...),
			FixedIn:              vulnerability.FixedIn,
			AffectedVersionRange: vulnerability.AffectedVersionRange,
			References:           append([]model.Reference(nil), vulnerability.References...),
			KEVExploited:         vulnerability.KEVExploited,
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
