package sbom

import (
	"time"

	"github.com/bomly-dev/bomly-cli/sdk"
)

// Target identifies an SBOM wire format target.
type Target string

const (
	TargetSPDX23JSON      Target = "spdx-2.3+json"
	TargetCycloneDX14JSON Target = "cyclonedx-1.4+json"
	TargetCycloneDX15JSON Target = "cyclonedx-1.5+json"
	TargetCycloneDX16JSON Target = "cyclonedx-1.6+json"
	TargetCycloneDX17JSON Target = "cyclonedx-1.7+json"
	TargetSyftJSON        Target = "syft+json"
	defaultDocumentName          = "bomly-dependencies"
	defaultToolName              = "bomly-cli"
)

// BuildOptions controls how a depgraph is projected into the intermediate SBOM model.
type BuildOptions struct {
	DocumentName    string
	DocumentNS      string
	ToolName        string
	ToolNames       []string
	Created         time.Time
	RootComponentID string
	SerialNumber    string

	// Registry, when non-nil, supplies matching-stage enrichment (licenses,
	// vulnerabilities, CPEs, digests, EOL) resolved by PURL and folded onto
	// each component during projection.
	Registry *sdk.PackageRegistry
}

// EncodeOptions controls JSON output formatting.
type EncodeOptions struct {
	Pretty bool
}

// Document is an intermediate, format-agnostic SBOM representation.
type Document struct {
	Name         string
	Namespace    string
	Tool         string
	Tools        []string
	Created      time.Time
	SerialNumber string

	Components   []Component
	Dependencies []Dependency
	Roots        []string
}

// Component describes one package surfaced in the intermediate SBOM model.
type Component struct {
	ID             string
	Name           string
	Version        string
	Scope          string
	PURL           string
	Ecosystem      string
	PackageManager string
	Type           string
	Copyright      string
	Licenses       []License

	// Matching-stage enrichment (populated when BuildOptions.Registry is set).
	CPEs            []string
	Digests         []Digest
	Vulnerabilities []Vulnerability
	EOL             *EOL
}

// Dependency describes one package relationship list in the intermediate SBOM model.
type Dependency struct {
	Ref       string
	DependsOn []string
}

// License describes normalized license details captured from an SBOM component.
type License struct {
	Value          string
	SPDXExpression string
	Type           string
}

// Digest is a content digest (algorithm + hex value) carried on a component.
type Digest struct {
	Algorithm string
	Value     string
}

// Vulnerability is a format-agnostic projection of one matching-stage advisory
// affecting a component. Encoders map it to the format's native representation
// (CycloneDX vulnerabilities, SPDX SECURITY external references).
type Vulnerability struct {
	ID            string
	Source        string
	Severity      string
	Score         *float64
	Vector        string
	Method        string
	CWEs          []int
	FixedVersions []string
	Advisories    []string
	Description   string
}

// EOL is a format-agnostic projection of end-of-life enrichment for a component.
type EOL struct {
	EOL           bool
	EOLDate       string
	Cycle         string
	LatestVersion string
}

// NameOrID returns the component name when present, otherwise its stable ID.
func (c Component) NameOrID() string {
	if c.Name != "" {
		return c.Name
	}
	return c.ID
}

// NameOrDefault returns the document name or Bomly's default document name.
func (d *Document) NameOrDefault() string {
	if d.Name != "" {
		return d.Name
	}
	return defaultDocumentName
}

// NamespaceOrDefault returns the document namespace or a generated Bomly namespace.
func (d *Document) NamespaceOrDefault() string {
	if d.Namespace != "" {
		return d.Namespace
	}
	return "https://bomly.dev/spdx/" + d.CreatedOrNow().UTC().Format("20060102150405")
}

// ToolOrDefault returns the producing tool name or Bomly's default tool label.
func (d *Document) ToolOrDefault() string {
	if d.Tool != "" {
		return d.Tool
	}
	return defaultToolName
}

// ToolNamesOrDefault returns all producing tool labels, defaulting to Bomly's tool label.
func (d *Document) ToolNamesOrDefault() []string {
	if len(d.Tools) > 0 {
		return append([]string(nil), d.Tools...)
	}
	return []string{d.ToolOrDefault()}
}

// CreatedOrNow returns the document timestamp in UTC, defaulting to the current time.
func (d *Document) CreatedOrNow() time.Time {
	if !d.Created.IsZero() {
		return d.Created.UTC()
	}
	return time.Now().UTC()
}
