package sbom

import "time"

// Target identifies an SBOM wire format target.
type Target string

const (
	TargetSPDX23JSON      Target = "spdx-2.3+json"
	TargetCycloneDX14JSON Target = "cyclonedx-1.4+json"
	TargetCycloneDX15JSON Target = "cyclonedx-1.5+json"
	TargetCycloneDX16JSON Target = "cyclonedx-1.6+json"
	TargetSyftJSON        Target = "syft+json"
	defaultDocumentName          = "bomly-dependencies"
	defaultToolName              = "bomly-cli"
)

// BuildOptions controls how a depgraph is projected into the intermediate SBOM model.
type BuildOptions struct {
	DocumentName    string
	DocumentNS      string
	ToolName        string
	Created         time.Time
	RootComponentID string
	SerialNumber    string
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
	Copyright      string
	Licenses       []License
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

// CreatedOrNow returns the document timestamp in UTC, defaulting to the current time.
func (d *Document) CreatedOrNow() time.Time {
	if !d.Created.IsZero() {
		return d.Created.UTC()
	}
	return time.Now().UTC()
}
