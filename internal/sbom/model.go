package sbom

import (
	"strings"
	"time"

	"github.com/bomly-dev/bomly-sdk"
)

// Target identifies an SBOM wire format target.
type Target string

const (
	TargetSPDX23JSON      Target = "spdx-2.3+json"
	TargetCycloneDX14JSON Target = "cyclonedx-1.4+json"
	TargetCycloneDX15JSON Target = "cyclonedx-1.5+json"
	TargetCycloneDX16JSON Target = "cyclonedx-1.6+json"
	TargetCycloneDX17JSON Target = "cyclonedx-1.7+json"
	defaultDocumentName          = "bomly-dependencies"
	defaultToolName              = "bomly-cli"

	// projectRootIDPrefix marks the synthesized primary component that
	// represents the scanned project itself rather than a resolved package.
	// SPDX encoding prefixes IDs with "SPDXRef-", so consumers must treat
	// both "DocumentRoot-" and "SPDXRef-DocumentRoot-" as pseudo roots.
	projectRootIDPrefix = "DocumentRoot-"
)

// ProjectRoot describes the scanned project so the projection can synthesize
// a primary component when the graph itself has no single root (multiple
// manifests, multiple ecosystems). Name is required; Version is optional.
type ProjectRoot struct {
	Name    string
	Version string
}

// Provenance carries optional producer metadata emitted into SBOM documents.
// The fields map onto EU CRA transparency expectations (manufacturer
// identification, security contact, coordinated disclosure, support period)
// but are format-agnostic and always optional.
type Provenance struct {
	Manufacturer               string
	SecurityContact            string
	VulnerabilityDisclosureURL string
	SupportEnd                 string
}

// Empty reports whether no provenance field is set.
func (p Provenance) Empty() bool {
	return p.Manufacturer == "" && p.SecurityContact == "" && p.VulnerabilityDisclosureURL == "" && p.SupportEnd == ""
}

// BuildOptions controls how a depgraph is projected into the intermediate SBOM model.
type BuildOptions struct {
	DocumentName    string
	DocumentNS      string
	ToolName        string
	ToolNames       []string
	ToolVersion     string
	Created         time.Time
	RootComponentID string
	SerialNumber    string

	// ProjectRoot, when non-nil, lets the projection synthesize a primary
	// component for the scanned project when the graph has no single root.
	ProjectRoot *ProjectRoot

	Provenance Provenance

	// Lifecycle is the CycloneDX lifecycle phase the document describes
	// (for example "pre-build" for source scans, "post-build" for container
	// images). Empty omits lifecycle metadata.
	Lifecycle string

	// Aggregate is the CycloneDX composition completeness declaration
	// ("complete", "incomplete", ...). Empty omits the declaration; callers
	// must only claim "complete" when nothing filtered or degraded the graph.
	Aggregate string

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
	ToolVersion  string
	Created      time.Time
	SerialNumber string
	Provenance   Provenance
	Lifecycle    string
	Aggregate    string

	Components   []Component
	Dependencies []Dependency
	Roots        []string
}

// IsProjectRootComponent reports whether a component is a synthesized pseudo
// root that stands in for the scanned project rather than a resolved package.
func IsProjectRootComponent(c Component) bool {
	return isProjectRootID(c.ID)
}

func isProjectRootID(id string) bool {
	id = strings.TrimSpace(id)
	return strings.HasPrefix(id, projectRootIDPrefix) || strings.HasPrefix(id, "SPDXRef-"+projectRootIDPrefix)
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

	// Where the package came from. Detection-time classification of a single
	// resolved URL sets exactly one of these, but an ingested document may
	// assert several independently — CycloneDX can carry both a
	// `distribution` and a `vcs` reference — so more than one may be set.
	// RegistryURL is the weakest of the three: it names a registry or index
	// root, and is deliberately never used as a download location.
	ArtifactURL string
	VCSURL      string
	RegistryURL string

	// Comments a source document attached to the references above. Kept
	// separately so an ingested comment is preserved rather than replaced by
	// Bomly's own, which could contradict what the producer asserted.
	ArtifactComment string
	VCSComment      string
	RegistryComment string

	// Repository is a canonical "github.com/owner/repo" source repository
	// supplied by the OpenSSF Scorecard matcher during enrichment.
	Repository string

	// Assertions preserved verbatim from an ingested SBOM. Bomly never
	// invents these; they are present only when the source document, or a
	// matcher, actually asserted them.
	Supplier       string
	SupplierType   string
	SupplierURL    string
	Originator     string
	OriginatorType string
	Description    string
	// Summary is SPDX's short-form description. SPDX 2.3 represents it and
	// PackageDescription as distinct fields; CycloneDX has only one, so the
	// summary is used there just as a fallback.
	Summary      string
	ExternalRefs []ExternalRef
}

// mergeComponentAssertions fills gaps in dst from src, leaving anything dst
// already asserts untouched. Used when one component is described in more than
// one place in a source document.
func mergeComponentAssertions(dst *Component, src Component) {
	if dst == nil {
		return
	}
	for _, field := range []struct {
		target *string
		value  string
	}{
		{&dst.Supplier, src.Supplier},
		{&dst.SupplierType, src.SupplierType},
		{&dst.SupplierURL, src.SupplierURL},
		{&dst.Originator, src.Originator},
		{&dst.OriginatorType, src.OriginatorType},
		{&dst.Description, src.Description},
		{&dst.Summary, src.Summary},
		{&dst.Repository, src.Repository},
		{&dst.ArtifactURL, src.ArtifactURL},
		{&dst.VCSURL, src.VCSURL},
		{&dst.RegistryURL, src.RegistryURL},
		{&dst.ArtifactComment, src.ArtifactComment},
		{&dst.VCSComment, src.VCSComment},
		{&dst.RegistryComment, src.RegistryComment},
		{&dst.Copyright, src.Copyright},
	} {
		if *field.target == "" {
			*field.target = field.value
		}
	}
	if len(dst.CPEs) == 0 {
		dst.CPEs = src.CPEs
	}
	if len(dst.Digests) == 0 {
		dst.Digests = src.Digests
	}
	if len(dst.Licenses) == 0 {
		dst.Licenses = src.Licenses
	}
	// External references are a set, not a single assertion: each copy may
	// name a different link, so a fill-gaps copy would drop the second one
	// entirely whenever the first had any.
	dst.ExternalRefs = unionExternalRefs(dst.ExternalRefs, src.ExternalRefs)
}

// unionExternalRefs appends references from extra that base does not already
// carry, keyed by type and URL.
func unionExternalRefs(base, extra []ExternalRef) []ExternalRef {
	if len(extra) == 0 {
		return base
	}
	type key struct{ refType, url string }
	seen := make(map[key]struct{}, len(base))
	for _, ref := range base {
		seen[key{ref.Type, ref.URL}] = struct{}{}
	}
	for _, ref := range extra {
		k := key{ref.Type, ref.URL}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		base = append(base, ref)
	}
	return base
}

// ExternalRef is an external reference carried through from an ingested SBOM
// so that a format conversion does not silently discard it.
type ExternalRef struct {
	Type    string
	URL     string
	Comment string
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

	// Recommendation is remediation guidance derived from known fixed
	// versions (CycloneDX `recommendation`; SPDX 2.3 has no equivalent).
	Recommendation string
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
