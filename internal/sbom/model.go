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

	// Assertions are the claims this document makes about itself: its
	// identity, name, data license, creators, tools, and comment. A decoder
	// fills them; ingest carries them onto the graph entry the document
	// became, so a later export can say what the source said (ADR-0037).
	//
	// This is what a document says about *itself*, which is why it is not the
	// same field as Sources below.
	Assertions sdk.DocumentAssertions

	// Sources are the documents this one was built from, one per ingested
	// SBOM, in entry order.
	//
	// Empty for a native scan: nothing was ingested, so Bomly's own document
	// asserts everything itself. One source is the conversion case, where the
	// document restates that source's assertions -- the fixed point issue
	// #396 requires. Two or more is the merge case, where the document
	// asserts its own aggregate identity and *links* each source rather than
	// inheriting one, because both formats give a document exactly one
	// identity and picking a source's would name a document that is not this
	// one.
	Sources []sdk.DocumentAssertions
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
	ID   string
	Name string

	// Org is the package namespace -- an npm scope, a Go module host and
	// owner, a Maven group. It is the PURL's namespace segment, emitted as
	// CycloneDX `group`. SPDX 2.3 has no equivalent field, so there it is
	// carried only inside the PURL external reference.
	Org string

	Version string

	// Scopes is the full scope set, not a scalar. A package reachable from
	// both a runtime and a development root carries both, and exporting only
	// the merged precedence value lost that at the SBOM boundary -- which is
	// the whole of what PR #406's scope union bought.
	//
	// Both formats hold one scope per component, so each encoder projects
	// this onto its own scalar and writes the set beside it in a carrier the
	// decoder prefers: a `bomly:scopes` CycloneDX property, a `scope=` field
	// in the SPDX package comment. The projection, the carrier format, and
	// the reverse mapping are all the SDK's (ADR-0037): they are one rule,
	// and a second copy here is how the forward and reverse directions came
	// to disagree in the first place.
	//
	// One clause of ADR-0037 is not implemented here: a source document's own
	// scalar -- CycloneDX's "optional", say -- is not preserved for verbatim
	// re-emission, because DependencyNode has nowhere to carry a source-
	// asserted scope alongside the derived set. "optional" therefore reads as
	// runtime and re-exports as "required". Tracked as bomly-dev/bomly-sdk#57.
	Scopes []sdk.Scope

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

	// Where the package came from. A detector asserts at most one of
	// ArtifactURL and VCSURL; registry enrichment may then fill VCSURL from a
	// resolved source repository when it is empty, so a component enriched
	// under --enrich can carry both. VCSRevision only accompanies VCSURL.
	// Both are plain absolute http(s) URLs; composing them into a format's
	// locator grammar is the encoder's job.
	ArtifactURL string
	VCSURL      string
	VCSRevision string

	// What the source document asserted about this component, beyond its
	// identity (ADR-0037, issue #396).
	//
	// These carry a foreign document's own claims through the graph so a
	// conversion does not silently drop them: `bomly scan --sbom --format
	// spdx` used to lose the supplier, description, checksums, CPEs and
	// references its input stated, because the only things surviving the
	// graph hop were coordinates, scope, copyright and licenses.
	//
	// They are SDK types rather than local structs on purpose. Each carries
	// its own publication gate -- Contact.Normalized, ExternalReference
	// .Normalized -- and every value crossing this boundary re-clears it,
	// because an ingested document is untrusted input that Bomly re-emits.
	// A local mirror of these shapes would be a second place for those rules
	// to be forgotten, which is the defect ADR-0037 replaced.
	Supplier    *sdk.Contact
	Originator  *sdk.Contact
	Description string
	Homepage    string

	// ExternalReferences are the document's own references, kept with the
	// category and type it stated so the SPDX triple round-trips without
	// being re-derived. Merge class: set, unioned by the reference's own
	// identity.
	ExternalReferences []sdk.ExternalReference

	// Every place this package was resolved from, primary first.
	//
	// ADR-0041 folds equal-identity records into one node and keeps their
	// disagreement as a list of origins -- a package resolved from two
	// different registries or mirrors is exactly the dependency-confusion
	// signal that fold exists to preserve. The single-valued fields above
	// carry the first, because a format has one download location; this
	// carries all of them, so the evidence survives the export boundary
	// rather than stopping at it.
	Origins []ComponentOrigin
}

// ComponentOrigin is one place a package was resolved from, already through
// the ADR-0033 publication gates.
type ComponentOrigin struct {
	ArtifactURL string
	Repository  string
	Revision    string
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
