package sdk

import (
	"context"
	"io"
)

// DetectorFilter narrows detector selection for a request.
type DetectorFilter struct {
	Include []string
	Exclude []string
}

// Includes reports whether a detector name is explicitly allowed.
func (f DetectorFilter) Includes(name string) bool {
	return includesName(f.Include, name)
}

// Excludes reports whether a detector name is explicitly denied.
func (f DetectorFilter) Excludes(name string) bool {
	return excludesName(f.Exclude, name)
}

// DetectionRequest defines input for dependency graph resolution.
type DetectionRequest struct {
	ProjectPath     string          `json:"projectPath,omitempty"`
	ExecutionTarget ExecutionTarget `json:"executionTarget"`
	Subproject      Subproject      `json:"subproject"`
	Ecosystem       Ecosystem       `json:"ecosystem,omitempty"`
	PackageManager  PackageManager  `json:"packageManager,omitempty"`
	// EnrichmentEnabled allows orchestration to request detector-time metadata
	// enrichment when a downstream command has opted into package enrichment.
	EnrichmentEnabled  bool            `json:"enrichmentEnabled,omitempty"`
	DetectorFilter     DetectorFilter  `json:"detectorFilter"`
	Query              DependencyQuery `json:"query"`
	InstallFirst       bool            `json:"installFirst,omitempty"`
	InstallArgs        []string        `json:"installArgs,omitempty"`
	CoreVersion        string          `json:"coreVersion,omitempty"`
	AllowStdErrLogging bool            `json:"allowStdErrLogging,omitempty"`
	Stderr             io.Writer       `json:"-"`
	Verbose            bool            `json:"-"`
}

// DetectionResult contains one or more manifest-scoped graphs.
type DetectionResult struct {
	SubprojectInfo      Subproject        `json:"subprojectInfo"`
	RootExecutionTarget ExecutionTarget   `json:"rootExecutionTarget"`
	DetectorName        string            `json:"detectorName,omitempty"`
	Origin              DetectorOrigin    `json:"origin,omitempty"`
	Technique           DetectorTechnique `json:"technique,omitempty"`
	Graphs              *GraphContainer   `json:"graphs,omitempty"`
}

// ConsolidatedGraph returns a single graph view for the resolve result.
func (r DetectionResult) ConsolidatedGraph() (*Graph, error) {
	return ConsolidateGraphContainerEntry(r.Graphs)
}

// DetectorDescriptor describes a detector registration.
type DetectorDescriptor struct {
	Name                  string                  `json:"name"`
	Enabled               bool                    `json:"enabled,omitempty"`
	Origin                DetectorOrigin          `json:"origin,omitempty"`
	Technique             DetectorTechnique       `json:"technique,omitempty"`
	SupportedEcosystems   []Ecosystem             `json:"supportedEcosystems,omitempty"`
	SupportedManagers     []PackageManager        `json:"supportedManagers,omitempty"`
	PackageManagerSupport []PackageManagerSupport `json:"packageManagerSupport,omitempty"`
	Capabilities          []string                `json:"capabilities,omitempty"`
	FallbackDetectors     []string                `json:"fallbackDetectors,omitempty"`
	SupportsInstallFirst  bool                    `json:"supportsInstallFirst,omitempty"`
}

// PackageManagerSupport records package-manager discovery metadata for a detector.
type PackageManagerSupport struct {
	PackageManager   PackageManager `json:"packageManager"`
	EvidencePatterns []string       `json:"evidencePatterns,omitempty"`
}

// PackageManagerSupporter reports detector package-manager discovery metadata.
type PackageManagerSupporter interface {
	PackageManagerSupport() []PackageManagerSupport
}

// Support returns package-manager discovery metadata for a detector.
func Support(manager PackageManager, evidencePatterns ...string) PackageManagerSupport {
	return PackageManagerSupport{
		PackageManager:   manager,
		EvidencePatterns: append([]string(nil), evidencePatterns...),
	}
}

// Detector resolves dependency information.
type Detector interface {
	Descriptor() DetectorDescriptor
	PackageManagerSupport() []PackageManagerSupport
	Ready() bool
	Applicable(context.Context, DetectionRequest) (bool, error)
	ResolveGraph(context.Context, DetectionRequest) (DetectionResult, error)
}

// FallbackDetector optionally provides a fallback detector that should run when
// the primary detector cannot produce a result.
type FallbackDetector interface {
	FallbackDetector() Detector
}

// InstallFirstDetector optionally prepares dependencies before graph resolution.
type InstallFirstDetector interface {
	Install(context.Context, DetectionRequest) error
}

// DetectRequest is the detector request payload exposed to plugins.
type DetectRequest = DetectionRequest

// DetectResponse is the detector response payload exposed to plugins.
type DetectResponse = DetectionResult
