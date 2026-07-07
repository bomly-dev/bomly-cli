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
	ScopeFilter        Scope           `json:"scopeFilter,omitempty"`
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
	// FallbackFrom names the planned primary detector that failed before a
	// fallback detector produced this result. Empty for routine applicability
	// hand-off between chained detectors.
	FallbackFrom string `json:"fallbackFrom,omitempty"`
	// FallbackReason is the human-readable cause of the primary detector's
	// failure, e.g. "not ready: java executable not found on PATH".
	FallbackReason string          `json:"fallbackReason,omitempty"`
	Graphs         *GraphContainer `json:"graphs,omitempty"`
}

// ConsolidatedGraph returns a single graph view for the resolve result.
func (r DetectionResult) ConsolidatedGraph() (*Graph, error) {
	return ConsolidateGraphContainerEntry(r.Graphs)
}

// DetectorDescriptor describes a detector registration.
type DetectorDescriptor struct {
	Name                  string                  `json:"name"`
	DisplayName           string                  `json:"displayName,omitempty"`
	Aliases               []string                `json:"aliases,omitempty"`
	Tags                  []string                `json:"tags,omitempty"`
	SupportedEcosystems   []Ecosystem             `json:"supportedEcosystems,omitempty"`
	SupportedManagers     []PackageManager        `json:"supportedManagers,omitempty"`
	Technique             DetectorTechnique       `json:"technique,omitempty"`
	PackageManagerSupport []PackageManagerSupport `json:"packageManagerSupport,omitempty"`
	FallbackDetectors     []string                `json:"fallbackDetectors,omitempty"`
	SupportsInstallFirst  bool                    `json:"supportsInstallFirst,omitempty"`
}

// PackageManagerSupport records package-manager discovery metadata for a
// detector. External detector plugins return this so Bomly can include them in
// subproject discovery and scan planning before the detector runs.
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
	// Ready reports whether the detector can run for the given request. It
	// returns nil when ready and a non-nil error describing the reason
	// (e.g. a missing toolchain) otherwise. Implementations may perform
	// lightweight, cancellable I/O (such as probing for a runtime) and should
	// honor ctx.
	Ready(context.Context, DetectionRequest) error
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
//
// It aliases DetectionRequest so plugin code can name payload types by role
// while sharing the same transport shape Bomly core uses internally.
type DetectRequest = DetectionRequest

// DetectResponse is the detector response payload exposed to plugins.
//
// It aliases DetectionResult so plugin code can name payload types by role
// while sharing the same transport shape Bomly core uses internally.
type DetectResponse = DetectionResult
