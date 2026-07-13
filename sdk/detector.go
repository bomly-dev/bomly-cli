package sdk

import (
	"context"
	"io"

	"go.uber.org/zap"
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
	// Logger is a request-scoped logger injected by the pipeline, already
	// bound to the subproject and detector this request targets. It lets a
	// detector instance that is shared across concurrently-resolved
	// subprojects emit log lines that identify which subproject they belong
	// to. It is process-local and never serialized. Use DetectorLogger to
	// read it with a safe fallback.
	Logger *zap.Logger `json:"-"`
}

// DetectorLogger returns the most specific non-nil logger for this request:
// the request-scoped Logger injected by the pipeline (carrying subproject and
// detector context) when present, otherwise the supplied fallback (typically
// the detector's own instance logger), otherwise a no-op logger. It never
// returns nil, so callers can drop the usual "if logger == nil" guard.
func (r DetectionRequest) DetectorLogger(fallback *zap.Logger) *zap.Logger {
	if r.Logger != nil {
		return r.Logger
	}
	if fallback != nil {
		return fallback
	}
	return zap.NewNop()
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
	// DiscoveryIgnoredDirectories lists directory basename globs (Go
	// path.Match syntax) that recursive subproject discovery must not descend
	// into because they hold third-party installs, vendored dependencies, or
	// build outputs for this detector's ecosystem (e.g. "node_modules",
	// "target"). Discovery aggregates these across every registered detector,
	// including external plugins. Optional; omitted by older plugins.
	DiscoveryIgnoredDirectories []string `json:"discoveryIgnoredDirectories,omitempty"`
	// DiscoveryIgnoredDirectoryMarkers lists file names whose presence inside
	// a directory marks that directory as ignored during recursive discovery
	// regardless of its name (e.g. "pyvenv.cfg" identifies a Python
	// virtualenv). Optional; omitted by older plugins.
	DiscoveryIgnoredDirectoryMarkers []string `json:"discoveryIgnoredDirectoryMarkers,omitempty"`
}

// PackageManagerSupport records package-manager discovery metadata for a
// detector. External detector plugins return this so Bomly can include them in
// subproject discovery and scan planning before the detector runs.
type PackageManagerSupport struct {
	PackageManager   PackageManager `json:"packageManager"`
	EvidencePatterns []string       `json:"evidencePatterns,omitempty"`
	// NativeMultiModule marks that the detector natively expands nested
	// workspace/reactor modules for this package manager from a root manifest
	// (Maven reactors, npm/pnpm/yarn workspaces, cargo workspace members,
	// ...). Recursive discovery prunes nested subprojects for the same
	// package manager below a directory where a native multi-module manager
	// was detected, so the same modules are not scanned twice. Optional;
	// omitted by older plugins.
	NativeMultiModule bool `json:"nativeMultiModule,omitempty"`
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

// WithNativeMultiModule returns a copy of the support entry marked as natively
// expanding nested workspace/reactor modules from a root manifest, opting the
// package manager into recursive-discovery ancestor pruning.
func (s PackageManagerSupport) WithNativeMultiModule() PackageManagerSupport {
	s.NativeMultiModule = true
	return s
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
