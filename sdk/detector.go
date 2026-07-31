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
	EnrichmentEnabled bool            `json:"enrichmentEnabled,omitempty"`
	DetectorFilter    DetectorFilter  `json:"detectorFilter"`
	ScopeFilter       Scope           `json:"scopeFilter,omitempty"`
	Query             DependencyQuery `json:"query"`
	InstallFirst      bool            `json:"installFirst,omitempty"`
	InstallArgs       []string        `json:"installArgs,omitempty"`
	CoreVersion       string          `json:"coreVersion,omitempty"`
	// AllowStdErrLogging tells a detector that the user enabled debug output
	// and accepts the detector's raw subprocess diagnostics in that output.
	AllowStdErrLogging bool `json:"allowStdErrLogging,omitempty"`
	// Stderr and Verbose are process-local fields used by built-in detectors.
	// Stderr is nil unless debug output is enabled. Verbose mirrors
	// AllowStdErrLogging for compatibility with existing detector code.
	Stderr  io.Writer `json:"-"`
	Verbose bool      `json:"-"`
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
	// Warnings are non-fatal problems the detector found while resolving: the
	// graphs above are usable, but something about the project will break or
	// degrade an install elsewhere. The engine fills in each warning's
	// Subproject and surfaces them alongside the ones it observes itself.
	Warnings []DetectorWarning `json:"warnings,omitempty"`
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
	// RemediationCapabilities advertises optional, read-only support for
	// package-manager-specific remediation strategies. Core calls the optional
	// provider only when this list is non-empty.
	RemediationCapabilities []RemediationCapability `json:"remediationCapabilities,omitempty"`
	// IgnoredDirectories lists directory basename globs (Go
	// path.Match syntax) that recursive subproject discovery must not descend
	// into because they hold third-party installs, vendored dependencies, or
	// build outputs for this detector's ecosystem (e.g. "node_modules",
	// "target"). Discovery aggregates these across every registered detector,
	// including external plugins. Optional; omitted by older plugins.
	IgnoredDirectories []string `json:"ignoredDirectories,omitempty"`
	// IgnoredDirectoryMarkers lists file names whose presence inside
	// a directory marks that directory as ignored during recursive discovery
	// regardless of its name (e.g. "pyvenv.cfg" identifies a Python
	// virtualenv). Optional; omitted by older plugins.
	IgnoredDirectoryMarkers []string `json:"ignoredDirectoryMarkers,omitempty"`
}

// Clone returns a deep copy of the detector descriptor.
func (d DetectorDescriptor) Clone() DetectorDescriptor {
	clone := d
	clone.Aliases = append([]string(nil), d.Aliases...)
	clone.Tags = append([]string(nil), d.Tags...)
	clone.SupportedEcosystems = append([]Ecosystem(nil), d.SupportedEcosystems...)
	clone.SupportedManagers = append([]PackageManager(nil), d.SupportedManagers...)
	clone.FallbackDetectors = append([]string(nil), d.FallbackDetectors...)
	clone.IgnoredDirectories = append([]string(nil), d.IgnoredDirectories...)
	clone.IgnoredDirectoryMarkers = append([]string(nil), d.IgnoredDirectoryMarkers...)
	clone.PackageManagerSupport = make([]PackageManagerSupport, len(d.PackageManagerSupport))
	for idx, support := range d.PackageManagerSupport {
		clone.PackageManagerSupport[idx] = support
		clone.PackageManagerSupport[idx].EvidencePatterns = append([]string(nil), support.EvidencePatterns...)
	}
	clone.RemediationCapabilities = make([]RemediationCapability, len(d.RemediationCapabilities))
	for idx, capability := range d.RemediationCapabilities {
		clone.RemediationCapabilities[idx] = capability
		clone.RemediationCapabilities[idx].SupportedManagers = append([]PackageManager(nil), capability.SupportedManagers...)
		clone.RemediationCapabilities[idx].Actions = append([]RemediationAction(nil), capability.Actions...)
	}
	return clone
}

// RemediationCapability advertises the occurrence-scoped strategies for which
// a detector can provide package-manager-specific evidence. Capabilities do
// not grant authority to choose final remediation or modify a project.
type RemediationCapability struct {
	SupportedManagers []PackageManager    `json:"supportedManagers,omitempty"`
	Actions           []RemediationAction `json:"actions,omitempty"`
}

// RemediationHintRequest supplies completed detection and enrichment evidence
// to an optional detector remediation provider.
type RemediationHintRequest struct {
	ProjectPath string           `json:"projectPath,omitempty"`
	Detection   DetectionResult  `json:"detection"`
	Registry    *PackageRegistry `json:"registry,omitempty"`
}

// RemediationStrategyHint is read-only detector evidence that a strategy is
// available for one occurrence. Advice is detector-owned, action-specific
// package-manager guidance. For example, a transitive-override hint can
// explain the manager's override syntax, while a lockfile-refresh hint can
// provide the normal refresh command. Core validates and bounds this text,
// then retains authority over the final action.
type RemediationStrategyHint struct {
	Action RemediationAction `json:"action"`
	Advice string            `json:"advice,omitempty"`
}

// RemediationHint contributes package-manager evidence for one detected
// dependency occurrence.
type RemediationHint struct {
	DependencyRef string                    `json:"dependencyRef"`
	ManifestPath  string                    `json:"manifestPath,omitempty"`
	Strategies    []RemediationStrategyHint `json:"strategies,omitempty"`
}

// RemediationHintResponse contains optional read-only detector evidence.
type RemediationHintResponse struct {
	Hints       []RemediationHint `json:"hints,omitempty"`
	Diagnostics []string          `json:"diagnostics,omitempty"`
}

// PackageManagerSupport records package-manager discovery metadata for a
// detector. External detector plugins return this so Bomly can include them in
// subproject discovery and scan planning before the detector runs.
type PackageManagerSupport struct {
	PackageManager   PackageManager `json:"packageManager"`
	EvidencePatterns []string       `json:"evidencePatterns,omitempty"`
	// MultiModule marks that the detector natively expands nested
	// workspace/reactor modules for this package manager from a root manifest
	// (Maven reactors, npm/pnpm/yarn workspaces, cargo workspace members,
	// ...). Recursive discovery prunes nested subprojects for the same
	// package manager below a directory where a native multi-module manager
	// was detected, so the same modules are not scanned twice. Optional;
	// omitted by older plugins.
	MultiModule bool `json:"multiModule,omitempty"`
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

// WithMultiModule returns a copy of the support entry marked as natively
// expanding nested workspace/reactor modules from a root manifest, opting the
// package manager into recursive-discovery ancestor pruning.
func (s PackageManagerSupport) WithMultiModule() PackageManagerSupport {
	s.MultiModule = true
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

// DetectorRemediationProvider optionally contributes read-only
// package-manager evidence after vulnerability enrichment.
type DetectorRemediationProvider interface {
	RemediationHints(context.Context, RemediationHintRequest) (RemediationHintResponse, error)
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
