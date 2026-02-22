package scan

import (
	"context"
	"io"

	"github.com/bomly/bomly-cli/internal/detectors"
	"github.com/bomly/bomly-cli/internal/model"
)

// Ecosystem groups package managers under a dependency model.
type Ecosystem = model.Ecosystem

const (
	EcosystemUnknown   = model.EcosystemUnknown
	EcosystemNPM       = model.EcosystemNPM
	EcosystemMaven     = model.EcosystemMaven
	EcosystemGo        = model.EcosystemGo
	EcosystemPython    = model.EcosystemPython
	EcosystemALPM      = model.EcosystemALPM
	EcosystemAPK       = model.EcosystemAPK
	EcosystemCPP       = model.EcosystemCPP
	EcosystemConda     = model.EcosystemConda
	EcosystemDart      = model.EcosystemDart
	EcosystemDPKG      = model.EcosystemDPKG
	EcosystemElixir    = model.EcosystemElixir
	EcosystemErlang    = model.EcosystemErlang
	EcosystemGitHub    = model.EcosystemGitHub
	EcosystemHaskell   = model.EcosystemHaskell
	EcosystemHomebrew  = model.EcosystemHomebrew
	EcosystemLua       = model.EcosystemLua
	EcosystemDotNet    = model.EcosystemDotNet
	EcosystemNix       = model.EcosystemNix
	EcosystemOCaml     = model.EcosystemOCaml
	EcosystemPHP       = model.EcosystemPHP
	EcosystemPortage   = model.EcosystemPortage
	EcosystemProlog    = model.EcosystemProlog
	EcosystemR         = model.EcosystemR
	EcosystemRPM       = model.EcosystemRPM
	EcosystemRuby      = model.EcosystemRuby
	EcosystemRust      = model.EcosystemRust
	EcosystemSBOM      = model.EcosystemSBOM
	EcosystemSnap      = model.EcosystemSnap
	EcosystemSwift     = model.EcosystemSwift
	EcosystemTerraform = model.EcosystemTerraform
	EcosystemWordPress = model.EcosystemWordPress
)

// ParseEcosystem normalizes a user-provided ecosystem value.
func ParseEcosystem(value string) (Ecosystem, error) {
	return model.ParseEcosystem(value)
}

// PackageManager identifies the concrete package manager or manifest family for a target.
type PackageManager = model.PackageManager

const (
	PackageManagerUnknown       = model.PackageManagerUnknown
	PackageManagerNPM           = model.PackageManagerNPM
	PackageManagerPNPM          = model.PackageManagerPNPM
	PackageManagerYarn          = model.PackageManagerYarn
	PackageManagerGradle        = model.PackageManagerGradle
	PackageManagerMaven         = model.PackageManagerMaven
	PackageManagerGoMod         = model.PackageManagerGoMod
	PackageManagerPip           = model.PackageManagerPip
	PackageManagerPipenv        = model.PackageManagerPipenv
	PackageManagerPoetry        = model.PackageManagerPoetry
	PackageManagerUV            = model.PackageManagerUV
	PackageManagerALPM          = model.PackageManagerALPM
	PackageManagerAPK           = model.PackageManagerAPK
	PackageManagerConan         = model.PackageManagerConan
	PackageManagerConda         = model.PackageManagerConda
	PackageManagerPub           = model.PackageManagerPub
	PackageManagerDPKG          = model.PackageManagerDPKG
	PackageManagerMix           = model.PackageManagerMix
	PackageManagerRebar         = model.PackageManagerRebar
	PackageManagerOTP           = model.PackageManagerOTP
	PackageManagerGitHubActions = model.PackageManagerGitHubActions
	PackageManagerCabal         = model.PackageManagerCabal
	PackageManagerStack         = model.PackageManagerStack
	PackageManagerHomebrew      = model.PackageManagerHomebrew
	PackageManagerLuaRocks      = model.PackageManagerLuaRocks
	PackageManagerNuGet         = model.PackageManagerNuGet
	PackageManagerNix           = model.PackageManagerNix
	PackageManagerOpam          = model.PackageManagerOpam
	PackageManagerComposer      = model.PackageManagerComposer
	PackageManagerPear          = model.PackageManagerPear
	PackageManagerPDM           = model.PackageManagerPDM
	PackageManagerPortage       = model.PackageManagerPortage
	PackageManagerSWIPLPack     = model.PackageManagerSWIPLPack
	PackageManagerRPackage      = model.PackageManagerRPackage
	PackageManagerRPM           = model.PackageManagerRPM
	PackageManagerBundler       = model.PackageManagerBundler
	PackageManagerGemspec       = model.PackageManagerGemspec
	PackageManagerCargo         = model.PackageManagerCargo
	PackageManagerSBOM          = model.PackageManagerSBOM
	PackageManagerSnap          = model.PackageManagerSnap
	PackageManagerCocoaPods     = model.PackageManagerCocoaPods
	PackageManagerSwiftPM       = model.PackageManagerSwiftPM
	PackageManagerTerraform     = model.PackageManagerTerraform
	PackageManagerWordPress     = model.PackageManagerWordPress
	PackageManagerSetupPy       = model.PackageManagerSetupPy
)

// ParsePackageManager normalizes a user-provided package-manager value.
func ParsePackageManager(value string) (PackageManager, error) {
	return model.ParsePackageManager(value)
}

// Scope describes the normalized dependency scope surfaced to users.
type Scope = detectors.Scope

const (
	ScopeUnknown     = detectors.ScopeUnknown
	ScopeRuntime     = detectors.ScopeRuntime
	ScopeDevelopment = detectors.ScopeDevelopment
)

// ParseScope normalizes a user-provided dependency scope value.
func ParseScope(value string) (Scope, error) {
	return detectors.ParseScope(value)
}

// DetectorFilter narrows detector selection for a request.
type DetectorFilter = model.DetectorFilter

// AuditorFilter narrows auditor selection for a request.
type AuditorFilter = model.AuditorFilter

// MatcherFilter narrows matcher selection for a request.
type MatcherFilter = model.MatcherFilter

// ExecutionTargetKind identifies the top-level source selected by the user for one scan execution.
type ExecutionTargetKind = detectors.ExecutionTargetKind

const (
	ExecutionTargetFilesystem       = detectors.ExecutionTargetFilesystem
	ExecutionTargetWorkingDirectory = detectors.ExecutionTargetWorkingDirectory
	ExecutionTargetGitRepository    = detectors.ExecutionTargetGitRepository
	ExecutionTargetContainerImage   = detectors.ExecutionTargetContainerImage
)

// ExecutionTarget identifies the single top-level source selected by the user for one scan execution.
type ExecutionTarget = detectors.ExecutionTarget

// Subproject identifies one package-manager root discovered beneath the execution target.
type Subproject = detectors.Subproject

// ComponentQuery identifies a specific component target.
type ComponentQuery = detectors.ComponentQuery

// DetectorType distinguishes detector and auditor implementation families.
type DetectorType = model.DetectorType

const (
	NativeDetector         = model.NativeDetector
	LockfileParserDetector = model.LockfileParserDetector
	ThirdPartyDetector     = model.ThirdPartyDetector
	PluginDetector         = model.PluginDetector
)

// TargetMode describes whether an operation targets a whole graph or a single component.
type TargetMode = model.TargetMode

const (
	TargetModeFullGraph = model.TargetModeFullGraph
	TargetModeComponent = model.TargetModeComponent
)

// DetectorDescriptor describes a detector registration.
type DetectorDescriptor = detectors.DetectorDescriptor

// ResolveGraphRequest defines input for dependency graph resolution.
type ResolveGraphRequest = detectors.ResolveGraphRequest

// ResolveGraphResult contains one or more manifest-scoped graphs.
type ResolveGraphResult = detectors.ResolveGraphResult

// Detector resolves dependency information.
type Detector = detectors.Detector

// FallbackDetector optionally provides a fallback detector that should run when
// the primary detector cannot produce a result.
type FallbackDetector = detectors.FallbackDetector

// InstallFirstDetector optionally prepares dependencies before graph resolution.
type InstallFirstDetector = detectors.InstallFirstDetector

// ReadyDetector optionally reports whether a detector can run in the current environment.
type ReadyDetector = detectors.ReadyDetector

// ApplicableDetector optionally reports whether a detector applies to a specific request.
type ApplicableDetector = detectors.ApplicableDetector

// AuditorDescriptor describes an auditor registration.
type AuditorDescriptor struct {
	Name                string
	ImplementationType  DetectorType
	SupportedEcosystems []Ecosystem
	SupportedManagers   []PackageManager
	SupportedModes      []TargetMode
	Priority            int
	Required            bool
	Capabilities        []string
}

// MatcherDescriptor describes a matcher registration.
type MatcherDescriptor struct {
	Name                string
	ImplementationType  DetectorType
	SupportedEcosystems []Ecosystem
	SupportedManagers   []PackageManager
	SupportedModes      []TargetMode
	Priority            int
	Required            bool
	Capabilities        []string
}

// FindingKind categorizes audit findings.
type FindingKind string

const (
	FindingKindRisk          FindingKind = "risk"
	FindingKindVulnerability FindingKind = "vulnerability"
	FindingKindPolicy        FindingKind = "policy"
)

// Finding describes a normalized audit result.
type Finding struct {
	ID       string
	Kind     FindingKind
	Package  *model.Package
	Title    string
	Severity string
	Reasons  []string
	Source   string
	// VexStatus is set when a VEX statement applies to this finding.
	// Values: "not_affected", "false_positive", "in_triage", "exploitable", or empty.
	VexStatus string
}

// RiskScore describes a normalized risk result for one package.
type RiskScore struct {
	Package *model.Package
	Score   int
	Band    string
	Signals map[string]any
}

// AuditRequest defines input for an auditor.
type AuditRequest struct {
	ProjectPath     string
	ExecutionTarget ExecutionTarget
	SubprojectInfo  Subproject
	Ecosystem       Ecosystem
	PackageManager  PackageManager
	Mode            TargetMode
	Query           ComponentQuery
	Graph           *model.Graph
	Target          *model.Package
	AuditorFilter   AuditorFilter
	Stderr          io.Writer
}

// MatchRequest defines input for a matcher.
type MatchRequest struct {
	ProjectPath     string
	ExecutionTarget ExecutionTarget
	SubprojectInfo  Subproject
	Ecosystem       Ecosystem
	PackageManager  PackageManager
	Mode            TargetMode
	Query           ComponentQuery
	Graph           *model.Graph
	Target          *model.Package
	MatcherFilter   MatcherFilter
	Stderr          io.Writer
}

// AuditResult contains findings and scores from one auditor.
type AuditResult struct {
	Graph      *model.Graph
	Target     *model.Package
	Findings   []Finding
	RiskScores []RiskScore
}

// MatchResult contains the graph after matcher enrichment.
type MatchResult struct {
	Graph       *model.Graph
	Target      *model.Package
	MatcherRuns []string
}

// Auditor analyzes graphs or components and returns findings.
type Auditor interface {
	Descriptor() AuditorDescriptor
	Audit(context.Context, AuditRequest) (AuditResult, error)
}

// ReadyAuditor optionally reports whether an auditor can run in the current environment.
type ReadyAuditor interface {
	Ready() bool
}

// ApplicableAuditor optionally reports whether an auditor applies to a specific request.
type ApplicableAuditor interface {
	Applicable(context.Context, AuditRequest) (bool, error)
}

// Matcher enriches graph packages with license data.
type Matcher interface {
	Descriptor() MatcherDescriptor
	Match(context.Context, MatchRequest) (MatchResult, error)
}

// ReadyMatcher optionally reports whether a matcher can run in the current environment.
type ReadyMatcher interface {
	Ready() bool
}

// ApplicableMatcher optionally reports whether a matcher applies to a specific request.
type ApplicableMatcher interface {
	Applicable(context.Context, MatchRequest) (bool, error)
}

// ---------------------------------------------------------------------------
// Hook interfaces
// ---------------------------------------------------------------------------

// HookDescriptor describes a hook registration.
type HookDescriptor struct {
	Name     string
	Priority int
	Stage    string // "pre-resolve" | "post-resolve"
}

// PreResolveContext provides inputs available before detection.
type PreResolveContext struct {
	ExecutionTarget ExecutionTarget
	Subprojects     []Subproject
	ProjectPath     string
	Stderr          io.Writer
}

// PostResolveContext provides inputs available after full resolution.
type PostResolveContext struct {
	Consolidated ConsolidatedGraph
	Findings     []Finding
	ProjectPath  string
	Stderr       io.Writer
}

// PreResolveHook runs logic before detection.
type PreResolveHook interface {
	Descriptor() HookDescriptor
	Execute(context.Context, PreResolveContext) error
}

// PostResolveHook runs logic after all resolution and auditing.
type PostResolveHook interface {
	Descriptor() HookDescriptor
	Execute(context.Context, PostResolveContext) error
}

// ---------------------------------------------------------------------------
// Pipeline types
// ---------------------------------------------------------------------------

// StageProcessor is a command-specific graph manipulation step injected into the
// pipeline between consolidation and audit. Return a non-nil error to abort.
type StageProcessor func(context.Context, *PipelineResult) error

// PipelineRequest defines input for a full pipeline run.
type PipelineRequest struct {
	ProjectPath     string
	ExecutionTarget ExecutionTarget
	Subprojects     []Subproject
	Processor       StageProcessor
	AuditEnabled    bool
	MatchEnabled    bool
	ScopeFilter     Scope
	AuditorFilter   AuditorFilter
	MatcherFilter   MatcherFilter
	DetectorFilter  DetectorFilter
	InstallFirst    bool
	InstallArgs     []string
	CoreVersion     string
	Stderr          io.Writer
	Verbose         bool
}

// PipelineWarning is a structured warning captured during a pipeline stage.
type PipelineWarning struct {
	Source  string // detector, auditor, or matcher name
	Message string // human-readable warning text
}

// PipelineResult contains the full output of a pipeline run.
type PipelineResult struct {
	ResolveResults   []ResolveGraphResult
	Consolidated     ConsolidatedGraph
	Graph            *model.Graph
	Findings         []Finding
	RiskScores       []RiskScore
	DetectorWarnings []PipelineWarning
	AuditWarnings    []PipelineWarning
	MatchWarnings    []PipelineWarning
	MatcherRuns      []string
	PartialErrors    error
}
