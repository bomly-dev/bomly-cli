package detectors

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/bomly/bomly-cli/internal/model"
)

// Ecosystem groups package managers under a dependency model.
type Ecosystem = model.Ecosystem

const (
	// Keep this list aligned with the Syft-backed support matrix in docs/SUPPORT_MATRIX.md
	// and the Syft manifest mappings in internal/detectors/syft/detector.go.
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

// DetectorType distinguishes detector implementation families.
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
	// TargetModeFullGraph requests whole-project resolution or analysis.
	TargetModeFullGraph = model.TargetModeFullGraph
	// TargetModeComponent requests a single-component targeted query.
	TargetModeComponent = model.TargetModeComponent
)

// DetectorFilter narrows detector selection for a request.
type DetectorFilter = model.DetectorFilter

// Scope describes the normalized dependency scope surfaced to users.
type Scope string

const (
	// ScopeUnknown indicates that a detector could not determine dependency scope.
	ScopeUnknown Scope = ""
	// ScopeRuntime indicates a dependency required at runtime.
	ScopeRuntime Scope = "runtime"
	// ScopeDevelopment indicates a dependency used only for development workflows.
	ScopeDevelopment Scope = "development"
)

// ParseScope normalizes a user-provided dependency scope value.
func ParseScope(value string) (Scope, error) {
	switch Scope(strings.ToLower(strings.TrimSpace(value))) {
	case ScopeRuntime:
		return ScopeRuntime, nil
	case ScopeDevelopment:
		return ScopeDevelopment, nil
	case ScopeUnknown:
		return ScopeUnknown, nil
	default:
		return ScopeUnknown, fmt.Errorf("unsupported scope %q", value)
	}
}

// ExecutionTargetKind identifies the top-level source selected by the user for one scan execution.
type ExecutionTargetKind string

const (
	// ExecutionTargetFilesystem points at a local filesystem path. The path may be a
	// directory or a single file depending on the selected scan target.
	ExecutionTargetFilesystem ExecutionTargetKind = "filesystem"
	// ExecutionTargetWorkingDirectory is kept as an alias for the existing local-path model.
	ExecutionTargetWorkingDirectory ExecutionTargetKind = ExecutionTargetFilesystem
	ExecutionTargetGitRepository    ExecutionTargetKind = "git-repository"
	ExecutionTargetContainerImage   ExecutionTargetKind = "container-image"
)

// ExecutionTarget identifies the single top-level source selected by the user for one scan execution.
type ExecutionTarget struct {
	Kind          ExecutionTargetKind
	Location      string
	RepositoryURL string
	Ref           string
}

// Subproject identifies one package-manager root discovered beneath the execution target.
type Subproject struct {
	ExecutionTarget         ExecutionTarget
	RelativePath            string
	PackageManager          PackageManager
	DetectedPackageManagers []PackageManager
	PlannedDetectors        []string
	Ecosystem               Ecosystem
}

// ComponentQuery identifies a specific component target.
type ComponentQuery struct {
	Name string
	ID   string
}

// DetectorDescriptor describes a detector registration.
type DetectorDescriptor struct {
	Name                string
	ImplementationType  DetectorType
	SupportedEcosystems []Ecosystem
	SupportedManagers   []PackageManager
	SupportedModes      []TargetMode
	Capabilities        []string
}

// ResolveGraphRequest defines input for dependency graph resolution.
type ResolveGraphRequest struct {
	ProjectPath     string
	ExecutionTarget ExecutionTarget
	Subproject      Subproject
	Ecosystem       Ecosystem
	PackageManager  PackageManager
	DetectorFilter  DetectorFilter
	Mode            TargetMode
	Query           ComponentQuery
	InstallFirst    bool
	InstallArgs     []string
	CoreVersion     string
	Stderr          io.Writer
	Verbose         bool
}

// ManifestMetadata is an alias for model.ManifestMetadata.
type ManifestMetadata = model.ManifestMetadata

// GraphEntry is an alias for model.GraphEntry.
type GraphEntry = model.GraphEntry

// GraphContainer is an alias for model.GraphContainer.
type GraphContainer = model.GraphContainer

// ResolveGraphResult contains one or more manifest-scoped graphs.
type ResolveGraphResult struct {
	SubprojectInfo      Subproject
	RootExecutionTarget ExecutionTarget
	DetectorName        string
	// DetectorType records the detector implementation family so downstream
	// manifest deduplication can prefer native detector output over fallback
	// third-party results such as Syft.
	DetectorType DetectorType
	Graphs       *GraphContainer
}

// Detector resolves dependency information.
type Detector interface {
	ApplicableDetector
	ReadyDetector
	Descriptor() DetectorDescriptor
	ResolveGraph(context.Context, ResolveGraphRequest) (ResolveGraphResult, error)
}

// FallbackDetector optionally provides a fallback detector that should run when
// the primary detector cannot produce a result.
type FallbackDetector interface {
	FallbackDetector() Detector
}

// InstallFirstDetector optionally prepares dependencies before graph resolution.
type InstallFirstDetector interface {
	Install(context.Context, ResolveGraphRequest) error
}

// ReadyDetector optionally reports whether a detector can run in the current environment.
type ReadyDetector interface {
	Ready() bool
}

// ApplicableDetector optionally reports whether a detector applies to a specific request.
type ApplicableDetector interface {
	Applicable(context.Context, ResolveGraphRequest) (bool, error)
}

// PreferredPackageManagersForDetector returns package managers whose preferred detector matches detectorName.
func PreferredPackageManagersForDetector(detectorName string) []PackageManager {
	return model.PreferredPackageManagersForDetector(detectorName)
}

// PreferredEcosystemsForDetector returns ecosystems whose preferred package managers are backed by detectorName.
func PreferredEcosystemsForDetector(detectorName string) []Ecosystem {
	return model.PreferredEcosystemsForDetector(detectorName)
}

// EvidencePatternsForPackageManager returns the configured manifest or database evidence patterns.
func EvidencePatternsForPackageManager(manager PackageManager) []string {
	return model.EvidencePatternsForPackageManager(manager)
}
