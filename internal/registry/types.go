package registry

import "github.com/bomly/bomly-cli/internal/model"

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

// DetectorFilter narrows detector selection for a request.
type DetectorFilter = model.DetectorFilter

// AuditorFilter narrows auditor selection for a request.
type AuditorFilter = model.AuditorFilter

// MatcherFilter narrows matcher selection for a request.
type MatcherFilter = model.MatcherFilter
