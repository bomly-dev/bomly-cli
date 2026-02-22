package model

import (
	"fmt"
	"strings"
)

// Ecosystem groups package managers under a registry-specific dependency model.
type Ecosystem string

const (
	// Keep this list aligned with the Syft-backed support matrix in docs/SUPPORT_MATRIX.md
	// and the Syft manifest mappings in internal/detectors/syft/detector.go.
	EcosystemUnknown   Ecosystem = ""
	EcosystemNPM       Ecosystem = "npm"
	EcosystemMaven     Ecosystem = "maven"
	EcosystemGo        Ecosystem = "go"
	EcosystemPython    Ecosystem = "python"
	EcosystemALPM      Ecosystem = "alpm"
	EcosystemAPK       Ecosystem = "apk"
	EcosystemCPP       Ecosystem = "cpp"
	EcosystemConda     Ecosystem = "conda"
	EcosystemDart      Ecosystem = "dart"
	EcosystemDPKG      Ecosystem = "dpkg"
	EcosystemElixir    Ecosystem = "elixir"
	EcosystemErlang    Ecosystem = "erlang"
	EcosystemGitHub    Ecosystem = "github-actions"
	EcosystemHaskell   Ecosystem = "haskell"
	EcosystemHomebrew  Ecosystem = "homebrew"
	EcosystemLua       Ecosystem = "lua"
	EcosystemDotNet    Ecosystem = "dotnet"
	EcosystemNix       Ecosystem = "nix"
	EcosystemOCaml     Ecosystem = "ocaml"
	EcosystemPHP       Ecosystem = "php"
	EcosystemPortage   Ecosystem = "portage"
	EcosystemProlog    Ecosystem = "prolog"
	EcosystemR         Ecosystem = "r"
	EcosystemRPM       Ecosystem = "rpm"
	EcosystemRuby      Ecosystem = "ruby"
	EcosystemRust      Ecosystem = "rust"
	EcosystemSBOM      Ecosystem = "sbom"
	EcosystemSnap      Ecosystem = "snap"
	EcosystemSwift     Ecosystem = "swift"
	EcosystemTerraform Ecosystem = "terraform"
	EcosystemWordPress Ecosystem = "wordpress"
)

// ParseEcosystem normalizes a user-provided ecosystem value.
func ParseEcosystem(value string) (Ecosystem, error) {
	return parseKnownEcosystem(value)
}

// DetectorType distinguishes detector and auditor implementation families.
type DetectorType string

const (
	NativeDetector         DetectorType = "native"
	LockfileParserDetector DetectorType = "lockfile-parser"
	ThirdPartyDetector     DetectorType = "third-party"
	PluginDetector         DetectorType = "plugin"
)

// TargetMode describes whether an operation targets a whole graph or a single component.
type TargetMode string

const (
	// TargetModeFullGraph requests whole-project resolution or analysis.
	TargetModeFullGraph TargetMode = "full-graph"
	// TargetModeComponent requests a single-component targeted query.
	TargetModeComponent TargetMode = "component"
)

// DetectorFilter narrows detector selection for a request.
type DetectorFilter struct {
	Include []string
	Exclude []string
}

// AuditorFilter narrows auditor selection for a request.
type AuditorFilter struct {
	Include []string
	Exclude []string
}

// MatcherFilter narrows matcher selection for a request.
type MatcherFilter struct {
	Include []string
	Exclude []string
}

// Includes reports whether an auditor name is explicitly allowed.
func (f AuditorFilter) Includes(name string) bool {
	return includesName(f.Include, name)
}

// Excludes reports whether an auditor name is explicitly denied.
func (f AuditorFilter) Excludes(name string) bool {
	return excludesName(f.Exclude, name)
}

// Includes reports whether a matcher name is explicitly allowed.
func (f MatcherFilter) Includes(name string) bool {
	return includesName(f.Include, name)
}

// Excludes reports whether a matcher name is explicitly denied.
func (f MatcherFilter) Excludes(name string) bool {
	return excludesName(f.Exclude, name)
}

// Includes reports whether a detector name is explicitly allowed.
func (f DetectorFilter) Includes(name string) bool {
	return includesName(f.Include, name)
}

// Excludes reports whether a detector name is explicitly denied.
func (f DetectorFilter) Excludes(name string) bool {
	return excludesName(f.Exclude, name)
}

func includesName(include []string, name string) bool {
	if len(include) == 0 {
		return true
	}
	for _, candidate := range include {
		if candidate == name {
			return true
		}
	}
	return false
}

func excludesName(exclude []string, name string) bool {
	for _, candidate := range exclude {
		if candidate == name {
			return true
		}
	}
	return false
}

func parseKnownEcosystem(value string) (Ecosystem, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return EcosystemUnknown, fmt.Errorf("ecosystem is empty")
	}
	for _, item := range ecosystemRegistry {
		if normalized == string(item.Ecosystem) {
			return item.Ecosystem, nil
		}
		for _, alias := range item.Aliases {
			if normalized == alias {
				return item.Ecosystem, nil
			}
		}
	}
	return EcosystemUnknown, fmt.Errorf("unsupported ecosystem %q", value)
}
