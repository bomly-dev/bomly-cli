package sdk

import (
	"fmt"
	"strings"
)

// Ecosystem groups package managers under a registry-specific dependency model.
type Ecosystem string

// Keep this list aligned with the Syft-backed support matrix in docs/SUPPORT_MATRIX.md
// and the Syft manifest mappings in internal/detectors/syft/detector.go.
const (
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
	EcosystemScala     Ecosystem = "scala"
	EcosystemSBOM      Ecosystem = "sbom"
	EcosystemSnap      Ecosystem = "snap"
	EcosystemSwift     Ecosystem = "swift"
	EcosystemTerraform Ecosystem = "terraform"
	EcosystemWordPress Ecosystem = "wordpress"
	EcosystemOther     Ecosystem = "other"
)

// ParseEcosystem normalizes a user-provided ecosystem value.
func ParseEcosystem(value string) (Ecosystem, error) {
	return parseKnownEcosystem(value)
}

// EcosystemFilter specifies inclusion and exclusion rules for filtering ecosystems.
type EcosystemFilter struct {
	Include []Ecosystem
	Exclude []Ecosystem
}

// Includes reports whether a detector name is explicitly allowed.
func (f EcosystemFilter) Includes(name Ecosystem) bool {
	includes := make([]string, 0, len(f.Include))
	for _, item := range f.Include {
		includes = append(includes, string(item))
	}
	return includesName(includes, string(name))
}

// Excludes reports whether a detector name is explicitly denied.
func (f EcosystemFilter) Excludes(name Ecosystem) bool {
	excludes := make([]string, 0, len(f.Exclude))
	for _, item := range f.Exclude {
		excludes = append(excludes, string(item))
	}
	return excludesName(excludes, string(name))
}

type ecosystemSupport struct {
	Ecosystem Ecosystem
	Aliases   []string
}

var ecosystemRegistry = []ecosystemSupport{
	{Ecosystem: EcosystemNPM},
	{Ecosystem: EcosystemMaven, Aliases: []string{"gradle"}},
	{Ecosystem: EcosystemGo},
	{Ecosystem: EcosystemPython},
	{Ecosystem: EcosystemALPM},
	{Ecosystem: EcosystemAPK},
	{Ecosystem: EcosystemCPP},
	{Ecosystem: EcosystemConda},
	{Ecosystem: EcosystemDart},
	{Ecosystem: EcosystemDPKG},
	{Ecosystem: EcosystemElixir},
	{Ecosystem: EcosystemErlang},
	{Ecosystem: EcosystemGitHub},
	{Ecosystem: EcosystemHaskell},
	{Ecosystem: EcosystemHomebrew},
	{Ecosystem: EcosystemLua},
	{Ecosystem: EcosystemDotNet},
	{Ecosystem: EcosystemNix},
	{Ecosystem: EcosystemOCaml},
	{Ecosystem: EcosystemPHP},
	{Ecosystem: EcosystemPortage},
	{Ecosystem: EcosystemProlog},
	{Ecosystem: EcosystemR},
	{Ecosystem: EcosystemRPM},
	{Ecosystem: EcosystemRuby},
	{Ecosystem: EcosystemRust},
	{Ecosystem: EcosystemScala},
	{Ecosystem: EcosystemSBOM},
	{Ecosystem: EcosystemSnap},
	{Ecosystem: EcosystemSwift},
	{Ecosystem: EcosystemTerraform},
	{Ecosystem: EcosystemWordPress},
	{Ecosystem: EcosystemOther},
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
