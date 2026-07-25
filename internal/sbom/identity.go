package sbom

import (
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/bomly-dev/bomly-cli/sdk"
)

func parsePURL(value string) *packageurl.PackageURL {
	return sdk.ParsePackageURL(strings.TrimSpace(value))
}

// purlTypeEcosystems inverts sdk.PackageURLTypeForValues for the purl types
// whose spec name differs from the Bomly ecosystem name. Without these, a PURL
// Bomly itself emitted would not round-trip through SBOM ingest: ParseEcosystem
// only knows Bomly's own identifiers.
var purlTypeEcosystems = map[string]sdk.Ecosystem{
	"golang": sdk.EcosystemGo,
	// Elixir and Erlang share pkg:hex; Elixir is the far more common source of
	// a hex PURL, and the component's own ecosystem field wins when present.
	"hex":       sdk.EcosystemElixir,
	"hackage":   sdk.EcosystemHaskell,
	"cran":      sdk.EcosystemR,
	"opam":      sdk.EcosystemOCaml,
	"deb":       sdk.EcosystemDPKG,
	"cargo":     sdk.EcosystemRust,
	"nuget":     sdk.EcosystemDotNet,
	"pypi":      sdk.EcosystemPython,
	"gem":       sdk.EcosystemRuby,
	"composer":  sdk.EcosystemPHP,
	"pub":       sdk.EcosystemDart,
	"conan":     sdk.EcosystemCPP,
	"cocoapods": sdk.EcosystemSwift,
	"swift":     sdk.EcosystemSwift,
	// pkg:maven covers Scala too, but Java is the overwhelmingly common case
	// and there is nothing in the PURL to tell them apart.
	"maven":         sdk.EcosystemMaven,
	"githubactions": sdk.EcosystemGitHub,
}

func ecosystemFromPURLType(purlType string) sdk.Ecosystem {
	normalized := strings.ToLower(strings.TrimSpace(purlType))
	if ecosystem, ok := purlTypeEcosystems[normalized]; ok {
		return ecosystem
	}
	switch normalized {
	case "":
		return sdk.EcosystemUnknown
	default:
		ecosystem, err := sdk.ParseEcosystem(normalized)
		if err != nil {
			return sdk.EcosystemUnknown
		}
		return ecosystem
	}
}

func packageManagerForPURL(value string, ecosystemHint, packageManagerHint string) sdk.PackageManager {
	if manager, ok := parsePackageManagerHint(packageManagerHint); ok {
		return manager
	}
	if purl := parsePURL(value); purl != nil {
		if manager, ok := packageManagerForPURLType(purl.Type); ok {
			return manager
		}
	}
	if ecosystem, ok := parseEcosystemHint(ecosystemHint); ok {
		if manager, ok := preferredPackageManagerForEcosystem(ecosystem); ok {
			return manager
		}
	}
	return sdk.PackageManagerUnknown
}

func packageManagerForPURLType(purlType string) (sdk.PackageManager, bool) {
	ecosystem := ecosystemFromPURLType(purlType)
	if ecosystem == sdk.EcosystemUnknown {
		return sdk.PackageManagerUnknown, false
	}
	manager, ok := preferredPackageManagerForEcosystem(ecosystem)
	return manager, ok
}

func preferredPackageManagerForEcosystem(ecosystem sdk.Ecosystem) (sdk.PackageManager, bool) {
	for _, manager := range sdk.AllPackageManagers() {
		if manager.Ecosystem() == ecosystem {
			return manager, true
		}
	}
	return sdk.PackageManagerUnknown, false
}

func parsePackageManagerHint(value string) (sdk.PackageManager, bool) {
	manager, err := sdk.ParsePackageManager(value)
	if err != nil {
		return sdk.PackageManagerUnknown, false
	}
	return manager, true
}

func parseEcosystemHint(value string) (sdk.Ecosystem, bool) {
	ecosystem, err := sdk.ParseEcosystem(value)
	if err != nil {
		return sdk.EcosystemUnknown, false
	}
	return ecosystem, true
}
