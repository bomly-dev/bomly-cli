package sbom

import (
	"strings"

	"github.com/bomly-dev/bomly-sdk"
	"github.com/bomly-dev/bomly-sdk/purlkit"
)

// parsePURL delegates to purlkit, the SDK's kit over the official
// packageurl-go. sdk.ParsePackageURL was the deprecated anchore-fork entry
// point and is gone; the nil-on-failure shape is kept for callers.
func parsePURL(value string) *purlkit.PURL {
	parsed, err := purlkit.Parse(strings.TrimSpace(value))
	if err != nil {
		return nil
	}
	return &parsed
}

// purlTypeEcosystems inverts sdk.PackageURLTypeForValues for the purl types
// whose spec name differs from the Bomly ecosystem name. Without these, a PURL
// Bomly itself emitted would not round-trip through SBOM ingest: ParseEcosystem
// only knows Bomly's own identifiers.
//
// Types that two ecosystems share are deliberately absent. pkg:hex is emitted
// for both Elixir (mix) and Erlang (rebar), and nothing in the PURL says which;
// since the standard codecs do not carry Component.Ecosystem — CycloneDX drops
// it and SPDX rebuilds it from the PURL — guessing here would relabel every
// round-tripped Erlang dependency as Elixir, and packageManagerForPURLType
// would then call it Mix. Leaving it unknown keeps the ambiguity visible.
// The purl-type -> ecosystem question is the SDK's, answered by
// EcosystemForPURLType. It was reassembled here out of purlkit calls plus a
// fallback of this package's own, which is the same drift in a thinner
// disguise: the SDK grew a second lookup for manager-name aliases and this
// copy did not, so "swiftpm" resolved to unknown here and to swift there.
// Delegating picked that up rather than any change being made for it.
func ecosystemFromPURLType(purlType string) sdk.Ecosystem {
	return sdk.EcosystemForPURLType(purlType)
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
