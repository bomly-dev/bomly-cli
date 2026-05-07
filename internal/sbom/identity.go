package sbom

import (
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/bomly-dev/bomly-cli/sdk"
)

func parsePURL(value string) *packageurl.PackageURL {
	return sdk.ParsePackageURL(strings.TrimSpace(value))
}

func ecosystemFromPURLType(purlType string) sdk.Ecosystem {
	normalized := strings.ToLower(strings.TrimSpace(purlType))
	switch normalized {
	case "golang":
		return sdk.EcosystemGo
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
