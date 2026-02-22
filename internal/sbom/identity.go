package sbom

import (
	"strings"

	"github.com/anchore/packageurl-go"
	model "github.com/bomly-dev/bomly-cli/sdk"
)

func parsePURL(value string) *packageurl.PackageURL {
	return model.ParsePackageURL(strings.TrimSpace(value))
}

func ecosystemFromPURLType(purlType string) model.Ecosystem {
	normalized := strings.ToLower(strings.TrimSpace(purlType))
	switch normalized {
	case "golang":
		return model.EcosystemGo
	case "":
		return model.EcosystemUnknown
	default:
		ecosystem, err := model.ParseEcosystem(normalized)
		if err != nil {
			return model.EcosystemUnknown
		}
		return ecosystem
	}
}

func packageManagerForPURL(value string, ecosystemHint, packageManagerHint string) model.PackageManager {
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
	return model.PackageManagerUnknown
}

func packageManagerForPURLType(purlType string) (model.PackageManager, bool) {
	ecosystem := ecosystemFromPURLType(purlType)
	if ecosystem == model.EcosystemUnknown {
		return model.PackageManagerUnknown, false
	}
	manager, ok := preferredPackageManagerForEcosystem(ecosystem)
	return manager, ok
}

func preferredPackageManagerForEcosystem(ecosystem model.Ecosystem) (model.PackageManager, bool) {
	for _, manager := range model.AllPackageManagers() {
		if manager.Ecosystem() == ecosystem {
			return manager, true
		}
	}
	return model.PackageManagerUnknown, false
}

func parsePackageManagerHint(value string) (model.PackageManager, bool) {
	manager, err := model.ParsePackageManager(value)
	if err != nil {
		return model.PackageManagerUnknown, false
	}
	return manager, true
}

func parseEcosystemHint(value string) (model.Ecosystem, bool) {
	ecosystem, err := model.ParseEcosystem(value)
	if err != nil {
		return model.EcosystemUnknown, false
	}
	return ecosystem, true
}
