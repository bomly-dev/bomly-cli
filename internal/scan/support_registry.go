package scan

import "github.com/bomly/bomly-cli/internal/model"

// PackageManagerSupport records the canonical support metadata for one package manager.
type PackageManagerSupport = model.PackageManagerSupport

// OperatingSystemSupport records the container OS families Syft documents support for.
type OperatingSystemSupport = model.OperatingSystemSupport

// SupportedEcosystems returns all canonical ecosystems known to the built-in support registry.
func SupportedEcosystems() []Ecosystem {
	return model.SupportedEcosystems()
}

// SupportedPackageManagers returns all package managers known to the built-in support registry.
func SupportedPackageManagers() []PackageManager {
	return model.SupportedPackageManagers()
}

// SupportedDetectors returns the unique detector names registered in support metadata order.
func SupportedDetectors() []string {
	return model.SupportedDetectors()
}

// SupportedEcosystemsForDetector returns canonical ecosystems supported by the named detector.
func SupportedEcosystemsForDetector(detectorName string) []Ecosystem {
	return model.SupportedEcosystemsForDetector(detectorName)
}

// SupportedPackageManagersForDetector returns package managers supported by the named detector.
func SupportedPackageManagersForDetector(detectorName string) []PackageManager {
	return model.SupportedPackageManagersForDetector(detectorName)
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

// PreferredPackageManagerForEcosystem returns the default package manager label for an ecosystem.
func PreferredPackageManagerForEcosystem(ecosystem Ecosystem) (PackageManager, bool) {
	return model.PreferredPackageManagerForEcosystem(ecosystem)
}

// RenderSupportMatrixMarkdown renders the canonical markdown support matrix document.
func RenderSupportMatrixMarkdown() string {
	return model.RenderSupportMatrixMarkdown()
}
