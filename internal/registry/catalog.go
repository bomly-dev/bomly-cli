package registry

import "github.com/bomly/bomly-cli/internal/model"

// PackageManager identifies the concrete package manager or manifest family for a target.
type PackageManager = model.PackageManager

const (
	PackageManagerUnknown       PackageManager = model.PackageManagerUnknown
	PackageManagerNPM           PackageManager = model.PackageManagerNPM
	PackageManagerPNPM          PackageManager = model.PackageManagerPNPM
	PackageManagerYarn          PackageManager = model.PackageManagerYarn
	PackageManagerGradle        PackageManager = model.PackageManagerGradle
	PackageManagerMaven         PackageManager = model.PackageManagerMaven
	PackageManagerGoMod         PackageManager = model.PackageManagerGoMod
	PackageManagerPip           PackageManager = model.PackageManagerPip
	PackageManagerPipenv        PackageManager = model.PackageManagerPipenv
	PackageManagerPoetry        PackageManager = model.PackageManagerPoetry
	PackageManagerUV            PackageManager = model.PackageManagerUV
	PackageManagerALPM          PackageManager = model.PackageManagerALPM
	PackageManagerAPK           PackageManager = model.PackageManagerAPK
	PackageManagerConan         PackageManager = model.PackageManagerConan
	PackageManagerConda         PackageManager = model.PackageManagerConda
	PackageManagerPub           PackageManager = model.PackageManagerPub
	PackageManagerDPKG          PackageManager = model.PackageManagerDPKG
	PackageManagerMix           PackageManager = model.PackageManagerMix
	PackageManagerRebar         PackageManager = model.PackageManagerRebar
	PackageManagerOTP           PackageManager = model.PackageManagerOTP
	PackageManagerGitHubActions PackageManager = model.PackageManagerGitHubActions
	PackageManagerCabal         PackageManager = model.PackageManagerCabal
	PackageManagerStack         PackageManager = model.PackageManagerStack
	PackageManagerHomebrew      PackageManager = model.PackageManagerHomebrew
	PackageManagerLuaRocks      PackageManager = model.PackageManagerLuaRocks
	PackageManagerNuGet         PackageManager = model.PackageManagerNuGet
	PackageManagerNix           PackageManager = model.PackageManagerNix
	PackageManagerOpam          PackageManager = model.PackageManagerOpam
	PackageManagerComposer      PackageManager = model.PackageManagerComposer
	PackageManagerPear          PackageManager = model.PackageManagerPear
	PackageManagerPDM           PackageManager = model.PackageManagerPDM
	PackageManagerPortage       PackageManager = model.PackageManagerPortage
	PackageManagerSWIPLPack     PackageManager = model.PackageManagerSWIPLPack
	PackageManagerRPackage      PackageManager = model.PackageManagerRPackage
	PackageManagerRPM           PackageManager = model.PackageManagerRPM
	PackageManagerBundler       PackageManager = model.PackageManagerBundler
	PackageManagerGemspec       PackageManager = model.PackageManagerGemspec
	PackageManagerCargo         PackageManager = model.PackageManagerCargo
	PackageManagerSBOM          PackageManager = model.PackageManagerSBOM
	PackageManagerSnap          PackageManager = model.PackageManagerSnap
	PackageManagerCocoaPods     PackageManager = model.PackageManagerCocoaPods
	PackageManagerSwiftPM       PackageManager = model.PackageManagerSwiftPM
	PackageManagerTerraform     PackageManager = model.PackageManagerTerraform
	PackageManagerWordPress     PackageManager = model.PackageManagerWordPress
	PackageManagerSetupPy       PackageManager = model.PackageManagerSetupPy
)

// PackageManagerMeta records the canonical support metadata for one package manager.
type PackageManagerMeta = model.PackageManagerMeta

// PackageManagerSupport records the canonical support metadata for one package manager.
type PackageManagerSupport = model.PackageManagerSupport

// OperatingSystemSupport records the container OS families Syft documents support for.
type OperatingSystemSupport = model.OperatingSystemSupport

// ParsePackageManager normalizes a user-provided package-manager value.
func ParsePackageManager(value string) (PackageManager, error) {
	return model.ParsePackageManager(value)
}

// AllPackageManagers returns the canonical package-manager list in registry order.
func AllPackageManagers() []PackageManager {
	return model.AllPackageManagers()
}

// SupportedPackageManagers returns all package managers known to the built-in support registry.
func SupportedPackageManagers() []PackageManager {
	return model.SupportedPackageManagers()
}

// PackageManagerByName looks up a package manager by canonical name or alias.
func PackageManagerByName(name string) (PackageManager, bool) {
	return model.PackageManagerByName(name)
}

// PackageManagersByEcosystem returns package managers grouped under one ecosystem.
func PackageManagersByEcosystem(ecosystem Ecosystem) ([]PackageManager, bool) {
	return model.PackageManagersByEcosystem(ecosystem)
}

// PackageManagersByEvidencePattern returns package managers keyed by one evidence pattern.
func PackageManagersByEvidencePattern(pattern string) ([]PackageManager, bool) {
	return model.PackageManagersByEvidencePattern(pattern)
}

// PackageManagersByDetector returns package managers that include the named detector in their chain.
func PackageManagersByDetector(detectorName string) ([]PackageManager, bool) {
	return model.PackageManagersByDetector(detectorName)
}

// PackageManagersByEcosystemAndDetectorType returns package managers narrowed to one ecosystem and detector family.
func PackageManagersByEcosystemAndDetectorType(ecosystem Ecosystem, detectorType DetectorType) ([]PackageManager, bool) {
	return model.PackageManagersByEcosystemAndDetectorType(ecosystem, detectorType)
}

// DetectorTypeForName returns the implementation family for a built-in detector name.
func DetectorTypeForName(name string) DetectorType {
	return model.DetectorTypeForName(name)
}

// SupportedEcosystems returns all canonical ecosystems known to the built-in support registry.
func SupportedEcosystems() []Ecosystem {
	return model.SupportedEcosystems()
}

// SupportEntries returns a copy of the canonical package-manager support registry.
func SupportEntries() []PackageManagerSupport {
	return model.SupportEntries()
}

// SupportEntriesForDetectorType returns package-manager entries supported by the given detector type.
func SupportEntriesForDetectorType(detectorType DetectorType) []PackageManagerSupport {
	return model.SupportEntriesForDetectorType(detectorType)
}

// SupportedEcosystemsForDetector returns canonical ecosystems supported by the named detector.
func SupportedEcosystemsForDetector(detectorName string) []Ecosystem {
	return model.SupportedEcosystemsForDetector(detectorName)
}

// SupportedEcosystemsForDetectorType returns canonical ecosystems supported by the given detector type.
func SupportedEcosystemsForDetectorType(detectorType DetectorType) []Ecosystem {
	return model.SupportedEcosystemsForDetectorType(detectorType)
}

// SupportedPackageManagersForDetector returns package managers supported by the named detector.
func SupportedPackageManagersForDetector(detectorName string) []PackageManager {
	return model.SupportedPackageManagersForDetector(detectorName)
}

// PreferredPackageManagersForDetector returns package managers whose preferred detector matches detectorName.
func PreferredPackageManagersForDetector(detectorName string) []PackageManager {
	return model.PreferredPackageManagersForDetector(detectorName)
}

// SupportedPackageManagersForDetectorType returns package managers supported by the given detector type.
func SupportedPackageManagersForDetectorType(detectorType DetectorType) []PackageManager {
	return model.SupportedPackageManagersForDetectorType(detectorType)
}

// SupportedOperatingSystems returns the documented OS families supported through Syft container scanning.
func SupportedOperatingSystems() []OperatingSystemSupport {
	return model.SupportedOperatingSystems()
}

// EvidencePatternsForPackageManager returns the configured manifest or database evidence patterns.
func EvidencePatternsForPackageManager(manager PackageManager) []string {
	return model.EvidencePatternsForPackageManager(manager)
}

// PreferredPackageManagerForEcosystem returns the default package manager label for an ecosystem.
func PreferredPackageManagerForEcosystem(ecosystem Ecosystem) (PackageManager, bool) {
	return model.PreferredPackageManagerForEcosystem(ecosystem)
}

// SupportedDetectors returns the unique detector names registered in support metadata order.
func SupportedDetectors() []string {
	return model.SupportedDetectors()
}

// PreferredEcosystemsForDetector returns ecosystems whose preferred package managers are backed by detectorName.
func PreferredEcosystemsForDetector(detectorName string) []Ecosystem {
	return model.PreferredEcosystemsForDetector(detectorName)
}
