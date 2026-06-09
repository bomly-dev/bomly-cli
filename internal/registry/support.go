package registry

import (
	"strings"

	rootdetectors "github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/detectors/cargo"
	"github.com/bomly-dev/bomly-cli/internal/detectors/cocoapods"
	"github.com/bomly-dev/bomly-cli/internal/detectors/composer"
	"github.com/bomly-dev/bomly-cli/internal/detectors/conan"
	"github.com/bomly-dev/bomly-cli/internal/detectors/githubactions"
	"github.com/bomly-dev/bomly-cli/internal/detectors/gomod"
	"github.com/bomly-dev/bomly-cli/internal/detectors/gradle"
	"github.com/bomly-dev/bomly-cli/internal/detectors/maven"
	"github.com/bomly-dev/bomly-cli/internal/detectors/mix"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node/npm"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node/pnpm"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node/yarn"
	"github.com/bomly-dev/bomly-cli/internal/detectors/nuget"
	"github.com/bomly-dev/bomly-cli/internal/detectors/pub"
	"github.com/bomly-dev/bomly-cli/internal/detectors/python"
	"github.com/bomly-dev/bomly-cli/internal/detectors/ruby"
	sbomdetector "github.com/bomly-dev/bomly-cli/internal/detectors/sbom"
	"github.com/bomly-dev/bomly-cli/internal/detectors/sbt"
	"github.com/bomly-dev/bomly-cli/internal/detectors/swiftpm"
	"github.com/bomly-dev/bomly-cli/internal/detectors/syft"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// PackageManagerSupport records Bomly's built-in support metadata for one package manager.
type PackageManagerSupport struct {
	Manager                    sdk.PackageManager
	Ecosystem                  sdk.Ecosystem
	Aliases                    []string
	EvidencePatterns           []string
	Detectors                  []string
	EvidencePatternsByDetector map[string][]string
}

// OperatingSystemSupport records the container OS families Syft documents support for.
type OperatingSystemSupport struct {
	Name          string
	Aliases       []string
	Provider      string
	VersionSource string
}

var packageManagerSupport = buildPackageManagerSupportCatalog(builtInSupportDetectors())
var detectorOriginByName = buildDetectorOriginCatalog(builtInSupportDetectors())
var detectorTechniqueByName = buildDetectorTechniqueCatalog(builtInSupportDetectors())

var operatingSystemSupport = []OperatingSystemSupport{
	{Name: "alpine", Provider: "apk-db-cataloger", VersionSource: "/etc/os-release"},
	{Name: "amazon linux", Aliases: []string{"amzn"}, Provider: "rpm-db-cataloger", VersionSource: "/etc/os-release"},
	{Name: "busybox", Provider: "busybox-cataloger", VersionSource: "busybox binary metadata"},
	{Name: "centos", Provider: "rpm-db-cataloger", VersionSource: "/etc/os-release"},
	{Name: "debian", Provider: "dpkg-db-cataloger", VersionSource: "/etc/os-release"},
	{Name: "distroless", Provider: "os-release-cataloger", VersionSource: "/etc/os-release"},
	{Name: "photon", Provider: "rpm-db-cataloger", VersionSource: "/etc/os-release"},
	{Name: "red hat", Aliases: []string{"rhel", "ubi"}, Provider: "rpm-db-cataloger", VersionSource: "/etc/os-release"},
	{Name: "rocky linux", Aliases: []string{"rocky"}, Provider: "rpm-db-cataloger", VersionSource: "/etc/os-release"},
	{Name: "sles", Aliases: []string{"suse", "opensuse", "opensuse leap"}, Provider: "rpm-db-cataloger", VersionSource: "/etc/os-release"},
	{Name: "ubuntu", Provider: "dpkg-db-cataloger", VersionSource: "/etc/os-release"},
	{Name: "wolfi", Provider: "apk-db-cataloger", VersionSource: "/etc/os-release"},
}

func builtInSupportDetectors() []sdk.Detector {
	return []sdk.Detector{
		npm.LockfileDetector{},
		npm.NativeDetector{},
		pnpm.LockfileDetector{},
		pnpm.NativeDetector{},
		yarn.LockfileDetector{},
		yarn.NativeDetector{},
		gradle.Detector{},
		maven.Detector{},
		gomod.Detector{},
		composer.Detector{},
		ruby.Detector{},
		githubactions.Detector{},
		python.PipDetector{},
		python.PipenvDetector{},
		python.PoetryDetector{},
		python.UVDetector{},
		nuget.Detector{},
		cargo.Detector{},
		pub.NativeDetector{},
		pub.Detector{},
		cocoapods.Detector{},
		swiftpm.NativeDetector{},
		swiftpm.Detector{},
		mix.Detector{},
		conan.Detector{},
		sbt.NativeDetector{},
		sbt.Detector{},
		sbomdetector.Detector{},
		syft.Detector{},
	}
}

// SupportedPackageManagers returns package managers known to Bomly's built-in registry.
func SupportedPackageManagers() []sdk.PackageManager {
	values := make([]sdk.PackageManager, 0, len(packageManagerSupport))
	for _, manager := range sdk.AllPackageManagers() {
		if _, ok := packageManagerSupport[manager]; ok {
			values = append(values, manager)
		}
	}
	return values
}

// SupportedEcosystems returns ecosystems known to Bomly's built-in support catalog.
func SupportedEcosystems() []sdk.Ecosystem {
	seen := make(map[sdk.Ecosystem]struct{})
	values := make([]sdk.Ecosystem, 0)
	for _, manager := range SupportedPackageManagers() {
		ecosystem := manager.Ecosystem()
		if ecosystem == sdk.EcosystemUnknown {
			continue
		}
		if _, ok := seen[ecosystem]; ok {
			continue
		}
		seen[ecosystem] = struct{}{}
		values = append(values, ecosystem)
	}
	return values
}

// EcosystemAliasMap returns accepted CLI ecosystem aliases to canonical values.
func EcosystemAliasMap() map[string]string {
	aliases := make(map[string]string)
	for _, ecosystem := range SupportedEcosystems() {
		aliases[string(ecosystem)] = string(ecosystem)
	}
	aliases[sdk.PackageManagerGradle.Name()] = string(sdk.EcosystemMaven)
	return aliases
}

// EvidencePatternsForPackageManager returns built-in discovery evidence patterns.
func EvidencePatternsForPackageManager(manager sdk.PackageManager) []string {
	entry, ok := packageManagerSupport[manager]
	if !ok {
		return nil
	}
	return append([]string(nil), entry.EvidencePatterns...)
}

// DetectorNamesForPackageManager returns the built-in detector chain for a package manager.
func DetectorNamesForPackageManager(manager sdk.PackageManager) []string {
	entry, ok := packageManagerSupport[manager]
	if !ok {
		return nil
	}
	return append([]string(nil), entry.Detectors...)
}

// PackageManagersByDetector returns package managers whose built-in chain includes detectorName.
func PackageManagersByDetector(detectorName string) ([]sdk.PackageManager, bool) {
	values := make([]sdk.PackageManager, 0)
	for _, manager := range SupportedPackageManagers() {
		for _, detector := range DetectorNamesForPackageManager(manager) {
			if detector == detectorName {
				values = append(values, manager)
				break
			}
		}
	}
	if len(values) == 0 {
		return nil, false
	}
	return values, true
}

// SupportedPackageManagersForDetector returns package managers supported by a built-in detector.
func SupportedPackageManagersForDetector(detectorName string) []sdk.PackageManager {
	values, _ := PackageManagersByDetector(detectorName)
	return values
}

// SupportedEcosystemsForDetector returns ecosystems supported by a built-in detector.
func SupportedEcosystemsForDetector(detectorName string) []sdk.Ecosystem {
	seen := make(map[sdk.Ecosystem]struct{})
	values := make([]sdk.Ecosystem, 0)
	for _, manager := range SupportedPackageManagersForDetector(detectorName) {
		ecosystem := manager.Ecosystem()
		if ecosystem == sdk.EcosystemUnknown {
			continue
		}
		if _, ok := seen[ecosystem]; ok {
			continue
		}
		seen[ecosystem] = struct{}{}
		values = append(values, ecosystem)
	}
	return values
}

// DetectorOriginForName returns the origin for a built-in detector name.
func DetectorOriginForName(name string) sdk.DetectorOrigin {
	return detectorOriginByName[strings.TrimSpace(name)]
}

// DetectorTechniqueForName returns the detection technique for a built-in detector name.
func DetectorTechniqueForName(name string) sdk.DetectorTechnique {
	return detectorTechniqueByName[strings.TrimSpace(name)]
}

// SupportEntries returns Bomly's built-in package-manager support catalog.
func SupportEntries() []PackageManagerSupport {
	values := make([]PackageManagerSupport, 0, len(packageManagerSupport))
	for _, manager := range sdk.AllPackageManagers() {
		if entry, ok := packageManagerSupport[manager]; ok {
			values = append(values, cloneSupport(entry))
		}
	}
	return values
}

// SupportEntriesForTechnique returns support entries backed by the requested detector technique.
func SupportEntriesForTechnique(technique sdk.DetectorTechnique) []PackageManagerSupport {
	values := make([]PackageManagerSupport, 0)
	for _, entry := range SupportEntries() {
		filtered := entry
		filtered.EvidencePatterns = nil
		filtered.Detectors = nil
		filtered.EvidencePatternsByDetector = nil
		for _, detector := range entry.Detectors {
			if DetectorTechniqueForName(detector) == technique {
				filtered.Detectors = appendUniqueStrings(filtered.Detectors, detector)
				filtered.EvidencePatterns = appendUniqueStrings(filtered.EvidencePatterns, entry.EvidencePatternsByDetector[detector]...)
				if filtered.EvidencePatternsByDetector == nil {
					filtered.EvidencePatternsByDetector = make(map[string][]string)
				}
				filtered.EvidencePatternsByDetector[detector] = appendUniqueStrings(filtered.EvidencePatternsByDetector[detector], entry.EvidencePatternsByDetector[detector]...)
			}
		}
		if len(filtered.Detectors) > 0 {
			values = append(values, filtered)
		}
	}
	return values
}

// SupportedOperatingSystems returns the documented OS families supported through Syft container scanning.
func SupportedOperatingSystems() []OperatingSystemSupport {
	values := make([]OperatingSystemSupport, len(operatingSystemSupport))
	copy(values, operatingSystemSupport)
	return values
}

func buildPackageManagerSupportCatalog(detectorList []sdk.Detector) map[sdk.PackageManager]PackageManagerSupport {
	catalog := make(map[sdk.PackageManager]PackageManagerSupport)
	for _, detector := range detectorList {
		if detector == nil {
			continue
		}
		descriptor := detector.Descriptor()
		for _, support := range detector.PackageManagerSupport() {
			if support.PackageManager == sdk.PackageManagerUnknown || support.PackageManager == sdk.PackageManagerOther {
				continue
			}
			entry := catalog[support.PackageManager]
			if entry.Manager == sdk.PackageManagerUnknown {
				entry.Manager = support.PackageManager
				entry.Ecosystem = support.PackageManager.Ecosystem()
			}
			entry.EvidencePatterns = appendUniqueStrings(entry.EvidencePatterns, support.EvidencePatterns...)
			entry.Detectors = appendUniqueStrings(entry.Detectors, descriptor.Name)
			if entry.EvidencePatternsByDetector == nil {
				entry.EvidencePatternsByDetector = make(map[string][]string)
			}
			entry.EvidencePatternsByDetector[descriptor.Name] = appendUniqueStrings(entry.EvidencePatternsByDetector[descriptor.Name], support.EvidencePatterns...)
			catalog[support.PackageManager] = entry
		}
	}
	return catalog
}

func buildDetectorOriginCatalog(detectorList []sdk.Detector) map[string]sdk.DetectorOrigin {
	catalog := make(map[string]sdk.DetectorOrigin, len(detectorList))
	for _, detector := range detectorList {
		if detector == nil {
			continue
		}
		descriptor := detector.Descriptor()
		if descriptor.Name == "" {
			continue
		}
		if descriptor.Name == rootdetectors.NameSyft {
			catalog[descriptor.Name] = sdk.BundledOrigin
		} else {
			catalog[descriptor.Name] = sdk.CoreOrigin
		}
	}
	return catalog
}

func buildDetectorTechniqueCatalog(detectorList []sdk.Detector) map[string]sdk.DetectorTechnique {
	catalog := make(map[string]sdk.DetectorTechnique, len(detectorList))
	for _, detector := range detectorList {
		if detector == nil {
			continue
		}
		descriptor := detector.Descriptor()
		if descriptor.Name == "" {
			continue
		}
		catalog[descriptor.Name] = descriptor.Technique
	}
	return catalog
}

func appendUniqueStrings(values []string, additions ...string) []string {
	for _, value := range additions {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		seen := false
		for _, existing := range values {
			if existing == value {
				seen = true
				break
			}
		}
		if !seen {
			values = append(values, value)
		}
	}
	return values
}

func cloneSupport(entry PackageManagerSupport) PackageManagerSupport {
	entry.Aliases = append([]string(nil), entry.Aliases...)
	entry.EvidencePatterns = append([]string(nil), entry.EvidencePatterns...)
	entry.Detectors = append([]string(nil), entry.Detectors...)
	if len(entry.EvidencePatternsByDetector) > 0 {
		clone := make(map[string][]string, len(entry.EvidencePatternsByDetector))
		for detector, patterns := range entry.EvidencePatternsByDetector {
			clone[detector] = append([]string(nil), patterns...)
		}
		entry.EvidencePatternsByDetector = clone
	}
	return entry
}
