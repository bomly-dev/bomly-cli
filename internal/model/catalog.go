package model

import (
	"fmt"
	"strings"
)

// PackageManager identifies the concrete package manager or manifest family for a target.
type PackageManager int

const (
	PackageManagerUnknown PackageManager = iota
	PackageManagerNPM
	PackageManagerPNPM
	PackageManagerYarn
	PackageManagerGradle
	PackageManagerMaven
	PackageManagerGoMod
	PackageManagerPip
	PackageManagerPipenv
	PackageManagerPoetry
	PackageManagerUV
	PackageManagerALPM
	PackageManagerAPK
	PackageManagerConan
	PackageManagerConda
	PackageManagerPub
	PackageManagerDPKG
	PackageManagerMix
	PackageManagerRebar
	PackageManagerOTP
	PackageManagerGitHubActions
	PackageManagerCabal
	PackageManagerStack
	PackageManagerHomebrew
	PackageManagerLuaRocks
	PackageManagerNuGet
	PackageManagerNix
	PackageManagerOpam
	PackageManagerComposer
	PackageManagerPear
	PackageManagerPDM
	PackageManagerPortage
	PackageManagerSWIPLPack
	PackageManagerRPackage
	PackageManagerRPM
	PackageManagerBundler
	PackageManagerGemspec
	PackageManagerCargo
	PackageManagerSBOM
	PackageManagerSnap
	PackageManagerCocoaPods
	PackageManagerSwiftPM
	PackageManagerTerraform
	PackageManagerWordPress
	PackageManagerSetupPy
	PackageManagerCount
)

// PackageManagerMeta records the canonical support metadata for one package manager.
type PackageManagerMeta struct {
	Name             string
	Ecosystem        Ecosystem
	Aliases          []string
	EvidencePatterns []string
	Detectors        []string
}

// PackageManagerSupport records the canonical support metadata for one package manager.
type PackageManagerSupport struct {
	Manager          PackageManager
	Ecosystem        Ecosystem
	Aliases          []string
	EvidencePatterns []string
	Detectors        []string
}

var packageManagerRegistry = [...]PackageManagerMeta{
	PackageManagerUnknown: {},
	PackageManagerNPM: {
		Name:             "npm",
		Ecosystem:        EcosystemNPM,
		EvidencePatterns: []string{"package-lock.json", "package.json"},
		Detectors:        []string{"npm-detector", "syft-detector"},
	},
	PackageManagerPNPM: {
		Name:             "pnpm",
		Ecosystem:        EcosystemNPM,
		EvidencePatterns: []string{"pnpm-lock.yaml", "package.json"},
		Detectors:        []string{"pnpm-detector", "syft-detector"},
	},
	PackageManagerYarn: {
		Name:             "yarn",
		Ecosystem:        EcosystemNPM,
		EvidencePatterns: []string{"yarn.lock", "package.json"},
		Detectors:        []string{"yarn-detector", "syft-detector"},
	},
	PackageManagerGradle: {
		Name:             "gradle",
		Ecosystem:        EcosystemMaven,
		EvidencePatterns: []string{"build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts", "gradle.lockfile*"},
		Detectors:        []string{"gradle-detector", "syft-detector"},
	},
	PackageManagerMaven: {
		Name:             "maven",
		Ecosystem:        EcosystemMaven,
		EvidencePatterns: []string{"pom.xml", "*pom.xml"},
		Detectors:        []string{"maven-detector", "syft-detector"},
	},
	PackageManagerGoMod: {
		Name:             "gomod",
		Ecosystem:        EcosystemGo,
		EvidencePatterns: []string{"go.mod"},
		Detectors:        []string{"go-detector", "syft-detector"},
	},
	PackageManagerPip: {
		Name:             "pip",
		Ecosystem:        EcosystemPython,
		EvidencePatterns: []string{"requirements.txt", "requirements-dev.txt", "requirements.in", "requirements.lock", "*requirements*.txt"},
		Detectors:        []string{"pip-detector", "syft-detector"},
	},
	PackageManagerPipenv: {
		Name:             "pipenv",
		Ecosystem:        EcosystemPython,
		EvidencePatterns: []string{"Pipfile", "Pipfile.lock"},
		Detectors:        []string{"pipenv-detector", "syft-detector"},
	},
	PackageManagerPoetry: {
		Name:             "poetry",
		Ecosystem:        EcosystemPython,
		EvidencePatterns: []string{"poetry.lock", "pyproject.toml"},
		Detectors:        []string{"poetry-detector", "syft-detector"},
	},
	PackageManagerUV: {
		Name:             "uv",
		Ecosystem:        EcosystemPython,
		EvidencePatterns: []string{"uv.lock", "pyproject.toml"},
		Detectors:        []string{"uv-detector", "syft-detector"},
	},
	PackageManagerALPM: {
		Name:             "alpm",
		Ecosystem:        EcosystemALPM,
		EvidencePatterns: []string{"var/lib/pacman/local/*/desc"},
		Detectors:        []string{"syft-detector"},
	},
	PackageManagerAPK: {
		Name:             "apk",
		Ecosystem:        EcosystemAPK,
		EvidencePatterns: []string{"lib/apk/db/installed"},
		Detectors:        []string{"syft-detector"},
	},
	PackageManagerConan: {
		Name:             "conan",
		Ecosystem:        EcosystemCPP,
		EvidencePatterns: []string{"conan.lock", "conanfile.txt", "conaninfo.txt"},
		Detectors:        []string{"syft-detector"},
	},
	PackageManagerConda: {
		Name:             "conda",
		Ecosystem:        EcosystemConda,
		EvidencePatterns: []string{"conda-meta/*.json"},
		Detectors:        []string{"syft-detector"},
	},
	PackageManagerPub: {
		Name:             "pub",
		Ecosystem:        EcosystemDart,
		EvidencePatterns: []string{"pubspec.yml", "pubspec.yaml", "pubspec.lock"},
		Detectors:        []string{"syft-detector"},
	},
	PackageManagerDPKG: {
		Name:             "dpkg",
		Ecosystem:        EcosystemDPKG,
		EvidencePatterns: []string{"lib/dpkg/status", "lib/dpkg/status.d/*", "lib/opkg/info/*.control", "lib/opkg/status"},
		Detectors:        []string{"syft-detector"},
	},
	PackageManagerMix: {
		Name:             "mix",
		Ecosystem:        EcosystemElixir,
		EvidencePatterns: []string{"mix.lock"},
		Detectors:        []string{"syft-detector"},
	},
	PackageManagerRebar: {
		Name:             "rebar",
		Ecosystem:        EcosystemErlang,
		EvidencePatterns: []string{"rebar.lock"},
		Detectors:        []string{"syft-detector"},
	},
	PackageManagerOTP: {
		Name:             "otp",
		Ecosystem:        EcosystemErlang,
		EvidencePatterns: []string{"*.app"},
		Detectors:        []string{"syft-detector"},
	},
	PackageManagerGitHubActions: {
		Name:             "github-actions",
		Ecosystem:        EcosystemGitHub,
		EvidencePatterns: []string{".github/workflows/*.yaml", ".github/workflows/*.yml", ".github/actions/*/action.yml", ".github/actions/*/action.yaml"},
		Detectors:        []string{"github-actions-detector", "syft-detector"},
	},
	PackageManagerCabal: {
		Name:             "cabal",
		Ecosystem:        EcosystemHaskell,
		EvidencePatterns: []string{"cabal.project.freeze"},
		Detectors:        []string{"syft-detector"},
	},
	PackageManagerStack: {
		Name:             "stack",
		Ecosystem:        EcosystemHaskell,
		EvidencePatterns: []string{"stack.yaml", "stack.yaml.lock"},
		Detectors:        []string{"syft-detector"},
	},
	PackageManagerHomebrew: {
		Name:             "homebrew",
		Ecosystem:        EcosystemHomebrew,
		EvidencePatterns: []string{"Cellar/*/*/.brew/*.rb", "Library/Taps/*/*/Formula/*.rb"},
		Detectors:        []string{"syft-detector"},
	},
	PackageManagerLuaRocks: {
		Name:             "luarocks",
		Ecosystem:        EcosystemLua,
		EvidencePatterns: []string{"*.rockspec"},
		Detectors:        []string{"syft-detector"},
	},
	PackageManagerNuGet: {
		Name:             "nuget",
		Ecosystem:        EcosystemDotNet,
		EvidencePatterns: []string{"packages.lock.json", "*.deps.json"},
		Detectors:        []string{"syft-detector"},
	},
	PackageManagerNix: {
		Name:             "nix",
		Ecosystem:        EcosystemNix,
		EvidencePatterns: []string{"nix/var/nix/db/db.sqlite", "nix/store/*.drv"},
		Detectors:        []string{"syft-detector"},
	},
	PackageManagerOpam: {
		Name:             "opam",
		Ecosystem:        EcosystemOCaml,
		EvidencePatterns: []string{"*opam"},
		Detectors:        []string{"syft-detector"},
	},
	PackageManagerComposer: {
		Name:             "composer",
		Ecosystem:        EcosystemPHP,
		EvidencePatterns: []string{"composer.lock", "installed.json"},
		Detectors:        []string{"composer-detector", "syft-detector"},
	},
	PackageManagerPear: {
		Name:             "pear",
		Ecosystem:        EcosystemPHP,
		EvidencePatterns: []string{"php/.registry/**/*.reg"},
		Detectors:        []string{"syft-detector"},
	},
	PackageManagerPDM: {
		Name:             "pdm",
		Ecosystem:        EcosystemPython,
		EvidencePatterns: []string{"pdm.lock", "pyproject.toml"},
		Detectors:        []string{"syft-detector"},
	},
	PackageManagerPortage: {
		Name:             "portage",
		Ecosystem:        EcosystemPortage,
		EvidencePatterns: []string{"var/db/pkg/*/*/CONTENTS"},
		Detectors:        []string{"syft-detector"},
	},
	PackageManagerSWIPLPack: {
		Name:             "swipl-pack",
		Ecosystem:        EcosystemProlog,
		EvidencePatterns: []string{"pack.pl"},
		Detectors:        []string{"syft-detector"},
	},
	PackageManagerRPackage: {
		Name:             "r-package",
		Ecosystem:        EcosystemR,
		EvidencePatterns: []string{"DESCRIPTION"},
		Detectors:        []string{"syft-detector"},
	},
	PackageManagerRPM: {
		Name:             "rpm",
		Ecosystem:        EcosystemRPM,
		EvidencePatterns: []string{"var/lib/rpmmanifest/container-manifest-2", "var/lib/rpm/Packages", "var/lib/rpm/Packages.db", "var/lib/rpm/rpmdb.sqlite", "usr/share/rpm/Packages", "usr/share/rpm/Packages.db", "usr/share/rpm/rpmdb.sqlite", "usr/lib/sysimage/rpm/Packages", "usr/lib/sysimage/rpm/Packages.db", "usr/lib/sysimage/rpm/rpmdb.sqlite"},
		Detectors:        []string{"syft-detector"},
	},
	PackageManagerBundler: {
		Name:             "bundler",
		Ecosystem:        EcosystemRuby,
		EvidencePatterns: []string{"Gemfile.lock", "Gemfile.next.lock"},
		Detectors:        []string{"bundler-detector", "syft-detector"},
	},
	PackageManagerGemspec: {
		Name:             "gemspec",
		Ecosystem:        EcosystemRuby,
		EvidencePatterns: []string{"*.gemspec"},
		Detectors:        []string{"syft-detector"},
	},
	PackageManagerCargo: {
		Name:             "cargo",
		Ecosystem:        EcosystemRust,
		EvidencePatterns: []string{"Cargo.lock"},
		Detectors:        []string{"syft-detector"},
	},
	PackageManagerSBOM: {
		Name:             "sbom",
		Ecosystem:        EcosystemSBOM,
		EvidencePatterns: []string{"*.syft.json", "*.bom.*", "*.bom", "bom", "*.sbom.*", "*.sbom", "sbom", "*.cdx.*", "*.cdx", "*.spdx.*", "*.spdx"},
		Detectors:        []string{"sbom-detector"},
	},
	PackageManagerSnap: {
		Name:             "snap",
		Ecosystem:        EcosystemSnap,
		EvidencePatterns: []string{"snap/snapcraft.yaml", "snap/manifest.yaml", "doc/linux-modules-*/changelog.Debian.gz", "usr/share/snappy/dpkg.yaml"},
		Detectors:        []string{"syft-detector"},
	},
	PackageManagerCocoaPods: {
		Name:             "cocoapods",
		Ecosystem:        EcosystemSwift,
		EvidencePatterns: []string{"Podfile.lock"},
		Detectors:        []string{"syft-detector"},
	},
	PackageManagerSwiftPM: {
		Name:             "swiftpm",
		Ecosystem:        EcosystemSwift,
		EvidencePatterns: []string{"Package.resolved", ".package.resolved"},
		Detectors:        []string{"syft-detector"},
	},
	PackageManagerTerraform: {
		Name:             "terraform",
		Ecosystem:        EcosystemTerraform,
		EvidencePatterns: []string{".terraform.lock.hcl"},
		Detectors:        []string{"syft-detector"},
	},
	PackageManagerWordPress: {
		Name:             "wordpress",
		Ecosystem:        EcosystemWordPress,
		EvidencePatterns: []string{"wp-content/plugins/*/*.php"},
		Detectors:        []string{"syft-detector"},
	},
	PackageManagerSetupPy: {
		Name:             "setuppy",
		Ecosystem:        EcosystemPython,
		EvidencePatterns: []string{"setup.py"},
		Detectors:        []string{"syft-detector"},
	},
}

var allPackageManagers = []PackageManager{
	PackageManagerNPM,
	PackageManagerPNPM,
	PackageManagerYarn,
	PackageManagerGradle,
	PackageManagerMaven,
	PackageManagerGoMod,
	PackageManagerPip,
	PackageManagerPipenv,
	PackageManagerPoetry,
	PackageManagerUV,
	PackageManagerALPM,
	PackageManagerAPK,
	PackageManagerConan,
	PackageManagerConda,
	PackageManagerPub,
	PackageManagerDPKG,
	PackageManagerMix,
	PackageManagerRebar,
	PackageManagerOTP,
	PackageManagerGitHubActions,
	PackageManagerCabal,
	PackageManagerStack,
	PackageManagerHomebrew,
	PackageManagerLuaRocks,
	PackageManagerNuGet,
	PackageManagerNix,
	PackageManagerOpam,
	PackageManagerComposer,
	PackageManagerPear,
	PackageManagerPDM,
	PackageManagerPortage,
	PackageManagerSWIPLPack,
	PackageManagerRPackage,
	PackageManagerRPM,
	PackageManagerBundler,
	PackageManagerGemspec,
	PackageManagerCargo,
	PackageManagerSBOM,
	PackageManagerSnap,
	PackageManagerCocoaPods,
	PackageManagerSwiftPM,
	PackageManagerTerraform,
	PackageManagerWordPress,
	PackageManagerSetupPy,
}

var (
	packageManagerByName             = map[string]PackageManager{}
	packageManagersByEcosystem       = map[Ecosystem][]PackageManager{}
	packageManagersByEvidencePattern = map[string][]PackageManager{}
	packageManagersByDetectorName    = map[string][]PackageManager{}
)

func init() {
	for _, manager := range allPackageManagers {
		meta := packageManagerRegistry[manager]
		packageManagerByName[meta.Name] = manager
		for _, alias := range meta.Aliases {
			packageManagerByName[strings.ToLower(strings.TrimSpace(alias))] = manager
		}
		packageManagersByEcosystem[meta.Ecosystem] = append(packageManagersByEcosystem[meta.Ecosystem], manager)
		for _, pattern := range meta.EvidencePatterns {
			packageManagersByEvidencePattern[pattern] = append(packageManagersByEvidencePattern[pattern], manager)
		}
		for _, detector := range meta.Detectors {
			packageManagersByDetectorName[detector] = append(packageManagersByDetectorName[detector], manager)
		}
	}
}

func (p PackageManager) valid() bool {
	return p > PackageManagerUnknown && p < PackageManagerCount
}

// String returns the canonical package-manager name.
func (p PackageManager) String() string {
	return p.Name()
}

// Name returns the canonical package-manager name.
func (p PackageManager) Name() string {
	if !p.valid() {
		return ""
	}
	return packageManagerRegistry[p].Name
}

// Ecosystem returns the higher-level grouping for a package manager.
func (p PackageManager) Ecosystem() Ecosystem {
	if !p.valid() {
		return EcosystemUnknown
	}
	return packageManagerRegistry[p].Ecosystem
}

// EvidencePatterns returns the configured manifest or database evidence patterns.
func (p PackageManager) EvidencePatterns() []string {
	if !p.valid() {
		return nil
	}
	values := make([]string, len(packageManagerRegistry[p].EvidencePatterns))
	copy(values, packageManagerRegistry[p].EvidencePatterns)
	return values
}

// Detectors returns the registered detector names for a package manager.
func (p PackageManager) Detectors() []string {
	if !p.valid() {
		return nil
	}
	values := make([]string, len(packageManagerRegistry[p].Detectors))
	copy(values, packageManagerRegistry[p].Detectors)
	return values
}

// PrimaryDetector returns the preferred detector that should run for a package manager.
func (p PackageManager) PrimaryDetector() string {
	if !p.valid() || len(packageManagerRegistry[p].Detectors) == 0 {
		return ""
	}
	return packageManagerRegistry[p].Detectors[0]
}

// ParsePackageManager normalizes a user-provided package-manager value.
func ParsePackageManager(value string) (PackageManager, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return PackageManagerUnknown, fmt.Errorf("package manager is empty")
	}
	manager, ok := packageManagerByName[normalized]
	if !ok {
		return PackageManagerUnknown, fmt.Errorf("unsupported package manager %q", value)
	}
	return manager, nil
}

// AllPackageManagers returns the canonical package-manager list in registry order.
func AllPackageManagers() []PackageManager {
	values := make([]PackageManager, len(allPackageManagers))
	copy(values, allPackageManagers)
	return values
}

// SupportedPackageManagers returns all package managers known to the built-in support registry.
func SupportedPackageManagers() []PackageManager {
	return AllPackageManagers()
}

// PackageManagerByName looks up a package manager by canonical name or alias.
func PackageManagerByName(name string) (PackageManager, bool) {
	manager, ok := packageManagerByName[strings.ToLower(strings.TrimSpace(name))]
	return manager, ok
}

// PackageManagersByEcosystem returns package managers grouped under one ecosystem.
func PackageManagersByEcosystem(ecosystem Ecosystem) ([]PackageManager, bool) {
	values, ok := packageManagersByEcosystem[ecosystem]
	if !ok {
		return nil, false
	}
	out := make([]PackageManager, len(values))
	copy(out, values)
	return out, true
}

// PackageManagersByEvidencePattern returns package managers keyed by one evidence pattern.
func PackageManagersByEvidencePattern(pattern string) ([]PackageManager, bool) {
	values, ok := packageManagersByEvidencePattern[pattern]
	if !ok {
		return nil, false
	}
	out := make([]PackageManager, len(values))
	copy(out, values)
	return out, true
}

// PackageManagersByDetector returns package managers that include the named detector in their chain.
func PackageManagersByDetector(detectorName string) ([]PackageManager, bool) {
	values, ok := packageManagersByDetectorName[detectorName]
	if !ok {
		return nil, false
	}
	out := make([]PackageManager, len(values))
	copy(out, values)
	return out, true
}

// PackageManagersByEcosystemAndDetectorType returns package managers narrowed to one ecosystem and detector family.
func PackageManagersByEcosystemAndDetectorType(ecosystem Ecosystem, detectorType DetectorType) ([]PackageManager, bool) {
	values, ok := packageManagersByEcosystem[ecosystem]
	if !ok {
		return nil, false
	}
	out := make([]PackageManager, 0, len(values))
	for _, manager := range values {
		for _, detector := range manager.Detectors() {
			if DetectorTypeForName(detector) == detectorType {
				out = append(out, manager)
				break
			}
		}
	}
	return out, len(out) > 0
}

// DetectorTypeForName returns the implementation family for a built-in detector name.
func DetectorTypeForName(name string) DetectorType {
	switch strings.TrimSpace(name) {
	case "syft-detector":
		return ThirdPartyDetector
	case "npm-detector",
		"pnpm-detector",
		"yarn-detector",
		"gradle-detector",
		"maven-detector",
		"go-detector",
		"composer-detector",
		"bundler-detector",
		"github-actions-detector",
		"pip-detector",
		"pipenv-detector",
		"poetry-detector",
		"uv-detector",
		"sbom-detector":
		return NativeDetector
	default:
		return ""
	}
}

type ecosystemSupport struct {
	Ecosystem Ecosystem
	Aliases   []string
}

// OperatingSystemSupport records the container OS families Syft documents support for.
// We keep this separate from Bomly's package-manager model because operating systems are
// scan target characteristics, not package-manager ecosystems.
type OperatingSystemSupport struct {
	Name          string
	Aliases       []string
	Provider      string
	VersionSource string
}

var ecosystemRegistry = []ecosystemSupport{
	{Ecosystem: EcosystemNPM},
	{Ecosystem: EcosystemMaven, Aliases: []string{PackageManagerGradle.Name()}},
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
	{Ecosystem: EcosystemSBOM},
	{Ecosystem: EcosystemSnap},
	{Ecosystem: EcosystemSwift},
	{Ecosystem: EcosystemTerraform},
	{Ecosystem: EcosystemWordPress},
}

var operatingSystemRegistry = []OperatingSystemSupport{
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

// SupportedEcosystems returns all canonical ecosystems known to the built-in support registry.
func SupportedEcosystems() []Ecosystem {
	values := make([]Ecosystem, 0, len(ecosystemRegistry))
	for _, item := range ecosystemRegistry {
		values = append(values, item.Ecosystem)
	}
	return values
}

// SupportEntries returns a copy of the canonical package-manager support registry.
func SupportEntries() []PackageManagerSupport {
	values := make([]PackageManagerSupport, 0, len(allPackageManagers))
	for _, manager := range allPackageManagers {
		values = append(values, supportEntryForPackageManager(manager))
	}
	return values
}

// SupportEntriesForDetectorType returns package-manager entries supported by the given detector type.
func SupportEntriesForDetectorType(detectorType DetectorType) []PackageManagerSupport {
	values := make([]PackageManagerSupport, 0, len(allPackageManagers))
	for _, manager := range allPackageManagers {
		entry := supportEntryForPackageManager(manager)
		if supportsDetectorType(entry.Detectors, detectorType) {
			values = append(values, entry)
		}
	}
	return values
}

// SupportedEcosystemsForDetector returns canonical ecosystems supported by the named detector.
func SupportedEcosystemsForDetector(detectorName string) []Ecosystem {
	seen := make(map[Ecosystem]struct{}, len(allPackageManagers))
	values := make([]Ecosystem, 0, len(allPackageManagers))
	for _, manager := range SupportedPackageManagersForDetector(detectorName) {
		ecosystem := manager.Ecosystem()
		if ecosystem == EcosystemUnknown {
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

// SupportedEcosystemsForDetectorType returns canonical ecosystems supported by the given detector type.
func SupportedEcosystemsForDetectorType(detectorType DetectorType) []Ecosystem {
	seen := make(map[Ecosystem]struct{}, len(allPackageManagers))
	values := make([]Ecosystem, 0, len(allPackageManagers))
	for _, entry := range SupportEntriesForDetectorType(detectorType) {
		if _, ok := seen[entry.Ecosystem]; ok {
			continue
		}
		seen[entry.Ecosystem] = struct{}{}
		values = append(values, entry.Ecosystem)
	}
	return values
}

// SupportedPackageManagersForDetector returns package managers supported by the named detector.
func SupportedPackageManagersForDetector(detectorName string) []PackageManager {
	values, _ := PackageManagersByDetector(detectorName)
	return values
}

// PreferredPackageManagersForDetector returns package managers whose preferred detector matches detectorName.
func PreferredPackageManagersForDetector(detectorName string) []PackageManager {
	values := make([]PackageManager, 0, len(allPackageManagers))
	for _, manager := range allPackageManagers {
		if manager.PrimaryDetector() == detectorName {
			values = append(values, manager)
		}
	}
	return values
}

// SupportedPackageManagersForDetectorType returns package managers supported by the given detector type.
func SupportedPackageManagersForDetectorType(detectorType DetectorType) []PackageManager {
	values := make([]PackageManager, 0, len(allPackageManagers))
	for _, entry := range SupportEntriesForDetectorType(detectorType) {
		values = append(values, entry.Manager)
	}
	return values
}

// SupportedOperatingSystems returns the documented OS families supported through Syft container scanning.
func SupportedOperatingSystems() []OperatingSystemSupport {
	values := make([]OperatingSystemSupport, len(operatingSystemRegistry))
	copy(values, operatingSystemRegistry)
	return values
}

// EvidencePatternsForPackageManager returns the configured manifest or database evidence patterns.
func EvidencePatternsForPackageManager(manager PackageManager) []string {
	return manager.EvidencePatterns()
}

// PreferredPackageManagerForEcosystem returns the default package manager label for an ecosystem.
func PreferredPackageManagerForEcosystem(ecosystem Ecosystem) (PackageManager, bool) {
	return preferredPackageManagerForEcosystem(ecosystem)
}

// SupportedDetectors returns the unique detector names registered in support metadata order.
func SupportedDetectors() []string {
	values := make([]string, 0, len(allPackageManagers))
	seen := make(map[string]struct{}, len(allPackageManagers))
	for _, manager := range allPackageManagers {
		for _, detector := range manager.Detectors() {
			if detector == "" {
				continue
			}
			if _, ok := seen[detector]; ok {
				continue
			}
			seen[detector] = struct{}{}
			values = append(values, detector)
		}
	}
	return values
}

// PreferredEcosystemsForDetector returns ecosystems whose preferred package managers are backed by detectorName.
func PreferredEcosystemsForDetector(detectorName string) []Ecosystem {
	seen := make(map[Ecosystem]struct{}, len(allPackageManagers))
	values := make([]Ecosystem, 0, len(allPackageManagers))
	for _, manager := range PreferredPackageManagersForDetector(detectorName) {
		ecosystem := manager.Ecosystem()
		if ecosystem == EcosystemUnknown {
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

func supportEntryForPackageManager(manager PackageManager) PackageManagerSupport {
	meta := packageManagerRegistry[manager]
	return PackageManagerSupport{
		Manager:          manager,
		Ecosystem:        meta.Ecosystem,
		Aliases:          append([]string(nil), meta.Aliases...),
		EvidencePatterns: append([]string(nil), meta.EvidencePatterns...),
		Detectors:        append([]string(nil), meta.Detectors...),
	}
}

func preferredPackageManagerForEcosystem(ecosystem Ecosystem) (PackageManager, bool) {
	var fallback PackageManager
	for _, manager := range allPackageManagers {
		entry := supportEntryForPackageManager(manager)
		if entry.Ecosystem != ecosystem {
			continue
		}
		if manager.Name() == string(ecosystem) {
			return manager, true
		}
		if fallback == PackageManagerUnknown {
			fallback = manager
		}
	}
	return fallback, fallback != PackageManagerUnknown
}

func supportsDetectorType(detectors []string, detectorType DetectorType) bool {
	for _, detector := range detectors {
		if DetectorTypeForName(detector) == detectorType {
			return true
		}
	}
	return false
}

type groupedSupportEntry struct {
	ecosystem Ecosystem
	managers  []string
	patterns  []string
}
