package sdk

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
	PackageManagerOther
	PackageManagerSBT
	PackageManagerCount
)

type packageManagerInfo struct {
	Name      string
	Ecosystem Ecosystem
	Aliases   []string
}

var packageManagerInfoByID = [...]packageManagerInfo{
	PackageManagerUnknown:       {},
	PackageManagerNPM:           {Name: "npm", Ecosystem: EcosystemNPM},
	PackageManagerPNPM:          {Name: "pnpm", Ecosystem: EcosystemNPM},
	PackageManagerYarn:          {Name: "yarn", Ecosystem: EcosystemNPM},
	PackageManagerGradle:        {Name: "gradle", Ecosystem: EcosystemMaven},
	PackageManagerMaven:         {Name: "maven", Ecosystem: EcosystemMaven},
	PackageManagerGoMod:         {Name: "gomod", Ecosystem: EcosystemGo},
	PackageManagerPip:           {Name: "pip", Ecosystem: EcosystemPython},
	PackageManagerPipenv:        {Name: "pipenv", Ecosystem: EcosystemPython},
	PackageManagerPoetry:        {Name: "poetry", Ecosystem: EcosystemPython},
	PackageManagerUV:            {Name: "uv", Ecosystem: EcosystemPython},
	PackageManagerALPM:          {Name: "alpm", Ecosystem: EcosystemALPM},
	PackageManagerAPK:           {Name: "apk", Ecosystem: EcosystemAPK},
	PackageManagerConan:         {Name: "conan", Ecosystem: EcosystemCPP},
	PackageManagerConda:         {Name: "conda", Ecosystem: EcosystemConda},
	PackageManagerPub:           {Name: "pub", Ecosystem: EcosystemDart},
	PackageManagerDPKG:          {Name: "dpkg", Ecosystem: EcosystemDPKG},
	PackageManagerMix:           {Name: "mix", Ecosystem: EcosystemElixir},
	PackageManagerRebar:         {Name: "rebar", Ecosystem: EcosystemErlang},
	PackageManagerOTP:           {Name: "otp", Ecosystem: EcosystemErlang},
	PackageManagerGitHubActions: {Name: "github-actions", Ecosystem: EcosystemGitHub},
	PackageManagerCabal:         {Name: "cabal", Ecosystem: EcosystemHaskell},
	PackageManagerStack:         {Name: "stack", Ecosystem: EcosystemHaskell},
	PackageManagerHomebrew:      {Name: "homebrew", Ecosystem: EcosystemHomebrew},
	PackageManagerLuaRocks:      {Name: "luarocks", Ecosystem: EcosystemLua},
	PackageManagerNuGet:         {Name: "nuget", Ecosystem: EcosystemDotNet},
	PackageManagerNix:           {Name: "nix", Ecosystem: EcosystemNix},
	PackageManagerOpam:          {Name: "opam", Ecosystem: EcosystemOCaml},
	PackageManagerComposer:      {Name: "composer", Ecosystem: EcosystemPHP},
	PackageManagerPear:          {Name: "pear", Ecosystem: EcosystemPHP},
	PackageManagerPDM:           {Name: "pdm", Ecosystem: EcosystemPython},
	PackageManagerPortage:       {Name: "portage", Ecosystem: EcosystemPortage},
	PackageManagerSWIPLPack:     {Name: "swipl-pack", Ecosystem: EcosystemProlog},
	PackageManagerRPackage:      {Name: "r-package", Ecosystem: EcosystemR},
	PackageManagerRPM:           {Name: "rpm", Ecosystem: EcosystemRPM},
	PackageManagerBundler:       {Name: "bundler", Ecosystem: EcosystemRuby},
	PackageManagerGemspec:       {Name: "gemspec", Ecosystem: EcosystemRuby},
	PackageManagerCargo:         {Name: "cargo", Ecosystem: EcosystemRust},
	PackageManagerSBOM:          {Name: "sbom", Ecosystem: EcosystemSBOM},
	PackageManagerSnap:          {Name: "snap", Ecosystem: EcosystemSnap},
	PackageManagerCocoaPods:     {Name: "cocoapods", Ecosystem: EcosystemSwift},
	PackageManagerSwiftPM:       {Name: "swiftpm", Ecosystem: EcosystemSwift},
	PackageManagerTerraform:     {Name: "terraform", Ecosystem: EcosystemTerraform},
	PackageManagerWordPress:     {Name: "wordpress", Ecosystem: EcosystemWordPress},
	PackageManagerSetupPy:       {Name: "setuppy", Ecosystem: EcosystemPython},
	PackageManagerOther:         {Name: "other", Ecosystem: EcosystemOther},
	PackageManagerSBT:           {Name: "sbt", Ecosystem: EcosystemScala},
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
	PackageManagerSBT,
	PackageManagerOther,
}

var packageManagerByName = map[string]PackageManager{}

func init() {
	for _, manager := range allPackageManagers {
		info := packageManagerInfoByID[manager]
		packageManagerByName[info.Name] = manager
		for _, alias := range info.Aliases {
			packageManagerByName[strings.ToLower(strings.TrimSpace(alias))] = manager
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
	return packageManagerInfoByID[p].Name
}

// Ecosystem returns the higher-level grouping for a package manager.
func (p PackageManager) Ecosystem() Ecosystem {
	if !p.valid() {
		return EcosystemUnknown
	}
	return packageManagerInfoByID[p].Ecosystem
}

// ParsePackageManager normalizes a package-manager value.
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

// AllPackageManagers returns the canonical package-manager list in SDK order.
func AllPackageManagers() []PackageManager {
	values := make([]PackageManager, len(allPackageManagers))
	copy(values, allPackageManagers)
	return values
}
