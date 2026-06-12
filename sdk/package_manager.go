package sdk

import (
	"fmt"
	"strings"
)

// PackageManager identifies the concrete package manager or manifest family for a target.
type PackageManager string

const (
	PackageManagerUnknown       PackageManager = ""
	PackageManagerNPM           PackageManager = "npm"
	PackageManagerPNPM          PackageManager = "pnpm"
	PackageManagerYarn          PackageManager = "yarn"
	PackageManagerGradle        PackageManager = "gradle"
	PackageManagerMaven         PackageManager = "maven"
	PackageManagerGoMod         PackageManager = "gomod"
	PackageManagerPip           PackageManager = "pip"
	PackageManagerPipenv        PackageManager = "pipenv"
	PackageManagerPoetry        PackageManager = "poetry"
	PackageManagerUV            PackageManager = "uv"
	PackageManagerALPM          PackageManager = "alpm"
	PackageManagerAPK           PackageManager = "apk"
	PackageManagerConan         PackageManager = "conan"
	PackageManagerConda         PackageManager = "conda"
	PackageManagerPub           PackageManager = "pub"
	PackageManagerDPKG          PackageManager = "dpkg"
	PackageManagerMix           PackageManager = "mix"
	PackageManagerRebar         PackageManager = "rebar"
	PackageManagerOTP           PackageManager = "otp"
	PackageManagerGitHubActions PackageManager = "github-actions"
	PackageManagerCabal         PackageManager = "cabal"
	PackageManagerStack         PackageManager = "stack"
	PackageManagerHomebrew      PackageManager = "homebrew"
	PackageManagerLuaRocks      PackageManager = "luarocks"
	PackageManagerNuGet         PackageManager = "nuget"
	PackageManagerNix           PackageManager = "nix"
	PackageManagerOpam          PackageManager = "opam"
	PackageManagerComposer      PackageManager = "composer"
	PackageManagerPear          PackageManager = "pear"
	PackageManagerPDM           PackageManager = "pdm"
	PackageManagerPortage       PackageManager = "portage"
	PackageManagerSWIPLPack     PackageManager = "swipl-pack"
	PackageManagerRPackage      PackageManager = "r-package"
	PackageManagerRPM           PackageManager = "rpm"
	PackageManagerBundler       PackageManager = "bundler"
	PackageManagerGemspec       PackageManager = "gemspec"
	PackageManagerCargo         PackageManager = "cargo"
	PackageManagerSBOM          PackageManager = "sbom"
	PackageManagerSnap          PackageManager = "snap"
	PackageManagerCocoaPods     PackageManager = "cocoapods"
	PackageManagerSwiftPM       PackageManager = "swiftpm"
	PackageManagerTerraform     PackageManager = "terraform"
	PackageManagerWordPress     PackageManager = "wordpress"
	PackageManagerSetupPy       PackageManager = "setuppy"
	PackageManagerOther         PackageManager = "other"
	PackageManagerSBT           PackageManager = "sbt"
	PackageManagerMultiple      PackageManager = "multiple"
)

type packageManagerInfo struct {
	Name      string
	Ecosystem Ecosystem
	Aliases   []string
	// Languages lists the programming languages typically built with this
	// package manager. Empty for OS-level managers that span many languages
	// (e.g. apk, dpkg, rpm).
	Languages []Language
}

var packageManagerInfoByID = map[PackageManager]packageManagerInfo{
	PackageManagerUnknown:       {},
	PackageManagerNPM:           {Name: "npm", Ecosystem: EcosystemNPM, Languages: []Language{LanguageJavaScript, LanguageTypeScript}},
	PackageManagerPNPM:          {Name: "pnpm", Ecosystem: EcosystemNPM, Languages: []Language{LanguageJavaScript, LanguageTypeScript}},
	PackageManagerYarn:          {Name: "yarn", Ecosystem: EcosystemNPM, Languages: []Language{LanguageJavaScript, LanguageTypeScript}},
	PackageManagerGradle:        {Name: "gradle", Ecosystem: EcosystemMaven, Languages: []Language{LanguageJava, LanguageKotlin, LanguageGroovy, LanguageScala}},
	PackageManagerMaven:         {Name: "maven", Ecosystem: EcosystemMaven, Languages: []Language{LanguageJava, LanguageKotlin, LanguageScala, LanguageGroovy}},
	PackageManagerGoMod:         {Name: "gomod", Ecosystem: EcosystemGo, Languages: []Language{LanguageGo}},
	PackageManagerPip:           {Name: "pip", Ecosystem: EcosystemPython, Languages: []Language{LanguagePython}},
	PackageManagerPipenv:        {Name: "pipenv", Ecosystem: EcosystemPython, Languages: []Language{LanguagePython}},
	PackageManagerPoetry:        {Name: "poetry", Ecosystem: EcosystemPython, Languages: []Language{LanguagePython}},
	PackageManagerUV:            {Name: "uv", Ecosystem: EcosystemPython, Languages: []Language{LanguagePython}},
	PackageManagerALPM:          {Name: "alpm", Ecosystem: EcosystemALPM},
	PackageManagerAPK:           {Name: "apk", Ecosystem: EcosystemAPK},
	PackageManagerConan:         {Name: "conan", Ecosystem: EcosystemCPP, Languages: []Language{LanguageC, LanguageCPP}},
	PackageManagerConda:         {Name: "conda", Ecosystem: EcosystemConda, Languages: []Language{LanguagePython, LanguageR, LanguageCPP}},
	PackageManagerPub:           {Name: "pub", Ecosystem: EcosystemDart, Languages: []Language{LanguageDart}},
	PackageManagerDPKG:          {Name: "dpkg", Ecosystem: EcosystemDPKG},
	PackageManagerMix:           {Name: "mix", Ecosystem: EcosystemElixir, Languages: []Language{LanguageElixir}},
	PackageManagerRebar:         {Name: "rebar", Ecosystem: EcosystemErlang, Languages: []Language{LanguageErlang}},
	PackageManagerOTP:           {Name: "otp", Ecosystem: EcosystemErlang, Languages: []Language{LanguageErlang}},
	PackageManagerGitHubActions: {Name: "github-actions", Ecosystem: EcosystemGitHub},
	PackageManagerCabal:         {Name: "cabal", Ecosystem: EcosystemHaskell, Languages: []Language{LanguageHaskell}},
	PackageManagerStack:         {Name: "stack", Ecosystem: EcosystemHaskell, Languages: []Language{LanguageHaskell}},
	PackageManagerHomebrew:      {Name: "homebrew", Ecosystem: EcosystemHomebrew},
	PackageManagerLuaRocks:      {Name: "luarocks", Ecosystem: EcosystemLua, Languages: []Language{LanguageLua}},
	PackageManagerNuGet:         {Name: "nuget", Ecosystem: EcosystemDotNet, Languages: []Language{LanguageCSharp, LanguageFSharp, LanguageVB}},
	PackageManagerNix:           {Name: "nix", Ecosystem: EcosystemNix},
	PackageManagerOpam:          {Name: "opam", Ecosystem: EcosystemOCaml, Languages: []Language{LanguageOCaml}},
	PackageManagerComposer:      {Name: "composer", Ecosystem: EcosystemPHP, Languages: []Language{LanguagePHP}},
	PackageManagerPear:          {Name: "pear", Ecosystem: EcosystemPHP, Languages: []Language{LanguagePHP}},
	PackageManagerPDM:           {Name: "pdm", Ecosystem: EcosystemPython, Languages: []Language{LanguagePython}},
	PackageManagerPortage:       {Name: "portage", Ecosystem: EcosystemPortage},
	PackageManagerSWIPLPack:     {Name: "swipl-pack", Ecosystem: EcosystemProlog},
	PackageManagerRPackage:      {Name: "r-package", Ecosystem: EcosystemR, Languages: []Language{LanguageR}},
	PackageManagerRPM:           {Name: "rpm", Ecosystem: EcosystemRPM},
	PackageManagerBundler:       {Name: "bundler", Ecosystem: EcosystemRuby, Languages: []Language{LanguageRuby}},
	PackageManagerGemspec:       {Name: "gemspec", Ecosystem: EcosystemRuby, Languages: []Language{LanguageRuby}},
	PackageManagerCargo:         {Name: "cargo", Ecosystem: EcosystemRust, Languages: []Language{LanguageRust}},
	PackageManagerSBOM:          {Name: "sbom", Ecosystem: EcosystemSBOM},
	PackageManagerSnap:          {Name: "snap", Ecosystem: EcosystemSnap},
	PackageManagerCocoaPods:     {Name: "cocoapods", Ecosystem: EcosystemSwift, Languages: []Language{LanguageSwift, LanguageObjC}},
	PackageManagerSwiftPM:       {Name: "swiftpm", Ecosystem: EcosystemSwift, Languages: []Language{LanguageSwift, LanguageObjC}},
	PackageManagerTerraform:     {Name: "terraform", Ecosystem: EcosystemTerraform},
	PackageManagerWordPress:     {Name: "wordpress", Ecosystem: EcosystemWordPress, Languages: []Language{LanguagePHP}},
	PackageManagerSetupPy:       {Name: "setuppy", Ecosystem: EcosystemPython, Languages: []Language{LanguagePython}},
	PackageManagerOther:         {Name: "other", Ecosystem: EcosystemOther},
	PackageManagerSBT:           {Name: "sbt", Ecosystem: EcosystemScala, Languages: []Language{LanguageScala, LanguageJava}},
	PackageManagerMultiple:      {Name: "multiple"},
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
	for _, manager := range append(append([]PackageManager(nil), allPackageManagers...), PackageManagerMultiple) {
		info := packageManagerInfoByID[manager]
		packageManagerByName[info.Name] = manager
		for _, alias := range info.Aliases {
			packageManagerByName[strings.ToLower(strings.TrimSpace(alias))] = manager
		}
	}
}

func (p PackageManager) valid() bool {
	_, ok := packageManagerInfoByID[p]
	return ok && p != PackageManagerUnknown
}

// String returns the canonical package-manager name.
func (p PackageManager) String() string {
	return p.Name()
}

// Name returns the canonical package-manager name.
func (p PackageManager) Name() string {
	if !p.valid() {
		return string(p)
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

// Languages returns the programming languages typically built with this
// package manager. The first entry is the most common / canonical language;
// callers that need a single value should take Languages()[0]. Returns nil
// for OS-level managers and any manager that does not have a meaningful
// language association.
func (p PackageManager) Languages() []Language {
	if !p.valid() {
		return nil
	}
	src := packageManagerInfoByID[p].Languages
	if len(src) == 0 {
		return nil
	}
	return append([]Language(nil), src...)
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
