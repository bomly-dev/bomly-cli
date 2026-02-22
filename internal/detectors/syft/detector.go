package syft

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/system"
	model "github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// Detector resolves dependency graphs through the Syft Go library (builtin)
// or the syft CLI binary (external).
type Detector struct {
	Logger              *zap.Logger
	WorkingDir          string
	SupportedEcosystems []model.Ecosystem
	SupportedManagers   []model.PackageManager
}

var packageManagerSupport = []model.PackageManagerSupport{
	model.Support(model.PackageManagerNPM, "package-lock.json", "package.json"),
	model.Support(model.PackageManagerPNPM, "pnpm-lock.yaml", "package.json"),
	model.Support(model.PackageManagerYarn, "yarn.lock", "package.json"),
	model.Support(model.PackageManagerGradle, "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts", "gradle.lockfile*"),
	model.Support(model.PackageManagerMaven, "pom.xml", "*pom.xml"),
	model.Support(model.PackageManagerGoMod, "go.mod"),
	model.Support(model.PackageManagerPip, "requirements.txt", "requirements-dev.txt", "requirements.in", "requirements.lock", "*requirements*.txt"),
	model.Support(model.PackageManagerPipenv, "Pipfile", "Pipfile.lock"),
	model.Support(model.PackageManagerPoetry, "poetry.lock", "pyproject.toml"),
	model.Support(model.PackageManagerUV, "uv.lock", "pyproject.toml"),
	model.Support(model.PackageManagerALPM, "var/lib/pacman/local/*/desc"),
	model.Support(model.PackageManagerAPK, "lib/apk/db/installed"),
	model.Support(model.PackageManagerConan, "conan.lock", "conanfile.txt", "conaninfo.txt"),
	model.Support(model.PackageManagerConda, "conda-meta/*.json"),
	model.Support(model.PackageManagerPub, "pubspec.yml", "pubspec.yaml", "pubspec.lock"),
	model.Support(model.PackageManagerDPKG, "lib/dpkg/status", "lib/dpkg/status.d/*", "lib/opkg/info/*.control", "lib/opkg/status"),
	model.Support(model.PackageManagerMix, "mix.lock"),
	model.Support(model.PackageManagerRebar, "rebar.lock"),
	model.Support(model.PackageManagerOTP, "*.app"),
	model.Support(model.PackageManagerGitHubActions, ".github/workflows/*.yaml", ".github/workflows/*.yml", ".github/actions/*/action.yml", ".github/actions/*/action.yaml"),
	model.Support(model.PackageManagerCabal, "cabal.project.freeze"),
	model.Support(model.PackageManagerStack, "stack.yaml", "stack.yaml.lock"),
	model.Support(model.PackageManagerHomebrew, "Cellar/*/*/.brew/*.rb", "Library/Taps/*/*/Formula/*.rb"),
	model.Support(model.PackageManagerLuaRocks, "*.rockspec"),
	model.Support(model.PackageManagerNuGet, "packages.lock.json", "*.deps.json"),
	model.Support(model.PackageManagerNix, "nix/var/nix/db/db.sqlite", "nix/store/*.drv"),
	model.Support(model.PackageManagerOpam, "*opam"),
	model.Support(model.PackageManagerComposer, "composer.lock", "installed.json"),
	model.Support(model.PackageManagerPear, "php/.registry/**/*.reg"),
	model.Support(model.PackageManagerPDM, "pdm.lock", "pyproject.toml"),
	model.Support(model.PackageManagerPortage, "var/db/pkg/*/*/CONTENTS"),
	model.Support(model.PackageManagerSWIPLPack, "pack.pl"),
	model.Support(model.PackageManagerRPackage, "DESCRIPTION"),
	model.Support(model.PackageManagerRPM, "var/lib/rpmmanifest/container-manifest-2", "var/lib/rpm/Packages", "var/lib/rpm/Packages.db", "var/lib/rpm/rpmdb.sqlite", "usr/share/rpm/Packages", "usr/share/rpm/Packages.db", "usr/share/rpm/rpmdb.sqlite", "usr/lib/sysimage/rpm/Packages", "usr/lib/sysimage/rpm/Packages.db", "usr/lib/sysimage/rpm/rpmdb.sqlite"),
	model.Support(model.PackageManagerBundler, "Gemfile.lock", "Gemfile.next.lock"),
	model.Support(model.PackageManagerGemspec, "*.gemspec"),
	model.Support(model.PackageManagerCargo, "Cargo.lock"),
	model.Support(model.PackageManagerSnap, "snap/snapcraft.yaml", "snap/manifest.yaml", "doc/linux-modules-*/changelog.Debian.gz", "usr/share/snappy/dpkg.yaml"),
	model.Support(model.PackageManagerCocoaPods, "Podfile.lock"),
	model.Support(model.PackageManagerSwiftPM, "Package.resolved", ".package.resolved"),
	model.Support(model.PackageManagerTerraform, ".terraform.lock.hcl"),
	model.Support(model.PackageManagerWordPress, "wp-content/plugins/*/*.php"),
	model.Support(model.PackageManagerSetupPy, "setup.py"),
}

// PackageManagerSupport returns Syft package-manager discovery metadata.
func (d Detector) PackageManagerSupport() []model.PackageManagerSupport {
	values := make([]model.PackageManagerSupport, len(packageManagerSupport))
	copy(values, packageManagerSupport)
	for idx := range values {
		values[idx].EvidencePatterns = append([]string(nil), values[idx].EvidencePatterns...)
	}
	return values
}

// Ready reports whether the detector is ready to run.
func (d Detector) Ready() bool {
	return true
}

// Applicable reports whether Syft should run for the requested project.
func (d Detector) Applicable(ctx context.Context, req model.DetectionRequest) (bool, error) {
	_ = ctx

	if req.ExecutionTarget.Kind == model.ExecutionTargetContainerImage {
		return true, nil
	}

	workingDir := syftWorkingDir(d.WorkingDir, req)

	if isSingleFileTarget(workingDir) {
		return true, nil
	}

	for _, candidate := range supportedFilesForManager(req.PackageManager) {
		exists, err := syftPatternExists(workingDir, candidate)
		if err != nil {
			return false, err
		}
		if exists {
			return true, nil
		}
	}
	return false, nil
}

// Descriptor describes the Syft-backed detector.
func (d Detector) Descriptor() model.DetectorDescriptor {
	supportedEcosystems := d.SupportedEcosystems
	supportedManagers := d.SupportedManagers
	return model.DetectorDescriptor{
		Name:                detectors.NameSyft,
		Enabled:             true,
		ComponentType:       model.ThirdPartyComponent,
		SupportedEcosystems: supportedEcosystems,
		SupportedManagers:   supportedManagers,
		SupportedModes:      []model.TargetMode{model.TargetModeFullGraph, model.TargetModeComponent},
		Capabilities:        []string{"graph-resolution", "component-targeting", "sbom-import", "detector-enrichment"},
	}
}

func supportedFilesForManager(manager model.PackageManager) []string {
	for _, support := range packageManagerSupport {
		if support.PackageManager == manager {
			return append([]string(nil), support.EvidencePatterns...)
		}
	}
	return nil
}

func syftPatternExists(dir string, pattern string) (bool, error) {
	if !strings.ContainsAny(pattern, "*?[") {
		exists, err := system.FileExists(filepath.Join(dir, filepath.FromSlash(pattern)))
		return err == nil && exists, err
	}
	matches, err := filepath.Glob(filepath.Join(dir, filepath.FromSlash(pattern)))
	if err != nil {
		return false, err
	}
	return len(matches) > 0, nil
}

func syftWorkingDir(defaultWorkingDir string, req model.DetectionRequest) string {
	if defaultWorkingDir != "" {
		return defaultWorkingDir
	}
	if req.ProjectPath != "" {
		return req.ProjectPath
	}
	return req.ExecutionTarget.Location
}

func isSingleFileTarget(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
