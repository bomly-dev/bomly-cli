package syft

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/system"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// Detector resolves dependency graphs through the Syft Go library (builtin)
// or the syft CLI binary (external).
type Detector struct {
	Logger              *zap.Logger
	WorkingDir          string
	SupportedEcosystems []sdk.Ecosystem
	SupportedManagers   []sdk.PackageManager
}

var packageManagerSupport = []sdk.PackageManagerSupport{
	sdk.Support(sdk.PackageManagerNPM, "package-lock.json", "package.json"),
	sdk.Support(sdk.PackageManagerPNPM, "pnpm-lock.yaml", "package.json"),
	sdk.Support(sdk.PackageManagerYarn, "yarn.lock", "package.json"),
	sdk.Support(sdk.PackageManagerBun, "bun.lockb"),
	sdk.Support(sdk.PackageManagerGradle, "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts", "gradle.lockfile*"),
	sdk.Support(sdk.PackageManagerMaven, "pom.xml", "*pom.xml"),
	sdk.Support(sdk.PackageManagerGoMod, "go.mod"),
	sdk.Support(sdk.PackageManagerPip, "requirements.txt", "requirements-dev.txt", "requirements.in", "requirements.lock", "*requirements*.txt"),
	sdk.Support(sdk.PackageManagerPipenv, "Pipfile", "Pipfile.lock"),
	sdk.Support(sdk.PackageManagerPoetry, "poetry.lock", "pyproject.toml"),
	sdk.Support(sdk.PackageManagerUV, "uv.lock", "pyproject.toml"),
	sdk.Support(sdk.PackageManagerALPM, "var/lib/pacman/local/*/desc"),
	sdk.Support(sdk.PackageManagerAPK, "lib/apk/db/installed"),
	sdk.Support(sdk.PackageManagerConan, "conan.lock", "conanfile.txt", "conaninfo.txt"),
	sdk.Support(sdk.PackageManagerConda, "conda-meta/*.json"),
	sdk.Support(sdk.PackageManagerPub, "pubspec.yml", "pubspec.yaml", "pubspec.lock"),
	sdk.Support(sdk.PackageManagerDPKG, "lib/dpkg/status", "lib/dpkg/status.d/*", "lib/opkg/info/*.control", "lib/opkg/status"),
	sdk.Support(sdk.PackageManagerMix, "mix.lock"),
	sdk.Support(sdk.PackageManagerRebar, "rebar.lock"),
	sdk.Support(sdk.PackageManagerOTP, "*.app"),
	sdk.Support(sdk.PackageManagerGitHubActions, ".github/workflows/*.yaml", ".github/workflows/*.yml", ".github/actions/*/action.yml", ".github/actions/*/action.yaml"),
	sdk.Support(sdk.PackageManagerCabal, "cabal.project.freeze"),
	sdk.Support(sdk.PackageManagerStack, "stack.yaml", "stack.yaml.lock"),
	sdk.Support(sdk.PackageManagerHomebrew, "Cellar/*/*/.brew/*.rb", "Library/Taps/*/*/Formula/*.rb"),
	sdk.Support(sdk.PackageManagerLuaRocks, "*.rockspec"),
	sdk.Support(sdk.PackageManagerNuGet, "packages.lock.json", "*.deps.json"),
	sdk.Support(sdk.PackageManagerNix, "nix/var/nix/db/db.sqlite", "nix/store/*.drv"),
	sdk.Support(sdk.PackageManagerOpam, "*opam"),
	sdk.Support(sdk.PackageManagerComposer, "composer.lock", "installed.json"),
	sdk.Support(sdk.PackageManagerPear, "php/.registry/**/*.reg"),
	sdk.Support(sdk.PackageManagerPDM, "pdm.lock", "pyproject.toml"),
	sdk.Support(sdk.PackageManagerPortage, "var/db/pkg/*/*/CONTENTS"),
	sdk.Support(sdk.PackageManagerSWIPLPack, "pack.pl"),
	sdk.Support(sdk.PackageManagerRPackage, "DESCRIPTION"),
	sdk.Support(sdk.PackageManagerRPM, "var/lib/rpmmanifest/container-manifest-2", "var/lib/rpm/Packages", "var/lib/rpm/Packages.db", "var/lib/rpm/rpmdb.sqlite", "usr/share/rpm/Packages", "usr/share/rpm/Packages.db", "usr/share/rpm/rpmdb.sqlite", "usr/lib/sysimage/rpm/Packages", "usr/lib/sysimage/rpm/Packages.db", "usr/lib/sysimage/rpm/rpmdb.sqlite"),
	sdk.Support(sdk.PackageManagerBundler, "Gemfile.lock", "Gemfile.next.lock"),
	sdk.Support(sdk.PackageManagerGemspec, "*.gemspec"),
	sdk.Support(sdk.PackageManagerCargo, "Cargo.lock"),
	sdk.Support(sdk.PackageManagerSnap, "snap/snapcraft.yaml", "snap/manifest.yaml", "doc/linux-modules-*/changelog.Debian.gz", "usr/share/snappy/dpkg.yaml"),
	sdk.Support(sdk.PackageManagerCocoaPods, "Podfile.lock"),
	sdk.Support(sdk.PackageManagerSwiftPM, "Package.resolved", ".package.resolved"),
	sdk.Support(sdk.PackageManagerTerraform, ".terraform.lock.hcl"),
	sdk.Support(sdk.PackageManagerWordPress, "wp-content/plugins/*/*.php"),
	sdk.Support(sdk.PackageManagerSetupPy, "setup.py"),
}

// PackageManagerSupport returns Syft package-manager discovery metadata.
func (d Detector) PackageManagerSupport() []sdk.PackageManagerSupport {
	values := make([]sdk.PackageManagerSupport, len(packageManagerSupport))
	copy(values, packageManagerSupport)
	for idx := range values {
		values[idx].EvidencePatterns = append([]string(nil), values[idx].EvidencePatterns...)
	}
	return values
}

// Ready reports whether the detector is ready to run.
func (d Detector) Ready(context.Context, sdk.DetectionRequest) error {
	return nil
}

// Applicable reports whether Syft should run for the requested project.
func (d Detector) Applicable(ctx context.Context, req sdk.DetectionRequest) (bool, error) {
	_ = ctx

	if req.ExecutionTarget.Kind == sdk.ExecutionTargetContainerImage {
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
func (d Detector) Descriptor() sdk.DetectorDescriptor {
	supportedEcosystems := d.SupportedEcosystems
	supportedManagers := d.SupportedManagers
	return sdk.DetectorDescriptor{
		Name:                detectors.NameSyft,
		Technique:           sdk.MultipleTechnique,
		SupportedEcosystems: supportedEcosystems,
		SupportedManagers:   supportedManagers,
		Tags:                []string{"graph-resolution", "component-targeting", "sbom-import", "detector-enrichment"},
	}
}

func supportedFilesForManager(manager sdk.PackageManager) []string {
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

func syftWorkingDir(defaultWorkingDir string, req sdk.DetectionRequest) string {
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
