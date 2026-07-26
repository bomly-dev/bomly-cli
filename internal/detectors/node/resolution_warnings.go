package node

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/bomly-dev/bomly-cli/sdk"
	"gopkg.in/yaml.v3"
)

// LockfileFormat identifies the lockfile a Node detector parsed and the format
// version it declares. The zero value means the detector has no format version
// to compare (Bun text lockfiles record none), which disables the
// format-versus-declaration checks without disabling the rest.
type LockfileFormat struct {
	File    string // base name, e.g. "pnpm-lock.yaml"
	Version string // format version as written, e.g. "9.0"
}

// managerBinaries maps the Node package managers to the binary name a project
// declares them under in packageManager and engines.
var managerBinaries = map[sdk.PackageManager]string{
	sdk.PackageManagerNPM:  "npm",
	sdk.PackageManagerPNPM: "pnpm",
	sdk.PackageManagerYarn: "yarn",
	sdk.PackageManagerBun:  "bun",
}

// managerLockfiles maps each Node package manager to the lockfiles that prove
// the project is installed with it.
var managerLockfiles = map[sdk.PackageManager][]string{
	sdk.PackageManagerNPM:  {"package-lock.json", "npm-shrinkwrap.json"},
	sdk.PackageManagerPNPM: {"pnpm-lock.yaml"},
	sdk.PackageManagerYarn: {"yarn.lock"},
	sdk.PackageManagerBun:  {"bun.lock", "bun.lockb"},
}

// ResolutionWarnings reports non-blocking problems with a Node project's
// package-manager configuration: the detector resolved a correct graph, but the
// project as committed will trip up an install elsewhere, typically in CI.
//
// Every check reads committed files only — package.json, the lockfile the
// caller already parsed, pnpm-workspace.yaml, and .npmrc. Nothing is executed:
// `pnpm`/`yarn` on PATH are frequently Corepack shims, and running them can
// download the pinned manager on demand, which would put a network call in a
// plain scan. Comparing what the repository declares is also the more accurate
// question, since that is what CI installs with, not whatever is on this
// machine's PATH.
//
// Unreadable or unrecognized inputs are skipped: malformed lockfiles are the
// detector's error to report, not this check's.
func ResolutionWarnings(projectDir string, manager sdk.PackageManager, lockfile LockfileFormat) []sdk.ResolutionWarning {
	projectDir = strings.TrimSpace(projectDir)
	if projectDir == "" {
		return nil
	}
	pkg := readPackageJSONConfig(projectDir)

	var warnings []sdk.ResolutionWarning
	warnings = append(warnings, packageManagerWarnings(projectDir, manager, lockfile, pkg)...)
	warnings = append(warnings, installGateWarnings(projectDir, manager)...)
	if len(warnings) == 0 {
		return nil
	}
	return warnings
}

// packageJSONConfig is the subset of package.json that constrains which
// package-manager version an install runs with.
type packageJSONConfig struct {
	PackageManager string            `json:"packageManager"`
	Engines        map[string]string `json:"engines"`
}

func packageManagerWarnings(projectDir string, manager sdk.PackageManager, lockfile LockfileFormat, pkg *packageJSONConfig) []sdk.ResolutionWarning {
	if pkg == nil {
		return nil
	}
	pinnedManager, pinnedVersion := parsePackageManagerPin(pkg.PackageManager)
	if pinnedManager == sdk.PackageManagerUnknown {
		return nil
	}
	binary := managerBinaries[pinnedManager]

	var warnings []sdk.ResolutionWarning
	if pinnedManager != manager {
		if committed := committedLockfile(projectDir, manager, lockfile); committed != "" {
			warnings = append(warnings, sdk.ResolutionWarning{
				Code:   sdk.ResolutionWarningPackageManager,
				Source: binary,
				Message: fmt.Sprintf("package.json pins packageManager %q but the project commits %s; CI installs with the pinned manager and will not use this lockfile",
					collapse(pkg.PackageManager), committed),
			})
		}
	}
	warnings = append(warnings, lockfileFormatWarning(pinnedManager, pinnedVersion, lockfile, binary)...)
	warnings = append(warnings, enginesWarning(pkg, pinnedManager, pinnedVersion, binary)...)
	return warnings
}

// lockfileFormatWarning compares the committed lockfile's format version with
// the package-manager version the project pins. A pin below the format's range
// cannot read the lockfile; a pin above it migrates the lockfile on install,
// which fails a frozen-lockfile CI step.
func lockfileFormatWarning(pinnedManager sdk.PackageManager, pinnedVersion string, lockfile LockfileFormat, binary string) []sdk.ResolutionWarning {
	if lockfile.File == "" || lockfile.Version == "" || pinnedVersion == "" {
		return nil
	}
	if pinnedManager != lockfileManager(lockfile.File) {
		return nil
	}
	pinnedMajor, ok := majorVersion(pinnedVersion)
	if !ok {
		return nil
	}
	formatMajor, ok := majorVersion(lockfile.Version)
	if !ok {
		return nil
	}
	minMajor, maxMajor := managerRangeForFormat(pinnedManager, formatMajor)
	switch {
	case minMajor > 0 && pinnedMajor < minMajor:
		return []sdk.ResolutionWarning{{
			Code:   sdk.ResolutionWarningLockfileFormat,
			Source: binary,
			Message: fmt.Sprintf("%s is format version %s, which requires %s >= %d, but package.json pins %s@%s; CI cannot read this lockfile",
				lockfile.File, lockfile.Version, binary, minMajor, binary, pinnedVersion),
		}}
	case maxMajor > 0 && pinnedMajor > maxMajor:
		return []sdk.ResolutionWarning{{
			Code:   sdk.ResolutionWarningLockfileFormat,
			Source: binary,
			Message: fmt.Sprintf("%s is format version %s, written by %s %d.x or older, but package.json pins %s@%s; it migrates the lockfile on install, so a frozen-lockfile CI step fails",
				lockfile.File, lockfile.Version, binary, maxMajor, binary, pinnedVersion),
		}}
	default:
		return nil
	}
}

// enginesWarning reports a project that contradicts itself: the engines
// constraint CI enforces excludes the very version packageManager pins.
func enginesWarning(pkg *packageJSONConfig, pinnedManager sdk.PackageManager, pinnedVersion, binary string) []sdk.ResolutionWarning {
	if pinnedVersion == "" || len(pkg.Engines) == 0 {
		return nil
	}
	constraintText := strings.TrimSpace(pkg.Engines[managerBinaries[pinnedManager]])
	if constraintText == "" {
		return nil
	}
	constraint, err := semver.NewConstraint(constraintText)
	if err != nil {
		return nil
	}
	version, err := semver.NewVersion(pinnedVersion)
	if err != nil || constraint.Check(version) {
		return nil
	}
	return []sdk.ResolutionWarning{{
		Code:   sdk.ResolutionWarningEngines,
		Source: binary,
		Message: fmt.Sprintf("package.json pins %s@%s but requires engines.%s %q; the pinned manager cannot satisfy the project's own constraint",
			binary, pinnedVersion, binary, collapse(constraintText)),
	}}
}

// installGateWarnings reports install policies that reject freshly published
// versions — the gate that makes "upgrade to the fixed version" fail in CI even
// though the advisory is resolved.
func installGateWarnings(projectDir string, manager sdk.PackageManager) []sdk.ResolutionWarning {
	var warnings []sdk.ResolutionWarning
	source := managerBinaries[manager]
	if source == "" {
		source = "npm"
	}
	if minutes, ok := workspaceMinimumReleaseAge(projectDir); ok {
		warnings = append(warnings, releaseAgeWarning(source, "pnpm-workspace.yaml sets minimumReleaseAge", minutes))
	}
	npmrc := readNpmrc(projectDir)
	if minutes, ok := npmrcMinutes(npmrc, "minimum-release-age"); ok {
		warnings = append(warnings, releaseAgeWarning(source, ".npmrc sets minimum-release-age", minutes))
	}
	if before := strings.TrimSpace(npmrc["before"]); before != "" {
		warnings = append(warnings, sdk.ResolutionWarning{
			Code:   sdk.ResolutionWarningInstallGate,
			Source: source,
			Message: fmt.Sprintf(".npmrc sets before=%s; versions published after that date are not installable, so a newer fixed version is rejected in CI",
				collapse(before)),
		})
	}
	return warnings
}

func releaseAgeWarning(source, setting string, minutes int) sdk.ResolutionWarning {
	return sdk.ResolutionWarning{
		Code:   sdk.ResolutionWarningInstallGate,
		Source: source,
		Message: fmt.Sprintf("%s=%d (%s); versions published inside that window are rejected at install, so a freshly published fix version fails CI until it ages out",
			setting, minutes, formatMinutes(minutes)),
	}
}

// committedLockfile returns the lockfile evidence for manager: the format the
// detector reported, or the first lockfile of that manager present on disk.
func committedLockfile(projectDir string, manager sdk.PackageManager, lockfile LockfileFormat) string {
	if lockfile.File != "" {
		return lockfile.File
	}
	for _, name := range managerLockfiles[manager] {
		if _, err := os.Stat(filepath.Join(projectDir, name)); err == nil {
			return name
		}
	}
	return ""
}

func lockfileManager(file string) sdk.PackageManager {
	for manager, names := range managerLockfiles {
		for _, name := range names {
			if name == file {
				return manager
			}
		}
	}
	return sdk.PackageManagerUnknown
}

// managerRangeForFormat maps a lockfile format major to the range of
// package-manager majors that keep it as-is. maxMajor 0 means unbounded.
//
//   - pnpm: 5.x is pnpm 5-7, 6.0 is pnpm 8, 9.0 is pnpm 9 and every newer major
//     released so far. Formats newer than any Bomly knows are assumed to track
//     the manager major.
//   - npm: lockfileVersion 2 and 3 were introduced by npm 7; version 1 is read
//     by every npm.
//   - yarn: format 1 is Yarn Classic; any Berry lockfile needs Yarn 2+.
func managerRangeForFormat(manager sdk.PackageManager, formatMajor int) (minMajor, maxMajor int) {
	switch manager {
	case sdk.PackageManagerPNPM:
		switch {
		case formatMajor <= 0:
			return 0, 0
		case formatMajor <= 5:
			return 5, 7
		case formatMajor == 6:
			return 8, 8
		default:
			return formatMajor, 0
		}
	case sdk.PackageManagerNPM:
		if formatMajor >= 2 {
			return 7, 0
		}
		return 0, 0
	case sdk.PackageManagerYarn:
		if formatMajor <= 1 {
			return 1, 1
		}
		return 2, 0
	default:
		return 0, 0
	}
}

// readPackageJSONConfig reads dir/package.json. Missing or malformed files
// yield nil.
func readPackageJSONConfig(dir string) *packageJSONConfig {
	data, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return nil
	}
	var pkg packageJSONConfig
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}
	return &pkg
}

// parsePackageManagerPin splits a Corepack "packageManager" value such as
// "pnpm@10.4.1+sha512.abc" into its manager and version.
func parsePackageManagerPin(pin string) (sdk.PackageManager, string) {
	pin = strings.TrimSpace(pin)
	if pin == "" {
		return sdk.PackageManagerUnknown, ""
	}
	name, version, _ := strings.Cut(pin, "@")
	version, _, _ = strings.Cut(version, "+")
	manager := sdk.PackageManager(strings.ToLower(strings.TrimSpace(name)))
	if _, ok := managerBinaries[manager]; !ok {
		return sdk.PackageManagerUnknown, ""
	}
	return manager, strings.TrimSpace(version)
}

// workspaceMinimumReleaseAge reads pnpm-workspace.yaml's minimumReleaseAge
// (minutes), the pnpm 10.16+ install gate for freshly published versions.
func workspaceMinimumReleaseAge(dir string) (int, bool) {
	data, err := os.ReadFile(filepath.Join(dir, "pnpm-workspace.yaml"))
	if err != nil {
		return 0, false
	}
	var workspace struct {
		MinimumReleaseAge *int `yaml:"minimumReleaseAge"`
	}
	if err := yaml.Unmarshal(data, &workspace); err != nil {
		return 0, false
	}
	if workspace.MinimumReleaseAge == nil || *workspace.MinimumReleaseAge <= 0 {
		return 0, false
	}
	return *workspace.MinimumReleaseAge, true
}

// readNpmrc parses dir/.npmrc into lowercase keys. Values are returned verbatim.
func readNpmrc(dir string) map[string]string {
	data, err := os.ReadFile(filepath.Join(dir, ".npmrc"))
	if err != nil {
		return nil
	}
	settings := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		settings[strings.ToLower(strings.TrimSpace(key))] = strings.Trim(strings.TrimSpace(value), `"'`)
	}
	return settings
}

func npmrcMinutes(settings map[string]string, key string) (int, bool) {
	raw, ok := settings[key]
	if !ok {
		return 0, false
	}
	minutes, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || minutes <= 0 {
		return 0, false
	}
	return minutes, true
}

func formatMinutes(minutes int) string {
	duration := time.Duration(minutes) * time.Minute
	if duration >= time.Hour && duration%time.Hour == 0 {
		return fmt.Sprintf("%dh", int(duration/time.Hour))
	}
	return duration.String()
}

// majorVersion extracts the leading major component of a version or lockfile
// format string ("10.4.1", "9.0", "3").
func majorVersion(value string) (int, bool) {
	value = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(value), "v"))
	if value == "" {
		return 0, false
	}
	head, _, _ := strings.Cut(value, ".")
	head, _, _ = strings.Cut(head, "-")
	major, err := strconv.Atoi(head)
	if err != nil || major < 0 {
		return 0, false
	}
	return major, true
}

// collapse folds whitespace so values read out of scanned repository content
// cannot inject extra lines into single-line warning channels.
func collapse(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

// AttachResolutionWarnings records warnings on a manifest, creating the
// resolution metadata only when there is something to report so manifests
// without warnings keep their existing shape.
func AttachResolutionWarnings(manifest *sdk.ManifestMetadata, warnings []sdk.ResolutionWarning) {
	if manifest == nil || len(warnings) == 0 {
		return
	}
	if manifest.Resolution == nil {
		manifest.Resolution = &sdk.ResolutionMetadata{}
	}
	manifest.Resolution.Warnings = append(manifest.Resolution.Warnings, warnings...)
}
