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
// format-versus-declaration check without disabling the rest.
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

// nodeLockfiles are every lockfile name the Node ecosystem commits, used to find
// evidence the detector did not parse itself.
var nodeLockfiles = []string{
	"package-lock.json",
	"npm-shrinkwrap.json",
	"pnpm-lock.yaml",
	"yarn.lock",
	"bun.lock",
	"bun.lockb",
}

// consumedLockfiles lists, per package manager, the lockfiles it reads as
// install input, from each manager's own documentation:
//
//   - npm drives installs from package-lock.json, npm-shrinkwrap.json, or
//     yarn.lock (documented order of precedence in `npm install`).
//   - pnpm reads only pnpm-lock.yaml; converting a foreign lockfile is the
//     separate, manual `pnpm import`.
//   - Yarn reads only yarn.lock.
//   - Bun reads bun.lock/bun.lockb and converts pnpm-lock.yaml on install.
var consumedLockfiles = map[sdk.PackageManager][]string{
	sdk.PackageManagerNPM:  {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock"},
	sdk.PackageManagerPNPM: {"pnpm-lock.yaml"},
	sdk.PackageManagerYarn: {"yarn.lock"},
	sdk.PackageManagerBun:  {"bun.lock", "bun.lockb", "pnpm-lock.yaml"},
}

// unreadLockfiles lists, per package manager, the lockfiles that manager is
// documented not to read, so committing one while pinning that manager is a real
// mismatch. A combination in neither table is treated as unknown and never
// warned about — Bun's handling of npm and Yarn lockfiles, for instance, is not
// documented either way.
var unreadLockfiles = map[sdk.PackageManager][]string{
	sdk.PackageManagerNPM:  {"pnpm-lock.yaml", "bun.lock", "bun.lockb"},
	sdk.PackageManagerPNPM: {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "bun.lock", "bun.lockb"},
	sdk.PackageManagerYarn: {"package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "bun.lock", "bun.lockb"},
	sdk.PackageManagerBun:  nil,
}

// PackageManagerWarnings reports non-fatal problems with a Node project's
// package-manager configuration: the detector resolved a correct graph, but the
// project as committed will trip up an install elsewhere, typically in CI.
// lockfile describes the lockfile the caller parsed, if any.
//
// Every check reads committed files only — package.json, that lockfile,
// pnpm-workspace.yaml, and .npmrc. Nothing is executed: `pnpm`/`yarn` on PATH
// are frequently Corepack shims, and running one can download the pinned
// manager on demand, which would put a network call in a plain scan. Comparing
// what the repository declares is also the more accurate question, since that is
// what CI installs with, not whatever is on this machine's PATH.
//
// Unreadable or unrecognized inputs are skipped: malformed lockfiles are the
// detector's error to report, not this check's.
func PackageManagerWarnings(projectDir string, manager sdk.PackageManager, lockfile LockfileFormat) []sdk.DetectorWarning {
	projectDir = strings.TrimSpace(projectDir)
	if projectDir == "" {
		return nil
	}
	pkg := readPackageJSONConfig(projectDir)
	pinnedManager, pinnedVersion := parsePackageManagerPin(pkg.packageManager())

	// Install gates are keyed to the manager that will actually run: the pin
	// when the project declares one, otherwise the detector's manager.
	effectiveManager := pinnedManager
	if effectiveManager == sdk.PackageManagerUnknown {
		effectiveManager = manager
	}

	var warnings []sdk.DetectorWarning
	warnings = append(warnings, lockfileWarnings(projectDir, pinnedManager, pinnedVersion, lockfile, pkg)...)
	warnings = append(warnings, enginesWarning(pkg, pinnedManager, pinnedVersion)...)
	warnings = append(warnings, installGateWarnings(projectDir, effectiveManager)...)
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

// packageManager returns the raw pin, tolerating a nil config so callers can
// treat "no package.json" as "no declarations".
func (p *packageJSONConfig) packageManager() string {
	if p == nil {
		return ""
	}
	return p.PackageManager
}

func lockfileWarnings(projectDir string, pinnedManager sdk.PackageManager, pinnedVersion string, lockfile LockfileFormat, pkg *packageJSONConfig) []sdk.DetectorWarning {
	if pinnedManager == sdk.PackageManagerUnknown {
		return nil
	}
	binary := managerBinaries[pinnedManager]

	var warnings []sdk.DetectorWarning
	for _, committed := range committedLockfiles(projectDir, lockfile) {
		if !lockfileUnread(pinnedManager, committed) {
			continue
		}
		warnings = append(warnings, sdk.DetectorWarning{
			Type:     sdk.DetectorWarningPackageManager,
			Code:     sdk.DetectorWarningCodeLockfileUnsupported,
			Source:   binary,
			Manifest: committed,
			Message: fmt.Sprintf("package.json pins packageManager %q, which does not read %s; CI installs with the pinned manager and resolves dependencies without this lockfile",
				collapse(pkg.packageManager()), committed),
		})
	}
	return append(warnings, lockfileFormatWarning(pinnedManager, pinnedVersion, lockfile, binary)...)
}

// lockfileUnread reports whether the manager is documented not to read the given
// lockfile. Unknown combinations return false, so an undocumented migration path
// is never reported as a mismatch.
func lockfileUnread(manager sdk.PackageManager, file string) bool {
	for _, name := range consumedLockfiles[manager] {
		if name == file {
			return false
		}
	}
	for _, name := range unreadLockfiles[manager] {
		if name == file {
			return true
		}
	}
	return false
}

// lockfileFormatWarning compares the committed lockfile's format version with
// the package-manager version the project pins. A pin below the format's range
// cannot read the lockfile; a pin above it migrates the lockfile on install,
// which fails a frozen-lockfile CI step.
func lockfileFormatWarning(pinnedManager sdk.PackageManager, pinnedVersion string, lockfile LockfileFormat, binary string) []sdk.DetectorWarning {
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
	warning := sdk.DetectorWarning{
		Type:     sdk.DetectorWarningPackageManager,
		Code:     sdk.DetectorWarningCodeLockfileFormat,
		Source:   binary,
		Manifest: lockfile.File,
	}
	switch {
	case minMajor > 0 && pinnedMajor < minMajor:
		warning.Message = fmt.Sprintf("%s is format version %s, which requires %s >= %d, but package.json pins %s@%s; CI cannot read this lockfile",
			lockfile.File, lockfile.Version, binary, minMajor, binary, pinnedVersion)
	case maxMajor > 0 && pinnedMajor > maxMajor:
		warning.Message = fmt.Sprintf("%s is format version %s, written by %s %d.x or older, but package.json pins %s@%s; it migrates the lockfile on install, so a frozen-lockfile CI step fails",
			lockfile.File, lockfile.Version, binary, maxMajor, binary, pinnedVersion)
	default:
		return nil
	}
	return []sdk.DetectorWarning{warning}
}

// enginesWarning reports a project that contradicts itself: the engines
// constraint CI enforces excludes the very version packageManager pins.
func enginesWarning(pkg *packageJSONConfig, pinnedManager sdk.PackageManager, pinnedVersion string) []sdk.DetectorWarning {
	if pkg == nil || pinnedVersion == "" || len(pkg.Engines) == 0 {
		return nil
	}
	binary := managerBinaries[pinnedManager]
	constraintText := strings.TrimSpace(pkg.Engines[binary])
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
	return []sdk.DetectorWarning{{
		Type:     sdk.DetectorWarningPackageManager,
		Code:     sdk.DetectorWarningCodeEnginesConstraint,
		Source:   binary,
		Manifest: "package.json",
		Message: fmt.Sprintf("package.json pins %s@%s but requires engines.%s %q; the pinned manager cannot satisfy the project's own constraint",
			binary, pinnedVersion, binary, collapse(constraintText)),
	}}
}

// installGateWarnings reports install policies that reject freshly published
// versions — the gate that makes "upgrade to the fixed version" fail in CI even
// though the advisory is resolved.
//
// Each manager's gate lives in a different file, under a different key, in
// different units, and is ignored by the others, so only the manager that will
// run the install is consulted:
//
//   - pnpm reads minimumReleaseAge (minutes) from pnpm-workspace.yaml. Current
//     pnpm reads only auth and registry settings from .npmrc, so a
//     minimum-release-age key there is not treated as an active gate.
//   - npm reads min-release-age (days) and before (a date) from .npmrc.
//   - Yarn and Bun have no equivalent committed gate Bomly models.
func installGateWarnings(projectDir string, manager sdk.PackageManager) []sdk.DetectorWarning {
	switch manager {
	case sdk.PackageManagerPNPM:
		minutes, ok := workspaceMinimumReleaseAge(projectDir)
		if !ok {
			return nil
		}
		return []sdk.DetectorWarning{releaseAgeWarning("pnpm", "pnpm-workspace.yaml",
			fmt.Sprintf("pnpm-workspace.yaml sets minimumReleaseAge=%d (%s)", minutes, formatMinutes(minutes)))}
	case sdk.PackageManagerNPM:
		var warnings []sdk.DetectorWarning
		npmrc := readNpmrc(projectDir)
		if days, ok := npmrcInt(npmrc, "min-release-age"); ok {
			warnings = append(warnings, releaseAgeWarning("npm", ".npmrc",
				fmt.Sprintf(".npmrc sets min-release-age=%d (%s)", days, formatDays(days))))
		}
		if before := strings.TrimSpace(npmrc["before"]); before != "" {
			warnings = append(warnings, sdk.DetectorWarning{
				Type:     sdk.DetectorWarningPackageManager,
				Code:     sdk.DetectorWarningCodeInstallGate,
				Source:   "npm",
				Manifest: ".npmrc",
				Message: fmt.Sprintf(".npmrc sets before=%s; versions published after that date are not installable, so a newer fixed version is rejected in CI",
					collapse(before)),
			})
		}
		return warnings
	default:
		return nil
	}
}

func releaseAgeWarning(source, manifest, setting string) sdk.DetectorWarning {
	return sdk.DetectorWarning{
		Type:     sdk.DetectorWarningPackageManager,
		Code:     sdk.DetectorWarningCodeInstallGate,
		Source:   source,
		Manifest: manifest,
		Message: fmt.Sprintf("%s; versions published inside that window are rejected at install, so a freshly published fix version fails CI until it ages out",
			setting),
	}
}

// committedLockfiles returns the Node lockfiles present in the project: the one
// the detector parsed plus any others on disk, since a second lockfile is
// exactly the evidence the pin check needs.
func committedLockfiles(projectDir string, lockfile LockfileFormat) []string {
	var files []string
	for _, name := range nodeLockfiles {
		if name == lockfile.File {
			files = append(files, name)
			continue
		}
		if _, err := os.Stat(filepath.Join(projectDir, name)); err == nil {
			files = append(files, name)
		}
	}
	return files
}

func lockfileManager(file string) sdk.PackageManager {
	switch file {
	case "package-lock.json", "npm-shrinkwrap.json":
		return sdk.PackageManagerNPM
	case "pnpm-lock.yaml":
		return sdk.PackageManagerPNPM
	case "yarn.lock":
		return sdk.PackageManagerYarn
	case "bun.lock", "bun.lockb":
		return sdk.PackageManagerBun
	default:
		return sdk.PackageManagerUnknown
	}
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

// workspaceMinimumReleaseAge reads pnpm-workspace.yaml's minimumReleaseAge: the
// number of minutes that must pass after a version is published before pnpm
// installs it.
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

func npmrcInt(settings map[string]string, key string) (int, bool) {
	raw, ok := settings[key]
	if !ok {
		return 0, false
	}
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value <= 0 {
		return 0, false
	}
	return value, true
}

func formatMinutes(minutes int) string {
	duration := time.Duration(minutes) * time.Minute
	if duration >= time.Hour && duration%time.Hour == 0 {
		return fmt.Sprintf("%dh", int(duration/time.Hour))
	}
	return duration.String()
}

func formatDays(days int) string {
	if days == 1 {
		return "1 day"
	}
	return fmt.Sprintf("%d days", days)
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
// cannot inject extra lines into single-line warning channels. Rendering applies
// the full untrusted-text sanitizer on top of this.
func collapse(value string) string {
	return strings.Join(strings.Fields(value), " ")
}
