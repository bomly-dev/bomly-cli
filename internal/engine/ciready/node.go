package ciready

import (
	"context"
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

// nodeManagerBinaries maps the Node package managers Bomly detects to the
// binary name their version is probed under.
var nodeManagerBinaries = map[sdk.PackageManager]string{
	sdk.PackageManagerNPM:  "npm",
	sdk.PackageManagerPNPM: "pnpm",
	sdk.PackageManagerYarn: "yarn",
	sdk.PackageManagerBun:  "bun",
}

func hasNodeManager(managers []sdk.PackageManager) bool {
	for _, manager := range managers {
		if _, ok := nodeManagerBinaries[manager]; ok {
			return true
		}
	}
	return false
}

// nodePackageJSON is the subset of package.json that drives CI-readiness
// checks: the Corepack pin and the engines constraints CI enforces.
type nodePackageJSON struct {
	PackageManager string            `json:"packageManager"`
	Engines        map[string]string `json:"engines"`
}

// nodeLockfile describes one lockfile found in a project directory.
type nodeLockfile struct {
	manager sdk.PackageManager
	file    string // base name, e.g. "pnpm-lock.yaml"
	format  string // format version as written in the lockfile, e.g. "9.0"
	major   int    // format major version, 0 when unknown
	// minMajor is the lowest package-manager major version that understands
	// this lockfile format. 0 when unknown or unbounded.
	minMajor int
	// maxMajor is the highest package-manager major version that keeps this
	// format as-is; newer majors migrate the lockfile. 0 when unbounded.
	maxMajor int
}

func (r *run) inspectNodeProject(ctx context.Context, dir, relativePath string) []Diagnostic {
	prefix := pathPrefix(relativePath)
	pkg := readNodePackageJSON(dir)
	lockfiles := discoverNodeLockfiles(dir)

	var diagnostics []Diagnostic
	diagnostics = append(diagnostics, r.pinDiagnostics(ctx, prefix, pkg, lockfiles)...)
	diagnostics = append(diagnostics, r.enginesDiagnostics(ctx, prefix, pkg)...)
	diagnostics = append(diagnostics, r.lockfileFormatDiagnostics(ctx, prefix, lockfiles)...)
	diagnostics = append(diagnostics, installGateDiagnostics(prefix, dir)...)
	return diagnostics
}

// pinDiagnostics checks the package.json "packageManager" pin against the
// lockfiles on disk and against the manager version on PATH.
func (r *run) pinDiagnostics(ctx context.Context, prefix string, pkg *nodePackageJSON, lockfiles []nodeLockfile) []Diagnostic {
	if pkg == nil {
		return nil
	}
	pinnedManager, pinnedVersion := parsePackageManagerPin(pkg.PackageManager)
	binary, known := nodeManagerBinaries[pinnedManager]
	if !known {
		return nil
	}

	var diagnostics []Diagnostic
	for _, lockfile := range lockfiles {
		if lockfile.manager == pinnedManager {
			continue
		}
		diagnostics = append(diagnostics, Diagnostic{
			Source: binary,
			Message: fmt.Sprintf("%spackage.json pins packageManager %q but the directory holds %s; CI installs with the pinned manager and will not use the committed %s lockfile",
				prefix, pkg.PackageManager, lockfile.file, lockfile.manager.Name()),
		})
	}

	if pinnedVersion == "" {
		return diagnostics
	}
	installed, ok := r.version(ctx, binary)
	if !ok {
		return diagnostics
	}
	pinnedMajor, pinnedOK := majorVersion(pinnedVersion)
	installedMajor, installedOK := majorVersion(installed)
	if !pinnedOK || !installedOK || pinnedMajor == installedMajor {
		return diagnostics
	}
	diagnostics = append(diagnostics, Diagnostic{
		Source: binary,
		Message: fmt.Sprintf("%spackage.json pins %s@%s but %s %s is on PATH; the local lockfile can be written in a format the pinned major does not accept (enable Corepack or install %s %d.x)",
			prefix, binary, pinnedVersion, binary, installed, binary, pinnedMajor),
	})
	return diagnostics
}

// enginesDiagnostics checks package.json "engines" constraints against the
// versions on PATH. CI runners enforce these with engine-strict.
func (r *run) enginesDiagnostics(ctx context.Context, prefix string, pkg *nodePackageJSON) []Diagnostic {
	if pkg == nil || len(pkg.Engines) == 0 {
		return nil
	}
	var diagnostics []Diagnostic
	for _, binary := range []string{"node", "npm", "pnpm", "yarn", "bun"} {
		constraintText := strings.TrimSpace(pkg.Engines[binary])
		if constraintText == "" {
			continue
		}
		constraint, err := semver.NewConstraint(constraintText)
		if err != nil {
			continue
		}
		installed, ok := r.version(ctx, binary)
		if !ok {
			continue
		}
		version, err := semver.NewVersion(installed)
		if err != nil {
			continue
		}
		if constraint.Check(version) {
			continue
		}
		diagnostics = append(diagnostics, Diagnostic{
			Source: binary,
			Message: fmt.Sprintf("%spackage.json requires engines.%s %q but %s %s is on PATH; installs fail wherever engine-strict is set",
				prefix, binary, constraintText, binary, installed),
		})
	}
	return diagnostics
}

// lockfileFormatDiagnostics compares each lockfile's format version against the
// manager version on PATH, in both directions: a format too new to be read, and
// a format so old the manager rewrites it (which fails a frozen-lockfile install).
func (r *run) lockfileFormatDiagnostics(ctx context.Context, prefix string, lockfiles []nodeLockfile) []Diagnostic {
	var diagnostics []Diagnostic
	for _, lockfile := range lockfiles {
		binary, known := nodeManagerBinaries[lockfile.manager]
		if !known || lockfile.major == 0 {
			continue
		}
		installed, ok := r.version(ctx, binary)
		if !ok {
			continue
		}
		installedMajor, majorOK := majorVersion(installed)
		if !majorOK {
			continue
		}
		switch {
		case lockfile.minMajor > 0 && installedMajor < lockfile.minMajor:
			diagnostics = append(diagnostics, Diagnostic{
				Source: binary,
				Message: fmt.Sprintf("%s%s is format version %s, which requires %s >= %d, but %s %s is on PATH; CI cannot read this lockfile",
					prefix, lockfile.file, lockfile.format, binary, lockfile.minMajor, binary, installed),
			})
		case lockfile.maxMajor > 0 && installedMajor > lockfile.maxMajor:
			diagnostics = append(diagnostics, Diagnostic{
				Source: binary,
				Message: fmt.Sprintf("%s%s is format version %s, written by %s %d.x or older, but %s %s is on PATH; it migrates the lockfile on install, so a frozen-lockfile CI step fails",
					prefix, lockfile.file, lockfile.format, binary, lockfile.maxMajor, binary, installed),
			})
		}
	}
	return diagnostics
}

// installGateDiagnostics reports install policies that reject freshly
// published versions — the gate that makes "upgrade to the fixed version" fail
// in CI even though the advisory is resolved.
func installGateDiagnostics(prefix, dir string) []Diagnostic {
	var diagnostics []Diagnostic
	if minutes, ok := workspaceMinimumReleaseAge(dir); ok {
		diagnostics = append(diagnostics, minimumReleaseAgeDiagnostic(prefix, "pnpm-workspace.yaml sets minimumReleaseAge", minutes))
	}
	npmrc := readNpmrc(dir)
	if minutes, ok := npmrcMinutes(npmrc, "minimum-release-age"); ok {
		diagnostics = append(diagnostics, minimumReleaseAgeDiagnostic(prefix, ".npmrc sets minimum-release-age", minutes))
	}
	if before := strings.TrimSpace(npmrc["before"]); before != "" {
		diagnostics = append(diagnostics, Diagnostic{
			Source: "npm",
			Message: fmt.Sprintf("%s.npmrc sets before=%s; versions published after that date are not installable, so a newer fixed version is rejected in CI",
				prefix, before),
		})
	}
	return diagnostics
}

func minimumReleaseAgeDiagnostic(prefix, setting string, minutes int) Diagnostic {
	return Diagnostic{
		Source: "pnpm",
		Message: fmt.Sprintf("%s%s=%d (%s); versions published inside that window are rejected at install, so a freshly published fix version fails CI until it ages out",
			prefix, setting, minutes, formatMinutes(minutes)),
	}
}

func formatMinutes(minutes int) string {
	duration := time.Duration(minutes) * time.Minute
	if duration >= time.Hour && duration%time.Hour == 0 {
		return fmt.Sprintf("%dh", int(duration/time.Hour))
	}
	return duration.String()
}

// readNodePackageJSON reads dir/package.json. Missing or malformed files yield
// nil: CI-readiness checks are best-effort and never surface parse errors that
// the detectors already report.
func readNodePackageJSON(dir string) *nodePackageJSON {
	data, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return nil
	}
	var pkg nodePackageJSON
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
	if _, ok := nodeManagerBinaries[manager]; !ok {
		return sdk.PackageManagerUnknown, ""
	}
	return manager, strings.TrimSpace(version)
}

// discoverNodeLockfiles returns the lockfiles present in dir, in a stable
// order, with their format version resolved where the format records one.
func discoverNodeLockfiles(dir string) []nodeLockfile {
	var lockfiles []nodeLockfile
	if lockfile, ok := readPnpmLockfile(dir); ok {
		lockfiles = append(lockfiles, lockfile)
	}
	for _, name := range []string{"package-lock.json", "npm-shrinkwrap.json"} {
		if lockfile, ok := readNpmLockfile(dir, name); ok {
			lockfiles = append(lockfiles, lockfile)
		}
	}
	if lockfile, ok := readYarnLockfile(dir); ok {
		lockfiles = append(lockfiles, lockfile)
	}
	for _, name := range []string{"bun.lock", "bun.lockb"} {
		if exists(filepath.Join(dir, name)) {
			lockfiles = append(lockfiles, nodeLockfile{manager: sdk.PackageManagerBun, file: name})
			break
		}
	}
	return lockfiles
}

func readPnpmLockfile(dir string) (nodeLockfile, bool) {
	const name = "pnpm-lock.yaml"
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return nodeLockfile{}, false
	}
	var lockfile struct {
		LockfileVersion any `yaml:"lockfileVersion"`
	}
	if err := yaml.Unmarshal(data, &lockfile); err != nil {
		return nodeLockfile{manager: sdk.PackageManagerPNPM, file: name}, true
	}
	format := formatVersionString(lockfile.LockfileVersion)
	major, _ := majorVersion(format)
	minMajor, maxMajor := pnpmLockfileManagerRange(major)
	return nodeLockfile{
		manager:  sdk.PackageManagerPNPM,
		file:     name,
		format:   format,
		major:    major,
		minMajor: minMajor,
		maxMajor: maxMajor,
	}, true
}

// pnpmLockfileManagerRange maps a pnpm lockfile format major to the range of
// pnpm majors that keep it as-is: 5.x is pnpm 5-7, 6.0 is pnpm 8, and 9.0 is
// pnpm 9 and every newer major released so far. Formats newer than any Bomly
// knows are assumed to track the manager major.
func pnpmLockfileManagerRange(major int) (minMajor, maxMajor int) {
	switch {
	case major <= 0:
		return 0, 0
	case major <= 5:
		return 5, 7
	case major == 6:
		return 8, 8
	default:
		return major, 0
	}
}

func readNpmLockfile(dir, name string) (nodeLockfile, bool) {
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return nodeLockfile{}, false
	}
	var lockfile struct {
		LockfileVersion int `json:"lockfileVersion"`
	}
	if err := json.Unmarshal(data, &lockfile); err != nil {
		return nodeLockfile{manager: sdk.PackageManagerNPM, file: name}, true
	}
	minMajor := 0
	if lockfile.LockfileVersion >= 2 {
		// lockfileVersion 2 and 3 were introduced by npm 7.
		minMajor = 7
	}
	return nodeLockfile{
		manager:  sdk.PackageManagerNPM,
		file:     name,
		format:   strconv.Itoa(lockfile.LockfileVersion),
		major:    lockfile.LockfileVersion,
		minMajor: minMajor,
	}, true
}

// readYarnLockfile distinguishes a Yarn Classic (v1) lockfile from a Berry
// lockfile, which records its format under the __metadata key.
func readYarnLockfile(dir string) (nodeLockfile, bool) {
	const name = "yarn.lock"
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return nodeLockfile{}, false
	}
	lockfile := nodeLockfile{manager: sdk.PackageManagerYarn, file: name}
	if !strings.Contains(string(data), "__metadata:") {
		lockfile.format = "1"
		lockfile.major = 1
		lockfile.minMajor = 1
		lockfile.maxMajor = 1
		return lockfile, true
	}
	var berry struct {
		Metadata struct {
			Version any `yaml:"version"`
		} `yaml:"__metadata"`
	}
	if err := yaml.Unmarshal(data, &berry); err == nil {
		lockfile.format = formatVersionString(berry.Metadata.Version)
	}
	if lockfile.format == "" {
		lockfile.format = "berry"
	}
	// Every Berry lockfile format needs Yarn 2 or newer; the __metadata version
	// tracks Berry's internal cache format, not the Yarn major.
	lockfile.major = 2
	lockfile.minMajor = 2
	return lockfile, true
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

// formatVersionString renders a YAML scalar lockfile version ("9.0", 9, 6.0)
// as the string the lockfile author would recognize.
func formatVersionString(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(typed)
	case int:
		return strconv.Itoa(typed)
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	default:
		return strings.TrimSpace(fmt.Sprintf("%v", typed))
	}
}

// majorVersion extracts the leading major component of a version or format
// string ("10.4.1", "9.0", "3").
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

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
