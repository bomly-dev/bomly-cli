package node

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func writeProject(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", path, err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	return dir
}

func requireWarning(t *testing.T, warnings []sdk.DetectorWarning, code sdk.DetectorWarningCode, substring string) {
	t.Helper()
	for _, warning := range warnings {
		if warning.Code != code || !strings.Contains(warning.Message, substring) {
			continue
		}
		if warning.Type != sdk.DetectorWarningPackageManager {
			t.Fatalf("expected the package-manager type, got %q", warning.Type)
		}
		if warning.DegradesCoverage() {
			t.Fatalf("package-manager warnings must not claim degraded coverage: %+v", warning)
		}
		return
	}
	t.Fatalf("no %s warning containing %q in %+v", code, substring, warnings)
}

func TestPackageManagerWarnings_PinnedManagerCannotReadLockfileFormat(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"package.json":   `{"name": "app", "packageManager": "pnpm@8.15.4"}`,
		"pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
	})
	warnings := PackageManagerWarnings(dir, sdk.PackageManagerPNPM, LockfileFormat{File: "pnpm-lock.yaml", Version: "9.0"})
	requireWarning(t, warnings, sdk.DetectorWarningCodeLockfileFormat, "requires pnpm >= 9, but package.json pins pnpm@8.15.4")
}

func TestPackageManagerWarnings_PinnedManagerMigratesOlderLockfileFormat(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"package.json":   `{"name": "app", "packageManager": "pnpm@11.0.0+sha512.abc"}`,
		"pnpm-lock.yaml": "lockfileVersion: '6.0'\n",
	})
	warnings := PackageManagerWarnings(dir, sdk.PackageManagerPNPM, LockfileFormat{File: "pnpm-lock.yaml", Version: "6.0"})
	requireWarning(t, warnings, sdk.DetectorWarningCodeLockfileFormat, "frozen-lockfile CI step fails")
}

func TestPackageManagerWarnings_CurrentFormatAndPinAreQuiet(t *testing.T) {
	// pnpm 10 and 11 still write lockfileVersion 9.0: same format, no warning.
	dir := writeProject(t, map[string]string{
		"package.json":   `{"name": "app", "packageManager": "pnpm@10.4.1"}`,
		"pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
	})
	if warnings := PackageManagerWarnings(dir, sdk.PackageManagerPNPM, LockfileFormat{File: "pnpm-lock.yaml", Version: "9.0"}); warnings != nil {
		t.Fatalf("expected no warnings, got %+v", warnings)
	}
}

func TestPackageManagerWarnings_NpmLockfileVersionRequiresNpm7(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"package.json":      `{"name": "app", "packageManager": "npm@6.14.18"}`,
		"package-lock.json": `{"lockfileVersion": 3}`,
	})
	warnings := PackageManagerWarnings(dir, sdk.PackageManagerNPM, LockfileFormat{File: "package-lock.json", Version: "3"})
	requireWarning(t, warnings, sdk.DetectorWarningCodeLockfileFormat, "requires npm >= 7")
}

func TestPackageManagerWarnings_YarnClassicLockfileWithBerryPin(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"package.json": `{"name": "app", "packageManager": "yarn@4.1.0"}`,
		"yarn.lock":    "# yarn lockfile v1\n",
	})
	warnings := PackageManagerWarnings(dir, sdk.PackageManagerYarn, LockfileFormat{File: "yarn.lock", Version: "1"})
	requireWarning(t, warnings, sdk.DetectorWarningCodeLockfileFormat, "migrates the lockfile on install")
}

func TestPackageManagerWarnings_BerryLockfileWithClassicPin(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"package.json": `{"name": "app", "packageManager": "yarn@1.22.22"}`,
		"yarn.lock":    "__metadata:\n  version: 8\n",
	})
	warnings := PackageManagerWarnings(dir, sdk.PackageManagerYarn, LockfileFormat{File: "yarn.lock", Version: "8"})
	requireWarning(t, warnings, sdk.DetectorWarningCodeLockfileFormat, "requires yarn >= 2")
}

func TestPackageManagerWarnings_PinnedManagerDoesNotReadCommittedLockfile(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"package.json":   `{"name": "app", "packageManager": "yarn@4.1.0"}`,
		"pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
	})
	warnings := PackageManagerWarnings(dir, sdk.PackageManagerPNPM, LockfileFormat{File: "pnpm-lock.yaml", Version: "9.0"})
	requireWarning(t, warnings, sdk.DetectorWarningCodeLockfileUnsupported, `pins packageManager "yarn@4.1.0", which does not read pnpm-lock.yaml`)
	// The format check is scoped to the pinned manager's own lockfile: a yarn pin
	// says nothing about which pnpm version wrote pnpm-lock.yaml.
	for _, warning := range warnings {
		if warning.Code == sdk.DetectorWarningCodeLockfileFormat {
			t.Fatalf("unexpected cross-manager format warning: %+v", warning)
		}
	}
}

func TestPackageManagerWarnings_NpmAcceptsYarnLockfile(t *testing.T) {
	// npm documents yarn.lock as install input after package-lock.json, so an npm
	// pin beside a yarn.lock is interoperability, not a mismatch.
	dir := writeProject(t, map[string]string{
		"package.json": `{"name": "app", "packageManager": "npm@10.9.0"}`,
		"yarn.lock":    "# yarn lockfile v1\n",
	})
	if warnings := PackageManagerWarnings(dir, sdk.PackageManagerYarn, LockfileFormat{File: "yarn.lock", Version: "1"}); warnings != nil {
		t.Fatalf("expected no warnings for an interoperable lockfile, got %+v", warnings)
	}
}

func TestPackageManagerWarnings_UndocumentedCombinationsStaySilent(t *testing.T) {
	// Bun's handling of npm lockfiles is not documented either way, so an unknown
	// combination stays silent rather than guessing.
	dir := writeProject(t, map[string]string{
		"package.json":      `{"name": "app", "packageManager": "bun@1.2.18"}`,
		"package-lock.json": `{"lockfileVersion": 3}`,
	})
	if warnings := PackageManagerWarnings(dir, sdk.PackageManagerNPM, LockfileFormat{File: "package-lock.json", Version: "3"}); warnings != nil {
		t.Fatalf("expected no warnings for an undocumented combination, got %+v", warnings)
	}
}

func TestPackageManagerWarnings_SecondLockfileFoundOnDisk(t *testing.T) {
	// The detector parsed pnpm-lock.yaml; the stray npm lockfile is found by stat.
	dir := writeProject(t, map[string]string{
		"package.json":      `{"name": "app", "packageManager": "pnpm@10.4.1"}`,
		"pnpm-lock.yaml":    "lockfileVersion: '9.0'\n",
		"package-lock.json": `{"lockfileVersion": 3}`,
	})
	warnings := PackageManagerWarnings(dir, sdk.PackageManagerPNPM, LockfileFormat{File: "pnpm-lock.yaml", Version: "9.0"})
	requireWarning(t, warnings, sdk.DetectorWarningCodeLockfileUnsupported, "does not read package-lock.json")
}

func TestPackageManagerWarnings_EnginesContradictsPin(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"package.json": `{"name": "app", "packageManager": "pnpm@9.15.0", "engines": {"pnpm": ">=10"}}`,
	})
	warnings := PackageManagerWarnings(dir, sdk.PackageManagerPNPM, LockfileFormat{})
	requireWarning(t, warnings, sdk.DetectorWarningCodeEnginesConstraint, `pins pnpm@9.15.0 but requires engines.pnpm ">=10"`)
}

func TestPackageManagerWarnings_EnginesSatisfiedByPin(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"package.json": `{"name": "app", "packageManager": "pnpm@10.4.1", "engines": {"pnpm": ">=10", "node": ">=22"}}`,
	})
	if warnings := PackageManagerWarnings(dir, sdk.PackageManagerPNPM, LockfileFormat{}); warnings != nil {
		t.Fatalf("expected no warnings, got %+v", warnings)
	}
}

func TestPackageManagerWarnings_PnpmInstallGateUsesMinutes(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"pnpm-workspace.yaml": "packages:\n  - packages/*\nminimumReleaseAge: 1440\n",
	})
	warnings := PackageManagerWarnings(dir, sdk.PackageManagerPNPM, LockfileFormat{})
	requireWarning(t, warnings, sdk.DetectorWarningCodeInstallGate, "minimumReleaseAge=1440 (24h)")
	requireWarning(t, warnings, sdk.DetectorWarningCodeInstallGate, "freshly published fix version fails CI")
	if warnings[0].Source != "pnpm" || warnings[0].Manifest != "pnpm-workspace.yaml" {
		t.Fatalf("unexpected gate warning attribution: %+v", warnings[0])
	}
}

func TestPackageManagerWarnings_NpmInstallGatesUseDays(t *testing.T) {
	// npm's key is min-release-age and its unit is days, not pnpm's minutes.
	dir := writeProject(t, map[string]string{
		".npmrc": "min-release-age=7\nbefore=2026-01-01\n",
	})
	warnings := PackageManagerWarnings(dir, sdk.PackageManagerNPM, LockfileFormat{})
	requireWarning(t, warnings, sdk.DetectorWarningCodeInstallGate, "min-release-age=7 (7 days)")
	requireWarning(t, warnings, sdk.DetectorWarningCodeInstallGate, "before=2026-01-01")
	for _, warning := range warnings {
		if warning.Source != "npm" {
			t.Fatalf("expected npm-sourced gate warnings, got %+v", warning)
		}
	}
}

func TestPackageManagerWarnings_GatesAreScopedToTheEffectiveManager(t *testing.T) {
	// Current pnpm reads only auth and registry settings from .npmrc, and npm never
	// had pnpm's minimum-release-age, so neither key is an active gate here.
	dir := writeProject(t, map[string]string{
		"package.json": `{"name": "app", "packageManager": "pnpm@11.0.0"}`,
		".npmrc":       "minimum-release-age=1440\nmin-release-age=7\nbefore=2026-01-01\n",
	})
	if warnings := PackageManagerWarnings(dir, sdk.PackageManagerPNPM, LockfileFormat{}); warnings != nil {
		t.Fatalf("expected no gate warnings for keys pnpm ignores, got %+v", warnings)
	}

	// The pin also overrides the detector's manager when deciding whose gates apply.
	dir = writeProject(t, map[string]string{
		"package.json":        `{"name": "app", "packageManager": "npm@10.9.0"}`,
		"pnpm-workspace.yaml": "minimumReleaseAge: 1440\n",
	})
	if warnings := PackageManagerWarnings(dir, sdk.PackageManagerPNPM, LockfileFormat{}); warnings != nil {
		t.Fatalf("expected pnpm's gate to be ignored under an npm pin, got %+v", warnings)
	}
}

func TestPackageManagerWarnings_IgnoresDisabledOrAbsentGates(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"pnpm-workspace.yaml": "packages:\n  - packages/*\nminimumReleaseAge: 0\n",
		".npmrc":              "registry=https://registry.npmjs.org/\n# min-release-age=7\n",
	})
	if warnings := PackageManagerWarnings(dir, sdk.PackageManagerPNPM, LockfileFormat{}); warnings != nil {
		t.Fatalf("expected no warnings, got %+v", warnings)
	}
}

func TestPackageManagerWarnings_MalformedInputsAreSilent(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"package.json":        "{ not json",
		"pnpm-workspace.yaml": "\tminimumReleaseAge: ][",
		".npmrc":              "no-equals-sign\n",
	})
	if warnings := PackageManagerWarnings(dir, sdk.PackageManagerPNPM, LockfileFormat{File: "pnpm-lock.yaml", Version: "9.0"}); warnings != nil {
		t.Fatalf("expected no warnings, got %+v", warnings)
	}
}

func TestPackageManagerWarnings_UnknownPinAndEmptyDirAreSilent(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"package.json":   `{"name": "app", "packageManager": "cargo@1.0.0"}`,
		"pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
	})
	if warnings := PackageManagerWarnings(dir, sdk.PackageManagerPNPM, LockfileFormat{File: "pnpm-lock.yaml", Version: "9.0"}); warnings != nil {
		t.Fatalf("expected no warnings for an unrecognized pin, got %+v", warnings)
	}
	if warnings := PackageManagerWarnings("  ", sdk.PackageManagerPNPM, LockfileFormat{}); warnings != nil {
		t.Fatalf("expected no warnings for an empty directory, got %+v", warnings)
	}
}

func TestPackageManagerWarnings_CollapsesNewlinesInScannedValues(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"package.json": `{"name": "app", "packageManager": "pnpm@9.15.0", "engines": {"pnpm": ">=10\n\nInjected: line"}}`,
	})
	for _, warning := range PackageManagerWarnings(dir, sdk.PackageManagerPNPM, LockfileFormat{}) {
		if strings.Contains(warning.Message, "\n") {
			t.Fatalf("warning message must stay single-line: %q", warning.Message)
		}
	}
}

func TestManagerRangeForFormat(t *testing.T) {
	cases := []struct {
		manager  sdk.PackageManager
		format   int
		min, max int
	}{
		{sdk.PackageManagerPNPM, 5, 5, 7},
		{sdk.PackageManagerPNPM, 6, 8, 8},
		{sdk.PackageManagerPNPM, 9, 9, 0},
		{sdk.PackageManagerPNPM, 12, 12, 0},
		{sdk.PackageManagerNPM, 1, 0, 0},
		{sdk.PackageManagerNPM, 3, 7, 0},
		{sdk.PackageManagerYarn, 1, 1, 1},
		{sdk.PackageManagerYarn, 8, 2, 0},
		{sdk.PackageManagerBun, 1, 0, 0},
	}
	for _, tc := range cases {
		minMajor, maxMajor := managerRangeForFormat(tc.manager, tc.format)
		if minMajor != tc.min || maxMajor != tc.max {
			t.Fatalf("managerRangeForFormat(%s, %d) = (%d, %d), want (%d, %d)", tc.manager, tc.format, minMajor, maxMajor, tc.min, tc.max)
		}
	}
}

func TestLockfileUnread(t *testing.T) {
	cases := []struct {
		manager sdk.PackageManager
		file    string
		want    bool
	}{
		{sdk.PackageManagerNPM, "yarn.lock", false},         // documented install input
		{sdk.PackageManagerNPM, "pnpm-lock.yaml", true},     // documented as not read
		{sdk.PackageManagerPNPM, "yarn.lock", true},         // conversion is a manual `pnpm import`
		{sdk.PackageManagerPNPM, "pnpm-lock.yaml", false},   // its own lockfile
		{sdk.PackageManagerBun, "pnpm-lock.yaml", false},    // converted on install
		{sdk.PackageManagerBun, "yarn.lock", false},         // undocumented: stay silent
		{sdk.PackageManagerYarn, "package-lock.json", true}, // documented as not read
	}
	for _, tc := range cases {
		if got := lockfileUnread(tc.manager, tc.file); got != tc.want {
			t.Fatalf("lockfileUnread(%s, %s) = %v, want %v", tc.manager, tc.file, got, tc.want)
		}
	}
}

func TestParsePackageManagerPin(t *testing.T) {
	manager, version := parsePackageManagerPin("pnpm@10.4.1+sha512.abc")
	if manager != sdk.PackageManagerPNPM || version != "10.4.1" {
		t.Fatalf("parsePackageManagerPin() = (%q, %q)", manager, version)
	}
	if manager, _ := parsePackageManagerPin("cargo@1.0.0"); manager != sdk.PackageManagerUnknown {
		t.Fatalf("expected unknown manager, got %q", manager)
	}
	if manager, _ := parsePackageManagerPin(""); manager != sdk.PackageManagerUnknown {
		t.Fatalf("expected unknown manager for an empty pin, got %q", manager)
	}
}

func TestFormatDurations(t *testing.T) {
	minutes := map[int]string{1440: "24h", 4320: "72h", 60: "1h", 30: "30m0s", 90: "1h30m0s"}
	for value, want := range minutes {
		if got := formatMinutes(value); got != want {
			t.Fatalf("formatMinutes(%d) = %q, want %q", value, got, want)
		}
	}
	days := map[int]string{1: "1 day", 7: "7 days"}
	for value, want := range days {
		if got := formatDays(value); got != want {
			t.Fatalf("formatDays(%d) = %q, want %q", value, got, want)
		}
	}
}
