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

func requireWarning(t *testing.T, warnings []sdk.ResolutionWarning, code sdk.ResolutionWarningCode, substring string) {
	t.Helper()
	for _, warning := range warnings {
		if warning.Code == code && strings.Contains(warning.Message, substring) {
			return
		}
	}
	t.Fatalf("no %s warning containing %q in %+v", code, substring, warnings)
}

func TestResolutionWarnings_PinnedManagerCannotReadLockfileFormat(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"package.json":   `{"name": "app", "packageManager": "pnpm@8.15.4"}`,
		"pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
	})
	warnings := ResolutionWarnings(dir, sdk.PackageManagerPNPM, LockfileFormat{File: "pnpm-lock.yaml", Version: "9.0"})
	requireWarning(t, warnings, sdk.ResolutionWarningLockfileFormat, "requires pnpm >= 9, but package.json pins pnpm@8.15.4")
}

func TestResolutionWarnings_PinnedManagerMigratesOlderLockfileFormat(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"package.json":   `{"name": "app", "packageManager": "pnpm@11.0.0+sha512.abc"}`,
		"pnpm-lock.yaml": "lockfileVersion: '6.0'\n",
	})
	warnings := ResolutionWarnings(dir, sdk.PackageManagerPNPM, LockfileFormat{File: "pnpm-lock.yaml", Version: "6.0"})
	requireWarning(t, warnings, sdk.ResolutionWarningLockfileFormat, "frozen-lockfile CI step fails")
}

func TestResolutionWarnings_CurrentFormatAndPinAreQuiet(t *testing.T) {
	// pnpm 10 and 11 still write lockfileVersion 9.0: same format, no warning.
	dir := writeProject(t, map[string]string{
		"package.json":   `{"name": "app", "packageManager": "pnpm@10.4.1"}`,
		"pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
	})
	if warnings := ResolutionWarnings(dir, sdk.PackageManagerPNPM, LockfileFormat{File: "pnpm-lock.yaml", Version: "9.0"}); warnings != nil {
		t.Fatalf("expected no warnings, got %+v", warnings)
	}
}

func TestResolutionWarnings_NpmLockfileVersionRequiresNpm7(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"package.json":      `{"name": "app", "packageManager": "npm@6.14.18"}`,
		"package-lock.json": `{"lockfileVersion": 3}`,
	})
	warnings := ResolutionWarnings(dir, sdk.PackageManagerNPM, LockfileFormat{File: "package-lock.json", Version: "3"})
	requireWarning(t, warnings, sdk.ResolutionWarningLockfileFormat, "requires npm >= 7")
}

func TestResolutionWarnings_YarnClassicLockfileWithBerryPin(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"package.json": `{"name": "app", "packageManager": "yarn@4.1.0"}`,
		"yarn.lock":    "# yarn lockfile v1\n",
	})
	warnings := ResolutionWarnings(dir, sdk.PackageManagerYarn, LockfileFormat{File: "yarn.lock", Version: "1"})
	requireWarning(t, warnings, sdk.ResolutionWarningLockfileFormat, "migrates the lockfile on install")
}

func TestResolutionWarnings_BerryLockfileWithClassicPin(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"package.json": `{"name": "app", "packageManager": "yarn@1.22.22"}`,
		"yarn.lock":    "__metadata:\n  version: 8\n",
	})
	warnings := ResolutionWarnings(dir, sdk.PackageManagerYarn, LockfileFormat{File: "yarn.lock", Version: "8"})
	requireWarning(t, warnings, sdk.ResolutionWarningLockfileFormat, "requires yarn >= 2")
}

func TestResolutionWarnings_PinnedManagerDisagreesWithCommittedLockfile(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"package.json":   `{"name": "app", "packageManager": "yarn@4.1.0"}`,
		"pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
	})
	warnings := ResolutionWarnings(dir, sdk.PackageManagerPNPM, LockfileFormat{File: "pnpm-lock.yaml", Version: "9.0"})
	requireWarning(t, warnings, sdk.ResolutionWarningPackageManager, `pins packageManager "yarn@4.1.0" but the project commits pnpm-lock.yaml`)
	// The format check is scoped to the pinned manager's own lockfile: a yarn
	// pin says nothing about which pnpm version wrote pnpm-lock.yaml.
	for _, warning := range warnings {
		if warning.Code == sdk.ResolutionWarningLockfileFormat {
			t.Fatalf("unexpected cross-manager format warning: %+v", warning)
		}
	}
}

func TestResolutionWarnings_NativeDetectorFindsLockfileOnDisk(t *testing.T) {
	// Native detectors parse no lockfile, so the mismatch is found by stat.
	dir := writeProject(t, map[string]string{
		"package.json":      `{"name": "app", "packageManager": "pnpm@10.4.1"}`,
		"package-lock.json": `{"lockfileVersion": 3}`,
	})
	warnings := ResolutionWarnings(dir, sdk.PackageManagerNPM, LockfileFormat{})
	requireWarning(t, warnings, sdk.ResolutionWarningPackageManager, "the project commits package-lock.json")
}

func TestResolutionWarnings_EnginesContradictsPin(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"package.json": `{"name": "app", "packageManager": "pnpm@9.15.0", "engines": {"pnpm": ">=10"}}`,
	})
	warnings := ResolutionWarnings(dir, sdk.PackageManagerPNPM, LockfileFormat{})
	requireWarning(t, warnings, sdk.ResolutionWarningEngines, `pins pnpm@9.15.0 but requires engines.pnpm ">=10"`)
}

func TestResolutionWarnings_EnginesSatisfiedByPin(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"package.json": `{"name": "app", "packageManager": "pnpm@10.4.1", "engines": {"pnpm": ">=10", "node": ">=22"}}`,
	})
	if warnings := ResolutionWarnings(dir, sdk.PackageManagerPNPM, LockfileFormat{}); warnings != nil {
		t.Fatalf("expected no warnings, got %+v", warnings)
	}
}

func TestResolutionWarnings_InstallGates(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"pnpm-workspace.yaml": "packages:\n  - packages/*\nminimumReleaseAge: 1440\n",
		".npmrc":              "minimum-release-age=4320\nbefore=2026-01-01\n",
	})
	warnings := ResolutionWarnings(dir, sdk.PackageManagerPNPM, LockfileFormat{})
	requireWarning(t, warnings, sdk.ResolutionWarningInstallGate, "minimumReleaseAge=1440 (24h)")
	requireWarning(t, warnings, sdk.ResolutionWarningInstallGate, "minimum-release-age=4320 (72h)")
	requireWarning(t, warnings, sdk.ResolutionWarningInstallGate, "before=2026-01-01")
	for _, warning := range warnings {
		if warning.Source != "pnpm" {
			t.Fatalf("expected pnpm-sourced gate warnings, got %+v", warning)
		}
	}
}

func TestResolutionWarnings_IgnoresDisabledOrAbsentGates(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"pnpm-workspace.yaml": "packages:\n  - packages/*\nminimumReleaseAge: 0\n",
		".npmrc":              "registry=https://registry.npmjs.org/\n# minimum-release-age=1440\n",
	})
	if warnings := ResolutionWarnings(dir, sdk.PackageManagerPNPM, LockfileFormat{}); warnings != nil {
		t.Fatalf("expected no warnings, got %+v", warnings)
	}
}

func TestResolutionWarnings_MalformedInputsAreSilent(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"package.json":        "{ not json",
		"pnpm-workspace.yaml": "\tminimumReleaseAge: ][",
		".npmrc":              "no-equals-sign\n",
	})
	if warnings := ResolutionWarnings(dir, sdk.PackageManagerPNPM, LockfileFormat{File: "pnpm-lock.yaml", Version: "9.0"}); warnings != nil {
		t.Fatalf("expected no warnings, got %+v", warnings)
	}
}

func TestResolutionWarnings_UnknownPinAndEmptyDirAreSilent(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"package.json":   `{"name": "app", "packageManager": "cargo@1.0.0"}`,
		"pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
	})
	if warnings := ResolutionWarnings(dir, sdk.PackageManagerPNPM, LockfileFormat{File: "pnpm-lock.yaml", Version: "9.0"}); warnings != nil {
		t.Fatalf("expected no warnings for an unrecognized pin, got %+v", warnings)
	}
	if warnings := ResolutionWarnings("  ", sdk.PackageManagerPNPM, LockfileFormat{}); warnings != nil {
		t.Fatalf("expected no warnings for an empty directory, got %+v", warnings)
	}
}

func TestResolutionWarnings_CollapsesNewlinesInScannedValues(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"package.json": `{"name": "app", "packageManager": "pnpm@9.15.0", "engines": {"pnpm": ">=10\n\nInjected: line"}}`,
	})
	warnings := ResolutionWarnings(dir, sdk.PackageManagerPNPM, LockfileFormat{})
	for _, warning := range warnings {
		if strings.Contains(warning.Message, "\n") {
			t.Fatalf("warning message must stay single-line: %q", warning.Message)
		}
	}
}

func TestAttachResolutionWarnings_LeavesManifestUntouchedWithoutWarnings(t *testing.T) {
	manifest := sdk.ManifestMetadata{Path: "pnpm-lock.yaml"}
	AttachResolutionWarnings(&manifest, nil)
	if manifest.Resolution != nil {
		t.Fatalf("expected resolution metadata to stay nil, got %+v", manifest.Resolution)
	}

	warning := sdk.ResolutionWarning{Code: sdk.ResolutionWarningInstallGate, Source: "pnpm", Message: "gate"}
	AttachResolutionWarnings(&manifest, []sdk.ResolutionWarning{warning})
	if manifest.Resolution == nil || len(manifest.Resolution.Warnings) != 1 {
		t.Fatalf("expected one attached warning, got %+v", manifest.Resolution)
	}
	// Attaching must not clobber metadata a detector already recorded.
	manifest.Resolution.Method = sdk.ResolutionMethodLockfile
	AttachResolutionWarnings(&manifest, []sdk.ResolutionWarning{warning})
	if manifest.Resolution.Method != sdk.ResolutionMethodLockfile || len(manifest.Resolution.Warnings) != 2 {
		t.Fatalf("unexpected resolution metadata: %+v", manifest.Resolution)
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
		min, max := managerRangeForFormat(tc.manager, tc.format)
		if min != tc.min || max != tc.max {
			t.Fatalf("managerRangeForFormat(%s, %d) = (%d, %d), want (%d, %d)", tc.manager, tc.format, min, max, tc.min, tc.max)
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

func TestFormatMinutes(t *testing.T) {
	cases := map[int]string{1440: "24h", 4320: "72h", 60: "1h", 30: "30m0s", 90: "1h30m0s"}
	for minutes, want := range cases {
		if got := formatMinutes(minutes); got != want {
			t.Fatalf("formatMinutes(%d) = %q, want %q", minutes, got, want)
		}
	}
}
