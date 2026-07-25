package ciready

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

// stubVersions builds a ToolVersionFunc backed by a fixed binary -> version map.
func stubVersions(versions map[string]string) ToolVersionFunc {
	return func(_ context.Context, binary string) (string, bool) {
		version, ok := versions[binary]
		return version, ok
	}
}

func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", path, err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
}

func nodeSubproject(dir, relativePath string, manager sdk.PackageManager) sdk.Subproject {
	return sdk.Subproject{
		ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: dir},
		RelativePath:            relativePath,
		DetectedPackageManagers: []sdk.PackageManager{manager},
		Ecosystem:               sdk.EcosystemNPM,
	}
}

func inspect(t *testing.T, files map[string]string, versions map[string]string) []Diagnostic {
	t.Helper()
	dir := t.TempDir()
	writeFiles(t, dir, files)
	inspector := Inspector{ToolVersion: stubVersions(versions)}
	return inspector.Inspect(context.Background(), []sdk.Subproject{nodeSubproject(dir, ".", sdk.PackageManagerPNPM)})
}

func requireMessage(t *testing.T, diagnostics []Diagnostic, source, substring string) {
	t.Helper()
	for _, diagnostic := range diagnostics {
		if diagnostic.Source == source && strings.Contains(diagnostic.Message, substring) {
			return
		}
	}
	t.Fatalf("no %s diagnostic containing %q in %v", source, substring, diagnostics)
}

func requireNoMessage(t *testing.T, diagnostics []Diagnostic, substring string) {
	t.Helper()
	for _, diagnostic := range diagnostics {
		if strings.Contains(diagnostic.Message, substring) {
			t.Fatalf("unexpected diagnostic containing %q: %s", substring, diagnostic.Message)
		}
	}
}

func TestInspect_LockfileFormatNewerThanManagerOnPath(t *testing.T) {
	diagnostics := inspect(t,
		map[string]string{"pnpm-lock.yaml": "lockfileVersion: '9.0'\n"},
		map[string]string{"pnpm": "8.15.4"},
	)
	requireMessage(t, diagnostics, "pnpm", "requires pnpm >= 9")
}

func TestInspect_LockfileFormatMigratedByNewerManager(t *testing.T) {
	diagnostics := inspect(t,
		map[string]string{"pnpm-lock.yaml": "lockfileVersion: '6.0'\n"},
		map[string]string{"pnpm": "10.4.1"},
	)
	requireMessage(t, diagnostics, "pnpm", "frozen-lockfile CI step fails")
}

func TestInspect_CurrentLockfileFormatIsQuiet(t *testing.T) {
	// pnpm 10 still writes lockfileVersion 9.0: same format, no hint.
	diagnostics := inspect(t,
		map[string]string{"pnpm-lock.yaml": "lockfileVersion: '9.0'\n"},
		map[string]string{"pnpm": "10.4.1"},
	)
	if len(diagnostics) != 0 {
		t.Fatalf("expected no diagnostics, got %v", diagnostics)
	}
}

func TestInspect_NpmLockfileVersionRequiresNpm7(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"package-lock.json": `{"lockfileVersion": 3}`})
	inspector := Inspector{ToolVersion: stubVersions(map[string]string{"npm": "6.14.18"})}
	diagnostics := inspector.Inspect(context.Background(), []sdk.Subproject{nodeSubproject(dir, ".", sdk.PackageManagerNPM)})
	requireMessage(t, diagnostics, "npm", "requires npm >= 7")
}

func TestInspect_YarnClassicLockfileWithBerryOnPath(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"yarn.lock": "# yarn lockfile v1\n\nleft-pad@^1.0.0:\n  version \"1.3.0\"\n"})
	inspector := Inspector{ToolVersion: stubVersions(map[string]string{"yarn": "4.1.0"})}
	diagnostics := inspector.Inspect(context.Background(), []sdk.Subproject{nodeSubproject(dir, ".", sdk.PackageManagerYarn)})
	requireMessage(t, diagnostics, "yarn", "migrates the lockfile on install")
}

func TestInspect_YarnBerryLockfileWithClassicOnPath(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"yarn.lock": "__metadata:\n  version: 8\n  cacheKey: 10\n"})
	inspector := Inspector{ToolVersion: stubVersions(map[string]string{"yarn": "1.22.22"})}
	diagnostics := inspector.Inspect(context.Background(), []sdk.Subproject{nodeSubproject(dir, ".", sdk.PackageManagerYarn)})
	requireMessage(t, diagnostics, "yarn", "requires yarn >= 2")
}

func TestInspect_PackageManagerPinMajorMismatch(t *testing.T) {
	diagnostics := inspect(t,
		map[string]string{
			"package.json":   `{"name": "app", "packageManager": "pnpm@11.0.0+sha512.abc"}`,
			"pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
		},
		map[string]string{"pnpm": "9.15.0"},
	)
	requireMessage(t, diagnostics, "pnpm", "pins pnpm@11.0.0 but pnpm 9.15.0 is on PATH")
}

func TestInspect_PackageManagerPinMatchesPathVersion(t *testing.T) {
	diagnostics := inspect(t,
		map[string]string{
			"package.json":   `{"name": "app", "packageManager": "pnpm@9.15.0"}`,
			"pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
		},
		map[string]string{"pnpm": "9.15.4"},
	)
	if len(diagnostics) != 0 {
		t.Fatalf("expected no diagnostics, got %v", diagnostics)
	}
}

func TestInspect_PackageManagerPinDisagreesWithLockfile(t *testing.T) {
	diagnostics := inspect(t,
		map[string]string{
			"package.json":   `{"name": "app", "packageManager": "yarn@4.1.0"}`,
			"pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
		},
		map[string]string{"yarn": "4.1.0", "pnpm": "9.15.0"},
	)
	requireMessage(t, diagnostics, "yarn", "the directory holds pnpm-lock.yaml")
}

func TestInspect_EnginesConstraintUnsatisfied(t *testing.T) {
	diagnostics := inspect(t,
		map[string]string{"package.json": `{"name": "app", "engines": {"node": ">=22", "pnpm": ">=10"}}`},
		map[string]string{"node": "v20.11.1", "pnpm": "10.4.1"},
	)
	requireMessage(t, diagnostics, "node", `requires engines.node ">=22" but node v20.11.1 is on PATH`)
	requireNoMessage(t, diagnostics, "engines.pnpm")
}

func TestInspect_EnginesIgnoredWhenToolAbsent(t *testing.T) {
	diagnostics := inspect(t,
		map[string]string{"package.json": `{"name": "app", "engines": {"node": ">=22"}}`},
		map[string]string{},
	)
	if len(diagnostics) != 0 {
		t.Fatalf("expected no diagnostics, got %v", diagnostics)
	}
}

func TestInspect_PnpmWorkspaceMinimumReleaseAgeGate(t *testing.T) {
	diagnostics := inspect(t,
		map[string]string{"pnpm-workspace.yaml": "packages:\n  - packages/*\nminimumReleaseAge: 1440\n"},
		map[string]string{"pnpm": "10.16.0"},
	)
	requireMessage(t, diagnostics, "pnpm", "minimumReleaseAge=1440 (24h)")
	requireMessage(t, diagnostics, "pnpm", "freshly published fix version fails CI")
}

func TestInspect_NpmrcInstallGates(t *testing.T) {
	diagnostics := inspect(t,
		map[string]string{".npmrc": "minimum-release-age=4320\nbefore=2026-01-01\n"},
		map[string]string{"pnpm": "10.16.0"},
	)
	requireMessage(t, diagnostics, "pnpm", "minimum-release-age=4320 (72h)")
	requireMessage(t, diagnostics, "npm", "before=2026-01-01")
}

func TestInspect_LabelsSubprojectPath(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"pnpm-lock.yaml": "lockfileVersion: '9.0'\n"})
	inspector := Inspector{ToolVersion: stubVersions(map[string]string{"pnpm": "8.15.4"})}
	diagnostics := inspector.Inspect(context.Background(), []sdk.Subproject{nodeSubproject(dir, "apps/web", sdk.PackageManagerPNPM)})
	requireMessage(t, diagnostics, "pnpm", "subproject apps/web: ")
}

func TestInspect_DeduplicatesRepeatedHints(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"pnpm-lock.yaml": "lockfileVersion: '9.0'\n"})
	inspector := Inspector{ToolVersion: stubVersions(map[string]string{"pnpm": "8.15.4"})}
	subprojects := []sdk.Subproject{
		nodeSubproject(dir, ".", sdk.PackageManagerPNPM),
		nodeSubproject(dir, ".", sdk.PackageManagerPNPM),
	}
	diagnostics := inspector.Inspect(context.Background(), subprojects)
	if len(diagnostics) != 1 {
		t.Fatalf("expected 1 deduplicated diagnostic, got %v", diagnostics)
	}
}

func TestInspect_SkipsNonNodeAndContainerTargets(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"pnpm-lock.yaml": "lockfileVersion: '9.0'\n"})
	inspector := Inspector{ToolVersion: stubVersions(map[string]string{"pnpm": "8.15.4"})}
	subprojects := []sdk.Subproject{
		{
			ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: dir},
			DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerGoMod},
		},
		{
			ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetContainerImage, Location: dir},
			DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerPNPM},
		},
		{
			ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: filepath.Join(dir, "missing")},
			DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerPNPM},
		},
	}
	if diagnostics := inspector.Inspect(context.Background(), subprojects); len(diagnostics) != 0 {
		t.Fatalf("expected no diagnostics, got %v", diagnostics)
	}
}

func TestInspect_FileTargetUsesParentDirectory(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"pnpm-lock.yaml": "lockfileVersion: '9.0'\n"})
	inspector := Inspector{ToolVersion: stubVersions(map[string]string{"pnpm": "8.15.4"})}
	subproject := sdk.Subproject{
		ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: filepath.Join(dir, "pnpm-lock.yaml")},
		DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerPNPM},
	}
	diagnostics := inspector.Inspect(context.Background(), []sdk.Subproject{subproject})
	requireMessage(t, diagnostics, "pnpm", "requires pnpm >= 9")
}

func TestInspect_ProbesEachBinaryOnce(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"pnpm-lock.yaml": "lockfileVersion: '9.0'\n"})
	probes := 0
	inspector := Inspector{ToolVersion: func(context.Context, string) (string, bool) {
		probes++
		return "8.15.4", true
	}}
	subprojects := []sdk.Subproject{
		nodeSubproject(dir, "a", sdk.PackageManagerPNPM),
		nodeSubproject(dir, "b", sdk.PackageManagerPNPM),
	}
	inspector.Inspect(context.Background(), subprojects)
	if probes != 1 {
		t.Fatalf("probes = %d, want 1", probes)
	}
}

func TestInspect_MalformedInputsAreSilent(t *testing.T) {
	diagnostics := inspect(t,
		map[string]string{
			"package.json":   "{ not json",
			"pnpm-lock.yaml": "\tlockfileVersion: ][",
			".npmrc":         "no-equals-sign\n",
		},
		map[string]string{"pnpm": "8.15.4"},
	)
	if len(diagnostics) != 0 {
		t.Fatalf("expected no diagnostics, got %v", diagnostics)
	}
}

func TestCommandVersion_MissingBinary(t *testing.T) {
	if _, ok := commandVersion(context.Background(), "bomly-not-a-real-binary"); ok {
		t.Fatal("expected missing binary to report not found")
	}
}

func TestParseVersionOutput(t *testing.T) {
	cases := []struct {
		out     string
		want    string
		wantOK  bool
		comment string
	}{
		{out: "10.4.1\n", want: "10.4.1", wantOK: true},
		{out: "v22.3.0\n", want: "22.3.0", wantOK: true},
		{out: "yarn install v1.22.22\n", want: "1.22.22", wantOK: true},
		{out: "\n", wantOK: false},
		{out: "command not found", wantOK: false},
	}
	for _, tc := range cases {
		got, ok := parseVersionOutput(tc.out)
		if ok != tc.wantOK || got != tc.want {
			t.Fatalf("parseVersionOutput(%q) = (%q, %v), want (%q, %v)", tc.out, got, ok, tc.want, tc.wantOK)
		}
	}
}

func TestMajorVersion(t *testing.T) {
	cases := []struct {
		value  string
		want   int
		wantOK bool
	}{
		{value: "10.4.1", want: 10, wantOK: true},
		{value: "9.0", want: 9, wantOK: true},
		{value: "v22.3.0", want: 22, wantOK: true},
		{value: "3", want: 3, wantOK: true},
		{value: "10.0.0-rc.1", want: 10, wantOK: true},
		{value: "", wantOK: false},
		{value: "berry", wantOK: false},
	}
	for _, tc := range cases {
		got, ok := majorVersion(tc.value)
		if ok != tc.wantOK || got != tc.want {
			t.Fatalf("majorVersion(%q) = (%d, %v), want (%d, %v)", tc.value, got, ok, tc.want, tc.wantOK)
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
		t.Fatalf("expected unknown manager for empty pin, got %q", manager)
	}
}
