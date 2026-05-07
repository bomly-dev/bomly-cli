package cli

import (
	"bytes"
	stdctx "context"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/cli/opts"
)

func TestModuleVersion(t *testing.T) {
	info := &debug.BuildInfo{Deps: []*debug.Module{
		{Path: "example.com/one", Version: "v1.2.3"},
		{Path: "example.com/two", Version: "v2.0.0", Replace: &debug.Module{Path: "example.com/two", Version: "v2.1.0"}},
	}}

	if got := moduleVersion(nil, "example.com/one"); got != "" {
		t.Fatalf("moduleVersion(nil, ...) = %q, want empty", got)
	}
	if got := moduleVersion(info, ""); got != "" {
		t.Fatalf("moduleVersion(..., empty) = %q, want empty", got)
	}
	if got := moduleVersion(info, "example.com/one"); got != "v1.2.3" {
		t.Fatalf("moduleVersion(one) = %q, want %q", got, "v1.2.3")
	}
	if got := moduleVersion(info, "example.com/two"); got != "v2.1.0" {
		t.Fatalf("moduleVersion(two) = %q, want %q", got, "v2.1.0")
	}
	if got := moduleVersion(info, "example.com/missing"); got != "" {
		t.Fatalf("moduleVersion(missing) = %q, want empty", got)
	}
}

func TestSelectedDependencyVersionsReturnsResolvedTrackedModules(t *testing.T) {
	modulePath, moduleVersion, ok := anyVersionedDependency()
	if !ok {
		t.Skip("no versioned module found in build info")
	}

	withTrackedDependencyVersions(t, []dependencyVersion{
		{Label: "Known", Module: modulePath},
		{Label: "Missing", Module: "example.com/missing"},
	})

	got := selectedDependencyVersions()
	if len(got) != 1 {
		t.Fatalf("selectedDependencyVersions() len = %d, want 1", len(got))
	}
	if got[0].Label != "Known" {
		t.Fatalf("selectedDependencyVersions()[0].Label = %q, want %q", got[0].Label, "Known")
	}
	if got[0].Module != modulePath {
		t.Fatalf("selectedDependencyVersions()[0].Module = %q, want %q", got[0].Module, modulePath)
	}
	if got[0].Version != moduleVersion {
		t.Fatalf("selectedDependencyVersions()[0].Version = %q, want %q", got[0].Version, moduleVersion)
	}
}

func TestRenderVersionDetailsNoResolvedDependencies(t *testing.T) {
	withTrackedDependencyVersions(t, []dependencyVersion{{Label: "Missing", Module: "example.com/missing"}})

	got := renderVersionDetails("v1.2.3")
	want := "bomly v1.2.3\n\nBuilt-in third-party plugins:"
	if got != want {
		t.Fatalf("renderVersionDetails() mismatch\nwant:\n%s\n\ngot:\n%s", want, got)
	}
}

func TestRenderVersionDetailsIncludesResolvedDependency(t *testing.T) {
	modulePath, moduleVersion, ok := anyVersionedDependency()
	if !ok {
		t.Skip("no versioned module found in build info")
	}

	withTrackedDependencyVersions(t, []dependencyVersion{{Label: "Known", Module: modulePath}})

	got := renderVersionDetails("v1.2.3")
	if !strings.Contains(got, "bomly v1.2.3") {
		t.Fatalf("renderVersionDetails() missing core version line, got:\n%s", got)
	}
	wantLine := "Known (" + modulePath + "): " + moduleVersion
	if !strings.Contains(got, wantLine) {
		t.Fatalf("renderVersionDetails() missing dependency line %q, got:\n%s", wantLine, got)
	}
}

func TestNewVersionCmdExecute(t *testing.T) {
	cmd := newVersionCmd("v9.9.9")
	cmd.SetContext(opts.ToContext(stdctx.Background(), &opts.Options{}))
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !strings.Contains(stdout.String(), "bomly v9.9.9") {
		t.Fatalf("expected version output on stdout, got %q", stdout.String())
	}
}

func TestNewVersionCmdRejectsArgs(t *testing.T) {
	cmd := newVersionCmd("v9.9.9")
	cmd.SetContext(opts.ToContext(stdctx.Background(), &opts.Options{}))
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"extra"})

	if err := cmd.Execute(); err == nil {
		t.Fatalf("Execute() with args expected error")
	}
}

func TestRootVersion_IncludesTrackedDependencyVersions(t *testing.T) {
	root, err := newRootCmd("0.9.0-test")
	if err != nil {
		t.Fatalf("newRootCmd() error = %v", err)
	}

	var output strings.Builder
	root.SetOut(&output)
	root.SetErr(&output)
	root.SetArgs([]string{"version"})

	if err := root.Execute(); err != nil {
		t.Fatalf("root.Execute() error = %v", err)
	}

	versionText := output.String()
	if !strings.Contains(versionText, "bomly 0.9.0-test") {
		t.Fatalf("expected version output to contain core version, got:\n%s", versionText)
	}
	for _, item := range selectedDependencyVersions() {
		want := item.Label + ":"
		if !strings.Contains(versionText, want) {
			t.Fatalf("expected version output to contain %q, got:\n%s", want, versionText)
		}
	}
}

func withTrackedDependencyVersions(t *testing.T, tracked []dependencyVersion) {
	t.Helper()
	original := trackedDependencyVersions
	trackedDependencyVersions = tracked
	t.Cleanup(func() {
		trackedDependencyVersions = original
	})
}

func anyVersionedDependency() (path string, version string, ok bool) {
	info, ok := debug.ReadBuildInfo()
	if !ok || info == nil {
		return "", "", false
	}

	for _, dep := range info.Deps {
		if dep == nil || dep.Path == "" {
			continue
		}
		if dep.Replace != nil && dep.Replace.Version != "" {
			return dep.Path, dep.Replace.Version, true
		}
		if dep.Version != "" {
			return dep.Path, dep.Version, true
		}
	}

	return "", "", false
}
