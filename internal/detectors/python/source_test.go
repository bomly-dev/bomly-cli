package python

import (
	"testing"

	"github.com/bomly-dev/bomly-sdk"
)

func TestPipInspectDependencySource(t *testing.T) {
	tests := []struct {
		name      string
		directURL map[string]any
		want      sdk.DependencySource
	}{
		{name: "registry", want: sdk.DependencySourceRegistry},
		{name: "git", directURL: map[string]any{"url": "https://github.com/example/pkg.git", "vcs_info": map[string]any{"vcs": "git"}}, want: sdk.DependencySourceGit},
		{name: "other source control", directURL: map[string]any{"url": "https://example.test/pkg", "vcs_info": map[string]any{"vcs": "hg"}}, want: sdk.DependencySourceURL},
		{name: "archive URL", directURL: map[string]any{"url": "https://example.test/pkg.whl", "archive_info": map[string]any{}}, want: sdk.DependencySourceURL},
		{name: "local directory", directURL: map[string]any{"url": "file:///workspace/pkg", "dir_info": map[string]any{}}, want: sdk.DependencySourceFile},
		{name: "missing evidence", directURL: map[string]any{"archive_info": map[string]any{}}, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pipInspectDependencySource(tt.directURL); got != tt.want {
				t.Fatalf("pipInspectDependencySource() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPipInspectRevision(t *testing.T) {
	directURL := map[string]any{
		"vcs_info": map[string]any{
			"requested_revision": "main",
			"commit_id":          "abc123",
		},
	}
	if got := pipInspectRevision(directURL); got != "abc123" {
		t.Fatalf("pipInspectRevision() = %q, want abc123", got)
	}
}

func TestUVDependencySource(t *testing.T) {
	tests := []struct {
		name   string
		source uvLockSource
		want   sdk.DependencySource
	}{
		{name: "registry", source: uvLockSource{Registry: "https://pypi.org/simple"}, want: sdk.DependencySourceRegistry},
		{name: "git", source: uvLockSource{Git: "https://github.com/example/pkg"}, want: sdk.DependencySourceGit},
		{name: "URL", source: uvLockSource{URL: "https://example.test/pkg.whl"}, want: sdk.DependencySourceURL},
		{name: "editable", source: uvLockSource{Editable: "."}, want: sdk.DependencySourceFile},
		{name: "path", source: uvLockSource{Path: "../pkg"}, want: sdk.DependencySourceFile},
		{name: "missing evidence", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := uvDependencySource(tt.source); got != tt.want {
				t.Fatalf("uvDependencySource() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestUVSourceRevisionPrefersImmutableReference(t *testing.T) {
	source := uvLockSource{Git: "https://github.com/example/pkg?rev=main#abc123"}
	if got := uvSourceRevision(source); got != "abc123" {
		t.Fatalf("uvSourceRevision() = %q, want abc123", got)
	}
}

func TestUVSourceRevisionFallsBackToRequestedReference(t *testing.T) {
	source := uvLockSource{Git: "https://github.com/example/pkg?rev=main"}
	if got := uvSourceRevision(source); got != "main" {
		t.Fatalf("uvSourceRevision() = %q, want main", got)
	}
}

func TestPoetryDependencySource(t *testing.T) {
	tests := []struct {
		sourceType string
		want       sdk.DependencySource
	}{
		{sourceType: "", want: sdk.DependencySourceRegistry},
		{sourceType: "legacy", want: sdk.DependencySourceRegistry},
		{sourceType: "git", want: sdk.DependencySourceGit},
		{sourceType: "directory", want: sdk.DependencySourceFile},
		{sourceType: "url", want: sdk.DependencySourceURL},
		{sourceType: "custom", want: ""},
	}
	for _, tt := range tests {
		if got := poetryDependencySource(tt.sourceType); got != tt.want {
			t.Errorf("poetryDependencySource(%q) = %q, want %q", tt.sourceType, got, tt.want)
		}
	}
}

func TestPipfileDependencySource(t *testing.T) {
	tests := []struct {
		name string
		pkg  pipfileLockPackage
		want sdk.DependencySource
	}{
		{name: "registry version", pkg: pipfileLockPackage{Version: "==1.0.0"}, want: sdk.DependencySourceRegistry},
		{name: "named index", pkg: pipfileLockPackage{Index: "private"}, want: sdk.DependencySourceRegistry},
		{name: "git", pkg: pipfileLockPackage{Git: "https://github.com/example/pkg"}, want: sdk.DependencySourceGit},
		{name: "path", pkg: pipfileLockPackage{Path: "../pkg"}, want: sdk.DependencySourceFile},
		{name: "file URL", pkg: pipfileLockPackage{File: "file:///workspace/pkg.whl"}, want: sdk.DependencySourceFile},
		{name: "local file", pkg: pipfileLockPackage{File: "./pkg.whl"}, want: sdk.DependencySourceFile},
		{name: "archive URL", pkg: pipfileLockPackage{File: "https://example.test/pkg.whl"}, want: sdk.DependencySourceURL},
		{name: "missing evidence", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pipfileDependencySource(tt.pkg); got != tt.want {
				t.Fatalf("pipfileDependencySource() = %q, want %q", got, tt.want)
			}
		})
	}
}
