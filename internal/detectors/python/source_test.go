package python

import (
	"testing"

	"github.com/bomly-dev/bomly-sdk/model"
)

func TestPipInspectDependencySource(t *testing.T) {
	tests := []struct {
		name      string
		directURL map[string]any
		want      model.DependencySource
	}{
		{name: "registry", want: model.DependencySourceRegistry},
		{name: "git", directURL: map[string]any{"url": "https://github.com/example/pkg.git", "vcs_info": map[string]any{"vcs": "git"}}, want: model.DependencySourceGit},
		{name: "other source control", directURL: map[string]any{"url": "https://example.test/pkg", "vcs_info": map[string]any{"vcs": "hg"}}, want: model.DependencySourceURL},
		{name: "archive URL", directURL: map[string]any{"url": "https://example.test/pkg.whl", "archive_info": map[string]any{}}, want: model.DependencySourceURL},
		{name: "local directory", directURL: map[string]any{"url": "file:///workspace/pkg", "dir_info": map[string]any{}}, want: model.DependencySourceFile},
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
		want   model.DependencySource
	}{
		{name: "registry", source: uvLockSource{Registry: "https://pypi.org/simple"}, want: model.DependencySourceRegistry},
		{name: "git", source: uvLockSource{Git: "https://github.com/example/pkg"}, want: model.DependencySourceGit},
		{name: "URL", source: uvLockSource{URL: "https://example.test/pkg.whl"}, want: model.DependencySourceURL},
		{name: "editable", source: uvLockSource{Editable: "."}, want: model.DependencySourceFile},
		{name: "path", source: uvLockSource{Path: "../pkg"}, want: model.DependencySourceFile},
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
		want       model.DependencySource
	}{
		{sourceType: "", want: model.DependencySourceRegistry},
		{sourceType: "legacy", want: model.DependencySourceRegistry},
		{sourceType: "git", want: model.DependencySourceGit},
		{sourceType: "directory", want: model.DependencySourceFile},
		{sourceType: "url", want: model.DependencySourceURL},
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
		want model.DependencySource
	}{
		{name: "registry version", pkg: pipfileLockPackage{Version: "==1.0.0"}, want: model.DependencySourceRegistry},
		{name: "named index", pkg: pipfileLockPackage{Index: "private"}, want: model.DependencySourceRegistry},
		{name: "git", pkg: pipfileLockPackage{Git: "https://github.com/example/pkg"}, want: model.DependencySourceGit},
		{name: "path", pkg: pipfileLockPackage{Path: "../pkg"}, want: model.DependencySourceFile},
		{name: "file URL", pkg: pipfileLockPackage{File: "file:///workspace/pkg.whl"}, want: model.DependencySourceFile},
		{name: "local file", pkg: pipfileLockPackage{File: "./pkg.whl"}, want: model.DependencySourceFile},
		{name: "archive URL", pkg: pipfileLockPackage{File: "https://example.test/pkg.whl"}, want: model.DependencySourceURL},
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
