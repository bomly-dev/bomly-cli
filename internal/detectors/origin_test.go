package detectors_test

import (
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-sdk"
)

func TestSetOriginArtifact(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{name: "registry tarball", raw: "https://registry.npmjs.org/react/-/react-18.2.0.tgz", want: "https://registry.npmjs.org/react/-/react-18.2.0.tgz"},
		{name: "yarn digest fragment is stripped", raw: "https://registry.npmjs.org/react/-/react-18.2.0.tgz#ceeba773e3e9d2b6f1a2b6b9f4f1cb2f9c2e1a55", want: "https://registry.npmjs.org/react/-/react-18.2.0.tgz"},
		{name: "codeload tarball", raw: "https://codeload.github.com/owner/repo/tar.gz/9f8e7d6c5b4a3928176554433221100ffeeddcc", want: "https://codeload.github.com/owner/repo/tar.gz/9f8e7d6c5b4a3928176554433221100ffeeddcc"},
		{name: "uppercase scheme is normalized", raw: "HTTPS://files.pythonhosted.org/packages/x/django-5.0.tar.gz", want: "https://files.pythonhosted.org/packages/x/django-5.0.tar.gz"},
		{name: "signed link carrying a query is dropped", raw: "https://nexus.corp/repo/pkg.tgz?token=abc123", want: ""},
		{name: "userinfo is dropped", raw: "https://user:s3cret@nexus.corp/repo/pkg.tgz", want: ""},
		{name: "npm link directory is dropped", raw: "packages/lib", want: ""},
		{name: "absolute local path is dropped", raw: "/Users/someone/src/project", want: ""},
		{name: "file url is dropped", raw: "file:///home/someone/wheels/pkg.whl", want: ""},
		{name: "git+ssh is dropped", raw: "git+ssh://git@github.com/owner/repo.git#9f8e7d6", want: ""},
		{name: "scp-style remote is dropped", raw: "git@github.com:owner/repo.git", want: ""},
		{name: "git+https prefix is not a plain URL", raw: "git+https://github.com/owner/repo.git", want: ""},
		{name: "non-web scheme is dropped", raw: "ftp://files.example.com/pkg.tgz", want: ""},
		{name: "windows path is dropped", raw: `C:\src\project`, want: ""},
		{name: "malformed host is dropped", raw: "https://:8080/pkg.tgz", want: ""},
		{name: "scheme without host is dropped", raw: "https://", want: ""},
		{name: "registry root names no artifact", raw: "https://registry.example.test/", want: ""},
		{name: "empty is dropped", raw: "   ", want: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dep := &sdk.Dependency{ID: "pkg"}
			detectors.SetOriginArtifact(dep, tc.raw)

			origin := detectors.OriginFrom(dep.Metadata)
			if origin.ArtifactURL != tc.want {
				t.Fatalf("artifact URL = %q, want %q", origin.ArtifactURL, tc.want)
			}
			if origin.VCSURL != "" || origin.VCSRevision != "" {
				t.Fatalf("artifact origin leaked repository data: %+v", origin)
			}
			if tc.want == "" && len(dep.Metadata) != 0 {
				t.Fatalf("rejected value still recorded metadata: %v", dep.Metadata)
			}
		})
	}
}

func TestSetOriginVCS(t *testing.T) {
	cases := []struct {
		name         string
		raw          string
		revision     string
		wantURL      string
		wantRevision string
	}{
		{
			name:         "repository with resolved commit",
			raw:          "https://github.com/owner/repo.git",
			revision:     "9f8e7d6c5b4a3928176554433221100ffeeddcc0",
			wantURL:      "https://github.com/owner/repo.git",
			wantRevision: "9f8e7d6c5b4a3928176554433221100ffeeddcc0",
		},
		{
			name:         "requested ref in query and fragment is dropped for the resolved one",
			raw:          "https://github.com/example/helper?rev=main#abc123",
			revision:     "0a1b2c3d4e5f60718293a4b5c6d7e8f901234567",
			wantURL:      "https://github.com/example/helper",
			wantRevision: "0a1b2c3d4e5f60718293a4b5c6d7e8f901234567",
		},
		{name: "tag pin", raw: "https://github.com/owner/repo", revision: "v1.2.3", wantURL: "https://github.com/owner/repo", wantRevision: "v1.2.3"},
		{name: "branch-style ref", raw: "https://github.com/owner/repo", revision: "release/2026-08", wantURL: "https://github.com/owner/repo", wantRevision: "release/2026-08"},
		{name: "unpinned repository", raw: "https://github.com/owner/repo", revision: "", wantURL: "https://github.com/owner/repo"},
		{name: "revision breaking the SPDX locator keeps the repository", raw: "https://github.com/owner/repo", revision: "feature@login", wantURL: "https://github.com/owner/repo"},
		{name: "whitespace revision keeps the repository", raw: "https://github.com/owner/repo", revision: "not a revision", wantURL: "https://github.com/owner/repo"},
		{name: "overlong revision keeps the repository", raw: "https://github.com/owner/repo", revision: strings.Repeat("a", 129), wantURL: "https://github.com/owner/repo"},
		{name: "bare host names no repository", raw: "https://github.com", revision: "9f8e7d6", wantURL: ""},
		{name: "index root names no repository", raw: "https://index.crates.io/", revision: "9f8e7d6", wantURL: ""},
		{name: "root path names no repository", raw: "https://github.com/", revision: "9f8e7d6", wantURL: ""},
		{name: "userinfo is dropped", raw: "https://oauth2:glpat-xxxxxxxxxxxxxxxxxxxx@gitlab.corp/team/repo.git", revision: "9f8e7d6", wantURL: ""},
		{name: "local checkout is dropped", raw: "/Users/someone/src/repo", revision: "9f8e7d6", wantURL: ""},
		{name: "ssh remote is dropped", raw: "ssh://git@github.com/owner/repo.git", revision: "9f8e7d6", wantURL: ""},
		{name: "ssh remote without userinfo is dropped", raw: "ssh://github.com/owner/repo.git", revision: "9f8e7d6", wantURL: ""},
		{name: "git+https prefix must be stripped by the detector", raw: "git+https://github.com/owner/repo.git", revision: "9f8e7d6", wantURL: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dep := &sdk.Dependency{ID: "pkg"}
			detectors.SetOriginVCS(dep, tc.raw, tc.revision)

			origin := detectors.OriginFrom(dep.Metadata)
			if origin.VCSURL != tc.wantURL {
				t.Fatalf("VCS URL = %q, want %q", origin.VCSURL, tc.wantURL)
			}
			if origin.VCSRevision != tc.wantRevision {
				t.Fatalf("VCS revision = %q, want %q", origin.VCSRevision, tc.wantRevision)
			}
			if origin.ArtifactURL != "" {
				t.Fatalf("repository origin leaked an artifact URL: %q", origin.ArtifactURL)
			}
			if tc.wantURL == "" && len(dep.Metadata) != 0 {
				t.Fatalf("rejected value still recorded metadata: %v", dep.Metadata)
			}
		})
	}
}

// A package has one origin. A later assertion replaces an earlier one rather
// than merging with it, so metadata never names two locations or pairs a
// repository with a revision that belongs to a different one.
func TestSetOriginReplacesRatherThanMerges(t *testing.T) {
	const (
		artifact   = "https://registry.npmjs.org/react/-/react-18.2.0.tgz"
		repository = "https://github.com/facebook/react"
		fork       = "https://github.com/facebook/react-fork"
		revision   = "c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8"
	)

	t.Run("repository replaces artifact", func(t *testing.T) {
		dep := &sdk.Dependency{ID: "pkg"}
		detectors.SetOriginArtifact(dep, artifact)
		detectors.SetOriginVCS(dep, repository, revision)

		want := detectors.Origin{VCSURL: repository, VCSRevision: revision}
		if got := detectors.OriginFrom(dep.Metadata); got != want {
			t.Fatalf("origin = %+v, want %+v", got, want)
		}
	})

	t.Run("artifact replaces repository", func(t *testing.T) {
		dep := &sdk.Dependency{ID: "pkg"}
		detectors.SetOriginVCS(dep, repository, revision)
		detectors.SetOriginArtifact(dep, artifact)

		want := detectors.Origin{ArtifactURL: artifact}
		if got := detectors.OriginFrom(dep.Metadata); got != want {
			t.Fatalf("origin = %+v, want %+v", got, want)
		}
	})

	t.Run("an unpinned repository drops the earlier revision", func(t *testing.T) {
		dep := &sdk.Dependency{ID: "pkg"}
		detectors.SetOriginVCS(dep, repository, revision)
		detectors.SetOriginVCS(dep, fork, "")

		want := detectors.Origin{VCSURL: fork}
		if got := detectors.OriginFrom(dep.Metadata); got != want {
			t.Fatalf("origin = %+v, want %+v; a revision must not follow a repository it did not come from", got, want)
		}
	})

	t.Run("a rejected value leaves the earlier origin intact", func(t *testing.T) {
		dep := &sdk.Dependency{ID: "pkg"}
		detectors.SetOriginArtifact(dep, artifact)
		detectors.SetOriginVCS(dep, "/Users/someone/src/react", revision)

		want := detectors.Origin{ArtifactURL: artifact}
		if got := detectors.OriginFrom(dep.Metadata); got != want {
			t.Fatalf("origin = %+v, want %+v", got, want)
		}
	})
}

func TestSetOriginAllocatesMetadataAndPreservesOtherKeys(t *testing.T) {
	dep := &sdk.Dependency{ID: "pkg"}
	detectors.SetOriginArtifact(dep, "https://registry.npmjs.org/react/-/react-18.2.0.tgz")
	if dep.Metadata == nil {
		t.Fatal("metadata map was not allocated")
	}

	dep.Metadata["unrelated"] = "keep me"
	detectors.SetOriginArtifact(dep, "https://registry.npmjs.org/react/-/react-18.3.0.tgz")
	if got := dep.Metadata["unrelated"]; got != "keep me" {
		t.Fatalf("unrelated metadata = %v, want %q", got, "keep me")
	}
	if got := detectors.OriginFrom(dep.Metadata).ArtifactURL; got != "https://registry.npmjs.org/react/-/react-18.3.0.tgz" {
		t.Fatalf("artifact URL = %q, want the most recent value", got)
	}
}

func TestSetOriginNilDependency(t *testing.T) {
	// Must not panic: detectors call these on nodes that may not exist.
	detectors.SetOriginArtifact(nil, "https://registry.npmjs.org/react/-/react-18.2.0.tgz")
	detectors.SetOriginVCS(nil, "https://github.com/owner/repo", "9f8e7d6")
}

func TestOriginFromRevalidatesHandBuiltMetadata(t *testing.T) {
	cases := []struct {
		name     string
		metadata map[string]any
		want     detectors.Origin
	}{
		{name: "nil metadata", metadata: nil},
		{name: "unrelated keys only", metadata: map[string]any{"npm": struct{}{}}},
		{
			name:     "credentialed artifact is dropped",
			metadata: map[string]any{detectors.MetadataKeyOriginArtifactURL: "https://user:s3cret@nexus.corp/pkg.tgz"},
		},
		{
			name:     "local path is dropped",
			metadata: map[string]any{detectors.MetadataKeyOriginVCSURL: "file:///home/someone/repo"},
		},
		{
			name:     "non-string value is dropped",
			metadata: map[string]any{detectors.MetadataKeyOriginArtifactURL: 42},
		},
		{
			name:     "revision without a repository is dropped",
			metadata: map[string]any{detectors.MetadataKeyOriginVCSRevision: "9f8e7d6"},
		},
		{
			name: "artifact wins over repository",
			metadata: map[string]any{
				detectors.MetadataKeyOriginArtifactURL: "https://registry.npmjs.org/react/-/react-18.2.0.tgz",
				detectors.MetadataKeyOriginVCSURL:      "https://github.com/facebook/react",
			},
			want: detectors.Origin{ArtifactURL: "https://registry.npmjs.org/react/-/react-18.2.0.tgz"},
		},
		{
			name: "query and fragment are stripped from a hand-built repository",
			metadata: map[string]any{
				detectors.MetadataKeyOriginVCSURL:      "https://github.com/owner/repo?rev=main#abc",
				detectors.MetadataKeyOriginVCSRevision: "9f8e7d6",
			},
			want: detectors.Origin{VCSURL: "https://github.com/owner/repo", VCSRevision: "9f8e7d6"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := detectors.OriginFrom(tc.metadata); got != tc.want {
				t.Fatalf("OriginFrom() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestOriginEmpty(t *testing.T) {
	if !(detectors.Origin{}).Empty() {
		t.Fatal("zero Origin should be empty")
	}
	if (detectors.Origin{ArtifactURL: "https://example.com/pkg.tgz"}).Empty() {
		t.Fatal("artifact origin should not be empty")
	}
	if (detectors.Origin{VCSURL: "https://example.com/repo"}).Empty() {
		t.Fatal("repository origin should not be empty")
	}
}

// One package can appear at several places in a dependency tree. Its
// occurrences must agree before an origin is published.
func TestMergeOrigin(t *testing.T) {
	const (
		artifact = "https://registry.npmjs.org/react/-/react-18.2.0.tgz"
		mirror   = "https://npm.corp/mirror/react/-/react-18.2.0.tgz"
		repo     = "https://github.com/facebook/react"
	)
	withArtifact := func(url string) *sdk.Dependency {
		dep := &sdk.Dependency{ID: "react@18.2.0"}
		detectors.SetOriginArtifact(dep, url)
		return dep
	}

	cases := []struct {
		name      string
		existing  *sdk.Dependency
		duplicate *sdk.Dependency
		want      detectors.Origin
	}{
		{
			name:      "occurrences agree",
			existing:  withArtifact(artifact),
			duplicate: withArtifact(artifact),
			want:      detectors.Origin{ArtifactURL: artifact},
		},
		{
			name:      "occurrences disagree, so the graph cannot say",
			existing:  withArtifact(artifact),
			duplicate: withArtifact(mirror),
		},
		{
			name:     "a different kind of origin is also a disagreement",
			existing: withArtifact(artifact),
			duplicate: func() *sdk.Dependency {
				d := &sdk.Dependency{ID: "react@18.2.0"}
				detectors.SetOriginVCS(d, repo, "")
				return d
			}(),
		},
		{
			name:      "an occurrence asserting nothing is not a disagreement",
			existing:  withArtifact(artifact),
			duplicate: &sdk.Dependency{ID: "react@18.2.0"},
			want:      detectors.Origin{ArtifactURL: artifact},
		},
		{
			name:      "an occurrence fills a gap the first one left",
			existing:  &sdk.Dependency{ID: "react@18.2.0"},
			duplicate: withArtifact(artifact),
			want:      detectors.Origin{ArtifactURL: artifact},
		},
		{
			name:      "neither asserts anything",
			existing:  &sdk.Dependency{ID: "react@18.2.0"},
			duplicate: &sdk.Dependency{ID: "react@18.2.0"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			detectors.MergeOrigin(tc.existing, tc.duplicate)
			if got := detectors.OriginFrom(tc.existing.Metadata); got != tc.want {
				t.Fatalf("merged origin = %+v, want %+v", got, tc.want)
			}
		})
	}

	t.Run("a pinned repository merging with an unpinned one disagrees", func(t *testing.T) {
		existing := &sdk.Dependency{ID: "react@18.2.0"}
		detectors.SetOriginVCS(existing, repo, "e7f8091a2b3c4d5e6f708192a3b4c5d6e7f80912")
		duplicate := &sdk.Dependency{ID: "react@18.2.0"}
		detectors.SetOriginVCS(duplicate, repo, "")

		detectors.MergeOrigin(existing, duplicate)
		if got := detectors.OriginFrom(existing.Metadata); !got.Empty() {
			t.Fatalf("merged origin = %+v, want none: the occurrences pin different commits", got)
		}
	})

	t.Run("nil is a no-op", func(t *testing.T) {
		detectors.MergeOrigin(nil, withArtifact(artifact))
		detectors.MergeOrigin(withArtifact(artifact), nil)
	})
}
