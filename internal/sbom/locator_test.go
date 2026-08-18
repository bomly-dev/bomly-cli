package sbom

import (
	"net/url"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-sdk"
)

func TestClassifyResolvedURL(t *testing.T) {
	cases := []struct {
		name      string
		raw       string
		source    sdk.DependencySource
		ecosystem sdk.Ecosystem
		wantKind  LocatorKind
		wantURL   string
	}{
		// Artifacts: the npm family is the cleanest case.
		{"npm tarball", "https://registry.npmjs.org/react/-/react-18.2.0.tgz", sdk.DependencySourceRegistry, sdk.EcosystemNPM, LocatorArtifact, "https://registry.npmjs.org/react/-/react-18.2.0.tgz"},
		{"python wheel", "https://files.pythonhosted.org/packages/x/req-2.31.0-py3-none-any.whl", sdk.DependencySourceURL, sdk.EcosystemPython, LocatorArtifact, "https://files.pythonhosted.org/packages/x/req-2.31.0-py3-none-any.whl"},
		{"python sdist", "https://files.pythonhosted.org/packages/x/req-2.31.0.tar.gz", sdk.DependencySourceURL, sdk.EcosystemPython, LocatorArtifact, "https://files.pythonhosted.org/packages/x/req-2.31.0.tar.gz"},
		{"gem artifact", "https://rubygems.org/gems/rake-13.0.6.gem", sdk.DependencySourceRegistry, sdk.EcosystemRuby, LocatorArtifact, "https://rubygems.org/gems/rake-13.0.6.gem"},

		// Registry roots must never become a download location.
		{"rubygems root", "https://rubygems.org/", sdk.DependencySourceRegistry, sdk.EcosystemRuby, LocatorRegistryRoot, "https://rubygems.org/"},
		{"pypi simple index", "https://pypi.org/simple", sdk.DependencySourceRegistry, sdk.EcosystemPython, LocatorRegistryRoot, "https://pypi.org/simple"},
		{"pub root", "https://pub.dev", sdk.DependencySourceRegistry, sdk.EcosystemDart, LocatorRegistryRoot, "https://pub.dev"},
		{"cargo registry prefix", "registry+https://github.com/rust-lang/crates.io-index", sdk.DependencySourceRegistry, sdk.EcosystemRust, LocatorRegistryRoot, "https://github.com/rust-lang/crates.io-index"},
		{"cargo sparse prefix", "sparse+https://index.crates.io/", sdk.DependencySourceRegistry, sdk.EcosystemRust, LocatorRegistryRoot, "https://index.crates.io/"},

		// VCS, including the SPDX grammar normalization.
		{"cargo git with rev", "git+https://github.com/a/b?rev=deadbeef", sdk.DependencySourceGit, sdk.EcosystemRust, LocatorVCS, "git+https://github.com/a/b@deadbeef"},
		{"cargo git with fragment", "git+https://github.com/a/b#cafebabe", sdk.DependencySourceGit, sdk.EcosystemRust, LocatorVCS, "git+https://github.com/a/b@cafebabe"},
		{"cargo git with tag", "git+https://github.com/a/b?tag=v1.2.3", sdk.DependencySourceGit, sdk.EcosystemRust, LocatorVCS, "git+https://github.com/a/b@v1.2.3"},
		{"git suffix path", "https://github.com/apple/swift-nio.git", sdk.DependencySourceGit, sdk.EcosystemSwift, LocatorVCS, "git+https://github.com/apple/swift-nio.git"},
		{"swiftpm registry kind still vcs", "https://github.com/apple/swift-nio", sdk.DependencySourceRegistry, sdk.EcosystemSwift, LocatorVCS, "git+https://github.com/apple/swift-nio"},

		// Local filesystem paths must never be emitted.
		{"absolute posix path", "/Users/ahmed/dev/mylib", sdk.DependencySourceFile, sdk.EcosystemPython, LocatorNone, ""},
		{"absolute path with non-file source", "/home/runner/work/x/y", sdk.DependencySourceURL, sdk.EcosystemPython, LocatorNone, ""},
		{"relative path", "../vendor/foo", sdk.DependencySourceFile, sdk.EcosystemPython, LocatorNone, ""},
		{"uv editable dot", ".", sdk.DependencySourceFile, sdk.EcosystemPython, LocatorNone, ""},
		{"windows path", `C:\src\lib`, sdk.DependencySourceFile, sdk.EcosystemNPM, LocatorNone, ""},
		{"file scheme", "file:///tmp/x.tgz", sdk.DependencySourceFile, sdk.EcosystemNPM, LocatorNone, ""},
		{"npm link specifier", "link:../pkg", sdk.DependencySourceWorkspace, sdk.EcosystemNPM, LocatorNone, ""},
		{"npm workspace specifier", "workspace:*", sdk.DependencySourceWorkspace, sdk.EcosystemNPM, LocatorNone, ""},
		{"npm link local dir", "https://registry.npmjs.org/a/-/a-1.0.0.tgz", sdk.DependencySourceWorkspace, sdk.EcosystemNPM, LocatorNone, ""},
		{"scp style git", "git@github.com:a/b.git", sdk.DependencySourceGit, sdk.EcosystemNPM, LocatorNone, ""},

		// Credentials must never reach an SBOM, in userinfo or anywhere else.
		{"userinfo token", "https://tok:s3cret@nexus.corp/a/b-1.0.tgz", sdk.DependencySourceRegistry, sdk.EcosystemNPM, LocatorNone, ""},
		{"token in hostname label", "https://ghp_abcd1234.repo.example/a.tgz", sdk.DependencySourceRegistry, sdk.EcosystemNPM, LocatorNone, ""},
		{"token in path segment", "https://repo.example/download/ghp_abcd1234/pkg.tgz", sdk.DependencySourceRegistry, sdk.EcosystemNPM, LocatorNone, ""},
		{"percent-encoded token in path", "https://repo.example/download/%67hp_abcd1234/pkg.tgz", sdk.DependencySourceRegistry, sdk.EcosystemNPM, LocatorNone, ""},
		{"username only", "https://tok@nexus.corp/a/b-1.0.tgz", sdk.DependencySourceRegistry, sdk.EcosystemNPM, LocatorNone, ""},
		{"query token", "https://nexus.corp/a/b-1.0.tgz?token=s3cret", sdk.DependencySourceRegistry, sdk.EcosystemNPM, LocatorNone, ""},
		{"presigned signature", "https://s3.amazonaws.com/b/a-1.0.tgz?X-Amz-Signature=deadbeef", sdk.DependencySourceRegistry, sdk.EcosystemNPM, LocatorNone, ""},
		{"fragment secret", "https://nexus.corp/a/b-1.0.tgz#s3cret", sdk.DependencySourceRegistry, sdk.EcosystemNPM, LocatorNone, ""},
		{"hex fragment of odd length is still a secret", "https://nexus.corp/a/b-1.0.tgz#deadbeef", sdk.DependencySourceRegistry, sdk.EcosystemNPM, LocatorNone, ""},
		// Yarn v1 appends the artifact's own sha1 to every resolved URL.
		// Treating that as a secret would drop the download location for
		// every package in a Yarn lockfile.
		{"yarn checksum fragment is stripped", "https://registry.yarnpkg.com/react/-/react-18.2.0.tgz#ceeba79ee36dfa7612b1ede82a3e37b2a30def1c", sdk.DependencySourceRegistry, sdk.EcosystemNPM, LocatorArtifact, "https://registry.yarnpkg.com/react/-/react-18.2.0.tgz"},
		{"sha256 fragment is stripped", "https://reg.example/a/b-1.0.tgz#" + strings.Repeat("a", 64), sdk.DependencySourceRegistry, sdk.EcosystemNPM, LocatorArtifact, "https://reg.example/a/b-1.0.tgz"},
		{"registry root with query", "https://nexus.corp/?apiKey=s3cret", sdk.DependencySourceRegistry, sdk.EcosystemRuby, LocatorNone, ""},
		// A VCS locator is exempt only because normalizeVCS discards the query
		// and keeps a character-checked revision. Every VCS form must be
		// classified before the gate, not just the cargo "git+" prefix.
		{"vcs query keeps only the revision", "git+https://github.com/a/b?rev=deadbeef&token=s3cret", sdk.DependencySourceGit, sdk.EcosystemRust, LocatorVCS, "git+https://github.com/a/b@deadbeef"},
		{"git source pin without prefix", "https://github.com/a/b?rev=deadbeef", sdk.DependencySourceGit, sdk.EcosystemNPM, LocatorVCS, "git+https://github.com/a/b@deadbeef"},
		{"dot-git path pin", "https://host/repo.git?rev=deadbeef", sdk.DependencySourceRegistry, sdk.EcosystemNPM, LocatorVCS, "git+https://host/repo.git@deadbeef"},
		{"swift pin with revision", "https://github.com/apple/swift-nio?tag=2.0.0", sdk.DependencySourceRegistry, sdk.EcosystemSwift, LocatorVCS, "git+https://github.com/apple/swift-nio@2.0.0"},
		{"git source drops a credential query", "https://github.com/a/b?token=s3cret", sdk.DependencySourceGit, sdk.EcosystemNPM, LocatorVCS, "git+https://github.com/a/b"},
		// The fragment is the resolved commit and the query is what was
		// requested, so the immutable commit wins over a moving branch. This
		// is the shape uv records: "?rev=main#abc123".
		{"resolved commit beats requested branch", "https://github.com/a/b?branch=main#abc123", sdk.DependencySourceGit, sdk.EcosystemPython, LocatorVCS, "git+https://github.com/a/b@abc123"},
		{"resolved commit beats requested rev", "https://github.com/example/git-helper?rev=main#abc123", sdk.DependencySourceGit, sdk.EcosystemPython, LocatorVCS, "git+https://github.com/example/git-helper@abc123"},
		// A fragment must be commit-shaped, not merely character-safe: an
		// access token passes isSafeRevision and would be republished.
		{"pat fragment is not a revision", "https://github.com/org/repo#ghp_abcd1234", sdk.DependencySourceGit, sdk.EcosystemNPM, LocatorVCS, "git+https://github.com/org/repo"},
		{"fine-grained pat fragment is not a revision", "https://github.com/org/repo#github_pat_11ABCDEFGHIJKLMNOP", sdk.DependencySourceGit, sdk.EcosystemNPM, LocatorVCS, "git+https://github.com/org/repo"},
		{"non-hex fragment is not a revision", "https://github.com/org/repo#release-candidate", sdk.DependencySourceGit, sdk.EcosystemNPM, LocatorVCS, "git+https://github.com/org/repo"},
		{"named query revision still allows tags", "https://github.com/org/repo?tag=v1.2.3", sdk.DependencySourceGit, sdk.EcosystemNPM, LocatorVCS, "git+https://github.com/org/repo@v1.2.3"},
		// A query key names its value a revision, so tags and branches are
		// legitimate there — but a recognizable token is not.
		{"token in rev query is rejected", "https://github.com/org/repo?rev=ghp_abcd1234", sdk.DependencySourceGit, sdk.EcosystemNPM, LocatorVCS, "git+https://github.com/org/repo"},
		{"token in branch query is rejected", "https://github.com/org/repo?branch=glpat-Abc123XYZ789def", sdk.DependencySourceGit, sdk.EcosystemNPM, LocatorVCS, "git+https://github.com/org/repo"},
		{"underscored branch still allowed", "https://github.com/org/repo?branch=release_candidate", sdk.DependencySourceGit, sdk.EcosystemNPM, LocatorVCS, "git+https://github.com/org/repo@release_candidate"},
		{"requested rev used when no commit resolved", "https://github.com/a/b?rev=v1.2.3", sdk.DependencySourceGit, sdk.EcosystemPython, LocatorVCS, "git+https://github.com/a/b@v1.2.3"},

		// Degenerate input.
		{"empty", "", sdk.DependencySourceRegistry, sdk.EcosystemNPM, LocatorNone, ""},
		{"whitespace", "   ", sdk.DependencySourceRegistry, sdk.EcosystemNPM, LocatorNone, ""},
		{"scheme only", "https://", sdk.DependencySourceRegistry, sdk.EcosystemNPM, LocatorNone, ""},
		{"colons", "::::", sdk.DependencySourceRegistry, sdk.EcosystemNPM, LocatorNone, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyResolvedURL(tc.raw, tc.source, tc.ecosystem)
			if got.Kind != tc.wantKind {
				t.Fatalf("kind = %v, want %v (url %q)", got.Kind, tc.wantKind, got.URL)
			}
			if got.URL != tc.wantURL {
				t.Fatalf("url = %q, want %q", got.URL, tc.wantURL)
			}
		})
	}
}

// TestClassifyResolvedURLNeverEmitsLocalPaths is the invariant that matters
// most: whatever a lockfile contains, a classified value is either empty or an
// absolute http(s)/git+http(s) URL. A regression here leaks the developer's or
// CI runner's directory layout into a published SBOM.
func TestClassifyResolvedURLNeverEmitsLocalPaths(t *testing.T) {
	inputs := []string{
		"/Users/ahmed/secret-project/lib", "../../etc/passwd", "./local", ".",
		`C:\Users\ahmed\proj`, "file:///Users/ahmed/x", "link:../a", "workspace:^1",
		"git@github.com:a/b.git", "ssh://git@github.com/a/b.git", "", "   ",
		"https://user:pass@host/a.tgz",
	}
	for _, in := range inputs {
		for _, source := range []sdk.DependencySource{
			sdk.DependencySourceRegistry, sdk.DependencySourceGit, sdk.DependencySourceURL,
			sdk.DependencySourceFile, sdk.DependencySourceProject, sdk.DependencySourceWorkspace, "",
		} {
			got := classifyResolvedURL(in, source, sdk.EcosystemNPM)
			assertPublishableLocator(t, got, in)
		}
	}
}

// assertPublishableLocator enforces the emit-or-nothing contract shared by the
// table test and the fuzz target.
func assertPublishableLocator(t *testing.T, got Locator, input string) {
	t.Helper()
	if got.Kind == LocatorNone {
		if got.URL != "" {
			t.Fatalf("LocatorNone carried url %q for input %q", got.URL, input)
		}
		return
	}
	if got.URL == "" {
		t.Fatalf("kind %v carried an empty url for input %q", got.Kind, input)
	}
	switch {
	case strings.HasPrefix(got.URL, "https://"), strings.HasPrefix(got.URL, "http://"):
	default:
		// The classifier deliberately keeps the asserted version-control tool
		// rather than rewriting everything to git+, so accept every prefix it
		// can produce. Hard-coding git+ here would fail `make fuzz` on valid
		// behavior.
		matched := false
		for _, prefix := range vcsToolPrefixes {
			if strings.HasPrefix(got.URL, prefix+"https://") || strings.HasPrefix(got.URL, prefix+"http://") ||
				strings.HasPrefix(got.URL, prefix+"git://") {
				matched = true
				break
			}
		}
		if !matched {
			t.Fatalf("emitted an out-of-vocabulary locator %q for input %q", got.URL, input)
		}
	}
	// Check userinfo structurally rather than by looking for "@": scoped npm
	// packages ("/@babel/core/") and VCS revisions ("@deadbeef") both contain
	// one legitimately.
	bare := got.URL
	for _, prefix := range vcsToolPrefixes {
		bare = strings.TrimPrefix(bare, prefix)
	}
	parsed, err := url.Parse(bare)
	if err != nil {
		t.Fatalf("emitted unparseable locator %q for input %q", got.URL, input)
	}
	if parsed.User != nil {
		t.Fatalf("emitted locator with userinfo %q for input %q", got.URL, input)
	}
}

func TestNormalizeRepositoryURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"github.com/kubernetes/kubernetes", "https://github.com/kubernetes/kubernetes"},
		{"gitlab.com/org/repo", "https://gitlab.com/org/repo"},
		{"https://github.com/a/b", "https://github.com/a/b"},
		{"", ""},
		{"   ", ""},
		{"not-a-host", ""},
		{"github.com", ""},
		{"github.com/", ""},
		{"/Users/ahmed/repo", ""},
		{"has space/repo", ""},
		{"ftp://github.com/a/b", ""},
		{"https://tok:sec@github.com/a/b", ""},
	}
	for _, tc := range cases {
		if got := normalizeRepositoryURL(tc.in); got != tc.want {
			t.Fatalf("normalizeRepositoryURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
