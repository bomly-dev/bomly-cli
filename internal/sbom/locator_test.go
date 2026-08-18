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
	case strings.HasPrefix(got.URL, "https://"), strings.HasPrefix(got.URL, "http://"),
		strings.HasPrefix(got.URL, "git+https://"), strings.HasPrefix(got.URL, "git+http://"):
	default:
		t.Fatalf("emitted non-http(s) locator %q for input %q", got.URL, input)
	}
	// Check userinfo structurally rather than by looking for "@": scoped npm
	// packages ("/@babel/core/") and VCS revisions ("@deadbeef") both contain
	// one legitimately.
	parsed, err := url.Parse(strings.TrimPrefix(got.URL, "git+"))
	if err != nil {
		t.Fatalf("emitted unparseable locator %q for input %q", got.URL, input)
	}
	if parsed.User != nil {
		t.Fatalf("emitted locator with userinfo %q for input %q", got.URL, input)
	}
}

func TestIsPublishableReferenceURL(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"https://example.com/docs", true},
		{"http://example.com/docs", true},
		{"mailto:security@example.com", true},
		// Credentials hide in every part of a reference, not just userinfo.
		{"mailto:security@example.com#token=s3cret", false},
		{"mailto:security@example.com?subject=s3cret", false},
		{"https://example.com/docs?token=s3cret", false},
		{"https://example.com/docs#s3cret", false},
		{"https://tok:s3cret@example.com/docs", false},
		// CycloneDX external-reference URLs are IRI references, so safe
		// non-HTTP identifiers must survive a round trip.
		{"urn:uuid:3f2504e0-4f89-41d3-9a0c-0305e82c3301", true},
		{"git://github.com/org/repo", true},
		{"ftp://files.example.com/pkg.tgz", true},
		{"urn:uuid:3f2504e0#s3cret", false},
		{"file:///Users/victim/secret.html", false},
		{"/Users/victim/secret.html", false},
		{"javascript:alert(1)", false},
		{"data:text/html,<script>alert(1)</script>", false},
		{"https://", false},
		{"mailto:", false},
		{"", false},
		{"   ", false},
	}
	for _, tc := range cases {
		if got := isPublishableReferenceURL(tc.in); got != tc.want {
			t.Fatalf("isPublishableReferenceURL(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestClassifyAssertedDownloadLocation covers the relaxed path used when a
// source document itself declared a value to be a download location. A benign
// query survives; a credential-shaped one still does not.
func TestClassifyAssertedDownloadLocation(t *testing.T) {
	cases := []struct {
		in       string
		wantKind LocatorKind
		wantURL  string
	}{
		// An exact endpoint with no archive suffix must not be demoted.
		{"https://repo.example/download?id=123", LocatorArtifact, "https://repo.example/download?id=123"},
		{"https://repo.example/download/left-pad", LocatorArtifact, "https://repo.example/download/left-pad"},
		{"https://reg.example/a/b-1.0.tgz", LocatorArtifact, "https://reg.example/a/b-1.0.tgz"},
		// Credentials stay rejected, by parameter name and by value shape.
		{"https://repo.example/download?token=s3cret", LocatorNone, ""},
		{"https://repo.example/download?X-Amz-Signature=deadbeef", LocatorNone, ""},
		{"https://repo.example/download?id=ghp_abcd1234", LocatorNone, ""},
		{"https://tok:s3cret@repo.example/download?id=123", LocatorNone, ""},
		{"file:///Users/victim/pkg.tgz", LocatorNone, ""},
		{"/Users/victim/pkg.tgz", LocatorNone, ""},
		{"NOASSERTION", LocatorNone, ""},
		{"", LocatorNone, ""},
	}
	for _, tc := range cases {
		got := classifyAssertedDownloadLocation(tc.in)
		if got.Kind != tc.wantKind || got.URL != tc.wantURL {
			t.Fatalf("classifyAssertedDownloadLocation(%q) = %+v, want kind %v url %q",
				tc.in, got, tc.wantKind, tc.wantURL)
		}
	}

	// The relaxation must not leak into the detector path, which has no such
	// assertion behind it.
	if got := classifyResolvedURL("https://repo.example/download?id=123", "", ""); got.Kind != LocatorNone {
		t.Fatalf("detector path accepted a query: %+v", got)
	}
}

func TestIsSafeRevisionRejectsCredentialShapes(t *testing.T) {
	rejected := []string{
		"ghp_abcd1234", "github_pat_11ABCDEFGHIJKLMNOP_xyz", "gho_abcdefghijklmnop", "ghs_abcdefghijklmnop",
		"glpat-Abc123XYZ789def", "npm_abcdefghijklmnop", "pypi-AgEIcHlwaS5vcmc",
		"xoxb-123456789-abcdefghijk", "sk-abcdef123456ghijk", "sk_live_abcdefghijkl",
		"AKIAIOSFODNN7EXAMPLE", "AIzaSyA-abc123defghijklmnop", "hf_abcDEFghijklmnop",
		"dop_v1_abcdefghijklmnop", "shpat_abc123defghijk",
	}
	for _, value := range rejected {
		if isSafeRevision(value) {
			t.Fatalf("isSafeRevision(%q) = true, want it rejected as a credential shape", value)
		}
	}

	// Real refs must keep working, including ones using the same characters a
	// token does.
	allowed := []string{
		"main", "v1.2.3", "2.0.0-beta.1", "release_candidate", "feature/foo",
		"9f8e7d6c5b4a", "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		"skip-ci", "package_name", "AKIRA",
	}
	for _, value := range allowed {
		if !isSafeRevision(value) {
			t.Fatalf("isSafeRevision(%q) = false, want a legitimate ref accepted", value)
		}
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
