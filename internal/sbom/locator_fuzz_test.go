package sbom

import (
	"testing"

	"github.com/bomly-dev/bomly-sdk"
	"github.com/bomly-dev/bomly-sdk/testkit"
)

// FuzzClassifyResolvedURL exercises the resolved-URL classifier, which runs
// over values taken verbatim from untrusted lockfiles (npm `resolved`, uv
// `editable`/`path`, Cargo.lock `source`, Gemfile.lock `GEM remote:`, and so
// on).
//
// The invariant under test is a safety property, not just an absence of
// panics: a classified value is either nothing at all or an absolute http(s)
// URL with no embedded credentials. That is what keeps local filesystem paths
// and private-registry tokens out of published SBOMs.
func FuzzClassifyResolvedURL(f *testing.F) {
	for _, seed := range []string{
		"https://registry.npmjs.org/react/-/react-18.2.0.tgz",
		"https://files.pythonhosted.org/packages/x/req-2.31.0-py3-none-any.whl",
		"https://rubygems.org/",
		"https://pypi.org/simple",
		"registry+https://github.com/rust-lang/crates.io-index",
		"sparse+https://index.crates.io/",
		"git+https://github.com/a/b?rev=deadbeef",
		"git+https://github.com/a/b#cafebabe",
		"https://github.com/apple/swift-nio.git",
		"https://registry.npmjs.org/@babel/core/-/core-7.0.0.tgz",
		"https://tok:s3cret@nexus.corp/a/b-1.0.tgz",
		"/Users/ahmed/dev/mylib",
		"../vendor/foo",
		".",
		`C:\src\lib`,
		"file:///tmp/x.tgz",
		"link:../pkg",
		"workspace:*",
		"git@github.com:a/b.git",
		"https://",
		// Regression: a host-only URL with a fragment once produced
		// "git+http://0@0", whose "@<revision>" suffix re-parses as userinfo.
		"http://0#0",
		// Regression: a control character in the fragment once reached the
		// revision suffix and produced an unparseable locator.
		"http://0/0#\x02",
		"::::",
		"",
		"   ",
		"\x00\uFFFD",
		"%%%%",
		"https://host/%2e%2e/%2e%2e/etc/passwd",
	} {
		f.Add(seed)
	}

	sources := []sdk.DependencySource{
		sdk.DependencySourceRegistry, sdk.DependencySourceGit, sdk.DependencySourceURL,
		sdk.DependencySourceFile, sdk.DependencySourceProject, sdk.DependencySourceWorkspace, "",
	}
	ecosystems := []sdk.Ecosystem{
		sdk.EcosystemNPM, sdk.EcosystemPython, sdk.EcosystemRust,
		sdk.EcosystemRuby, sdk.EcosystemSwift, sdk.EcosystemUnknown,
	}

	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > testkit.MaxFuzzInputSize {
			return
		}
		for _, source := range sources {
			for _, ecosystem := range ecosystems {
				got := classifyResolvedURL(raw, source, ecosystem)
				assertPublishableLocator(t, got, raw)

				if again := classifyResolvedURL(raw, source, ecosystem); again != got {
					t.Fatalf("nondeterministic classification of %q: %+v vs %+v", raw, got, again)
				}
			}
		}
	})
}

// FuzzNormalizeRepositoryURL exercises the scorecard repository renderer,
// whose input is an API-supplied repository identifier.
func FuzzNormalizeRepositoryURL(f *testing.F) {
	for _, seed := range []string{
		"github.com/kubernetes/kubernetes",
		"https://github.com/a/b",
		"github.com",
		"not-a-host",
		"/Users/ahmed/repo",
		"has space/repo",
		"ftp://github.com/a/b",
		"https://tok:sec@github.com/a/b",
		"",
		"\x00",
		// Regression: a dot-containing but non-hostname prefix once produced
		// "https://%./0", which is an invalid percent-escape.
		"%./0",
		// Regression: a scheme with no host once produced the bare "http:".
		"http://",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > testkit.MaxFuzzInputSize {
			return
		}
		got := normalizeRepositoryURL(raw)
		if got == "" {
			return
		}
		assertPublishableLocator(t, Locator{Kind: LocatorVCS, URL: got}, raw)
		if again := normalizeRepositoryURL(raw); again != got {
			t.Fatalf("nondeterministic normalization of %q: %q vs %q", raw, got, again)
		}
	})
}
