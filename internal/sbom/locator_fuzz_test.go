package sbom

import (
	"net/url"
	"strings"
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

// FuzzIsValidCPE exercises the CPE validator, a hand-written parser over
// values taken from untrusted SPDX and CycloneDX documents. It carries two
// separate grammars — the 2.3 formatted string with backslash escapes, and the
// 2.2 URI binding with percent encoding and a packed edition — so it meets the
// repository's rule that every new parser of untrusted data gets a target.
//
// The invariant is the one that matters for output: anything accepted is
// re-emitted as a package identity assertion, so an accepted value must be
// printable ASCII with no delimiter that would change how a consumer parses it.
func FuzzIsValidCPE(f *testing.F) {
	for _, seed := range []string{
		"cpe:2.3:a:example:left-pad:1.3.0:*:*:*:*:*:*:*",
		"cpe:2.3:o:vendor:os:1.0:-:*:*:*:*:*:*",
		`cpe:2.3:a:ven\:dor:prod:1.0:*:*:*:*:*:*:*`,
		"cpe:/a:hp:insight_diagnostics:7.4.0.1570::~~online~win2003~x64~",
		"cpe:/a:apache:log4j:2.14.1",
		"cpe:/a:vendor%3Aname:product",
		"cpe:/a:vendor%ZZ:product",
		"cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*:extra",
		"cpe:2.3:z:vendor:product:1.0:*:*:*:*:*:*:*",
		"cpe:2.3:a:vendor with space:product:1.0:*:*:*:*:*:*:*",
		`cpe:2.3:a:vendor:pro\`,
		"cpe:2.3:", "cpe:/", "cpe:", "not-a-cpe", "", "   ",
		"cpe:2.3:a:v:p:1.0:*:*:*:*:*:*:\x00",
		"cpe:/a:v:\x7f",
		"cpe:2.3:a:v:p:1.0:*:*:*:*:*:*:é",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > testkit.MaxFuzzInputSize {
			return
		}
		got := isValidCPE(raw)
		if again := isValidCPE(raw); again != got {
			t.Fatalf("nondeterministic validation of %q: %v vs %v", raw, got, again)
		}
		if !got {
			return
		}
		// isValidCPE trims, so the value callers must store is the trimmed
		// one. Every caller is responsible for storing that form; asserting
		// on it here is what pins the contract.
		trimmed := strings.TrimSpace(raw)
		for _, r := range trimmed {
			if r < '!' || r > '~' {
				t.Fatalf("accepted %q containing a non-printable or non-ASCII rune %q", trimmed, r)
			}
		}
		if !strings.HasPrefix(trimmed, "cpe:2.3:") && !strings.HasPrefix(trimmed, "cpe:/") {
			t.Fatalf("accepted %q, which is neither CPE binding", trimmed)
		}
	})
}

// FuzzIsPublishableReferenceURL exercises the gate every ingested external
// reference passes through. It spans several schemes, HTTP queries and paths,
// mail addresses, URN payloads, percent escapes, and credential detection, and
// a value it accepts is re-emitted verbatim into a published document.
//
// The invariant is what that re-emission requires: an accepted value carries
// no credential in any position and is a usable reference target.
func FuzzIsPublishableReferenceURL(f *testing.F) {
	for _, seed := range []string{
		"https://example.com/docs",
		"http://example.com/a?version=1",
		"ftp://files.example.com/pkg.tgz",
		"git://github.com/org/repo",
		"mailto:security@example.com",
		"urn:uuid:3f2504e0-4f89-41d3-9a0c-0305e82c3301",
		"urn:example:a%3Ab",
		"https://ghp_abcd1234.repo.example/a.tgz",
		"https://repo.example/download/ghp_abcd1234/pkg.tgz",
		"https://repo.example/download?token=s3cret",
		"https://repo.example/download?ghp_abcd1234",
		"https://tok:s3cret@example.com/a",
		"mailto:ghp_abcd1234",
		"mailto:ghp_abcd1234@example.com",
		"urn:foo bar", "urn:uuid:%ZZ",
		"file:///Users/victim/x", "javascript:alert(1)", "data:text/html,x",
		"/Users/victim/x", "https://", "", "   ", "\x00", "%%%",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > testkit.MaxFuzzInputSize {
			return
		}
		got := isPublishableReferenceURL(raw)
		if again := isPublishableReferenceURL(raw); again != got {
			t.Fatalf("nondeterministic result for %q: %v vs %v", raw, got, again)
		}
		if !got {
			return
		}

		trimmed := strings.TrimSpace(raw)
		parsed, err := url.Parse(trimmed)
		if err != nil {
			t.Fatalf("accepted an unparseable reference %q", trimmed)
		}
		if parsed.User != nil {
			t.Fatalf("accepted a reference carrying userinfo: %q", trimmed)
		}
		switch strings.ToLower(parsed.Scheme) {
		case "http", "https", "git", "ftp", "ftps", "mailto", "urn":
		default:
			t.Fatalf("accepted an out-of-vocabulary scheme %q in %q", parsed.Scheme, trimmed)
		}
		// No credential may survive anywhere in the emitted value. Scanning
		// the whole string keeps this independent of how the implementation
		// happens to split components.
		decoded := trimmed
		if unescaped, err := url.PathUnescape(trimmed); err == nil {
			decoded = unescaped
		}
		if containsCredential(decoded) {
			t.Fatalf("accepted %q, which contains a recognizable credential", trimmed)
		}
	})
}
