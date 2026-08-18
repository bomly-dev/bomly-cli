package detectors_test

import (
	"net/url"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-sdk"
	testutil "github.com/bomly-dev/bomly-sdk/testkit"
)

// FuzzSetOrigin drives the origin invariant with arbitrary lockfile-derived
// strings. Detectors pass raw lockfile fields straight through, so whatever a
// repository can put in a lockfile can reach these setters.
func FuzzSetOrigin(f *testing.F) {
	f.Add("https://registry.npmjs.org/react/-/react-18.2.0.tgz", "")
	f.Add("https://github.com/owner/repo.git", "9f8e7d6c5b4a3928176554433221100ffeeddcc0")
	f.Add("https://github.com/example/helper?rev=main#abc123", "v1.2.3")
	f.Add("https://user:s3cret@nexus.corp/repo/pkg.tgz", "main")
	f.Add("git+ssh://git@github.com/owner/repo.git#9f8e7d6", "9f8e7d6")
	f.Add("file:///home/someone/wheels/pkg.whl", "")
	f.Add("/Users/someone/src/project", "")
	f.Add("http://0#0", "0")
	f.Add("http://0/0#\x02", "\x02")
	f.Add("%./0", "%")
	f.Add("https://", "")
	f.Add("https://:8080/pkg.tgz", "")
	f.Add("https://例え.テスト/パッケージ.tgz", "リビジョン")

	f.Fuzz(func(t *testing.T, rawURL, revision string) {
		if len(rawURL)+len(revision) > testutil.MaxFuzzInputSize {
			return
		}

		artifact := &sdk.Dependency{ID: "pkg"}
		detectors.SetOriginArtifact(artifact, rawURL)
		repository := &sdk.Dependency{ID: "pkg"}
		detectors.SetOriginVCS(repository, rawURL, revision)

		// Whatever was stored must satisfy the invariant: export publishes
		// these values into an SBOM without re-deciding anything.
		assertPublishable(t, detectors.OriginFrom(artifact.Metadata))
		assertPublishable(t, detectors.OriginFrom(repository.Metadata))

		// A second pass over the same input must reach the same conclusion,
		// and reading back what was written must be a fixed point.
		again := &sdk.Dependency{ID: "pkg"}
		detectors.SetOriginVCS(again, rawURL, revision)
		first, second := detectors.OriginFrom(repository.Metadata), detectors.OriginFrom(again.Metadata)
		if first != second {
			t.Fatalf("nondeterministic origin: %+v then %+v", first, second)
		}
		if reread := detectors.OriginFrom(map[string]any{
			detectors.MetadataKeyOriginVCSURL:      first.VCSURL,
			detectors.MetadataKeyOriginVCSRevision: first.VCSRevision,
		}); reread != first {
			t.Fatalf("stored origin did not survive a re-read: %+v became %+v", first, reread)
		}
	})
}

// assertPublishable fails when an origin carries anything an SBOM must never
// show: a non-web location, a host-less URL, embedded credentials, or a
// revision that would break the SPDX "git+<url>@<revision>" grammar.
func assertPublishable(t *testing.T, origin detectors.Origin) {
	t.Helper()

	if origin.ArtifactURL != "" && origin.VCSURL != "" {
		t.Fatalf("origin claims two locations at once: %+v", origin)
	}
	if origin.VCSRevision != "" && origin.VCSURL == "" {
		t.Fatalf("revision %q recorded without a repository", origin.VCSRevision)
	}
	for _, raw := range []string{origin.ArtifactURL, origin.VCSURL} {
		if raw == "" {
			continue
		}
		parsed, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("published URL %q does not parse: %v", raw, err)
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			t.Fatalf("published URL %q is not a web location", raw)
		}
		if parsed.Hostname() == "" {
			t.Fatalf("published URL %q has no host", raw)
		}
		if parsed.User != nil {
			t.Fatalf("published URL %q carries credentials", raw)
		}
		if parsed.Fragment != "" {
			t.Fatalf("published URL %q carries a fragment", raw)
		}
	}
	if origin.VCSURL != "" {
		parsed, err := url.Parse(origin.VCSURL)
		if err != nil {
			t.Fatalf("repository URL %q does not parse: %v", origin.VCSURL, err)
		}
		if parsed.RawQuery != "" || parsed.ForceQuery {
			t.Fatalf("repository URL %q carries a query", origin.VCSURL)
		}
	}
	for _, r := range origin.VCSRevision {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '_', r == '-', r == '+', r == '/':
		default:
			t.Fatalf("revision %q carries %q, which breaks the SPDX locator grammar", origin.VCSRevision, r)
		}
	}
}
