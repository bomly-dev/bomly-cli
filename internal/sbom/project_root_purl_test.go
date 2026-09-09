package sbom

import (
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-sdk/purlkit"
)

// A project's name is not a controlled vocabulary. It is the directory the
// repository happens to sit in, or the last segment of a git remote, so it can
// carry any character a filesystem allows -- including the two the package-URL
// grammar reserves as separators.
//
// The synthesized root's PURL used to be pasted together from url.PathEscape
// output, and PathEscape leaves '@' alone because '@' is legal in a URL path.
// A project named "app@2" therefore exported as "pkg:generic/app@2", which
// reads back as the package "app" at version "2": the document asserted a
// different identity than the one it was describing. purlkit escapes the
// separators, so the parts that went in are the parts that come back out.
func TestProjectRootPURLSurvivesSeparatorsInNameAndVersion(t *testing.T) {
	cases := []struct {
		label   string
		name    string
		version string
		want    string
	}{
		{"ordinary", "demo-project", "v1.2.3", "pkg:generic/demo-project@v1.2.3"},
		{"no version", "demo-project", "", "pkg:generic/demo-project"},
		{"at sign in name", "app@2", "", "pkg:generic/app%402"},
		{"at sign in name with version", "app@2", "v1.0.0", "pkg:generic/app%402@v1.0.0"},
		{"at sign in version", "app", "1.0@rc1", "pkg:generic/app@1.0%40rc1"},
		{"space in name", "My App", "", "pkg:generic/my%20app"},
		{"slash in name", "a/b", "", "pkg:generic/a%2Fb"},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			got := projectRootComponent(ProjectRoot{Name: tc.name, Version: tc.version})
			if got.PURL != tc.want {
				t.Fatalf("PURL = %q, want %q", got.PURL, tc.want)
			}
			// The rendering is only worth pinning because it round-trips: a
			// consumer parsing the exported document must recover the name and
			// version the scan actually saw.
			parsed, err := purlkit.Parse(got.PURL)
			if err != nil {
				t.Fatalf("exported PURL %q does not parse: %v", got.PURL, err)
			}
			if wantName := strings.ToLower(tc.name); parsed.Name != wantName {
				t.Fatalf("PURL %q parses back to name %q, want %q", got.PURL, parsed.Name, wantName)
			}
			if parsed.Version != tc.version {
				t.Fatalf("PURL %q parses back to version %q, want %q", got.PURL, parsed.Version, tc.version)
			}
			// Name and Version stay verbatim on the component; only the PURL
			// is escaped.
			if got.Name != tc.name || got.Version != tc.version {
				t.Fatalf("component name/version = %q/%q, want %q/%q", got.Name, got.Version, tc.name, tc.version)
			}
		})
	}
}

// A name that cannot make a well-formed package URL yields no package URL,
// rather than a malformed one a consumer would have to guess at. The export
// path already refuses a blank project name before it gets here, so this is
// the second gate; it exists because the first one is a caller's promise and
// this one is the function's own.
func TestProjectRootPURLIsEmptyWhenItCannotBeWellFormed(t *testing.T) {
	for _, name := range []string{"", "   "} {
		got := projectRootComponent(ProjectRoot{Name: name, Version: "1.0.0"})
		if got.PURL != "" {
			t.Fatalf("projectRootComponent(%q).PURL = %q, want an empty PURL", name, got.PURL)
		}
	}
}
