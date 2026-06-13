package scorecard

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestResolveRepo(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		pkg  *sdk.Package
		want string
	}{
		{
			name: "nil package",
			pkg:  nil,
			want: "",
		},
		{
			name: "golang PURL with github.com module",
			pkg:  &sdk.Package{Coordinates: sdk.Coordinates{PURL: "pkg:golang/github.com/sirupsen/logrus@v1.9.0"}},
			want: "github.com/sirupsen/logrus",
		},
		{
			name: "golang PURL with github.com module and subpath",
			pkg:  &sdk.Package{Coordinates: sdk.Coordinates{PURL: "pkg:golang/github.com/google/go-containerregistry/pkg/v1@v0.14.0"}},
			want: "github.com/google/go-containerregistry",
		},
		{
			name: "golang PURL with non-github module",
			pkg:  &sdk.Package{Coordinates: sdk.Coordinates{PURL: "pkg:golang/golang.org/x/sys@v0.10.0"}},
			want: "",
		},
		{
			name: "github PURL type",
			pkg:  &sdk.Package{Coordinates: sdk.Coordinates{PURL: "pkg:github/ossf/scorecard@v5.0.0"}},
			want: "github.com/ossf/scorecard",
		},
		{
			name: "repository_url qualifier",
			pkg:  &sdk.Package{Coordinates: sdk.Coordinates{PURL: "pkg:npm/lodash@4.17.15?repository_url=https://github.com/lodash/lodash.git"}},
			want: "github.com/lodash/lodash",
		},
		{
			name: "vcs_url qualifier with .git suffix",
			pkg:  &sdk.Package{Coordinates: sdk.Coordinates{PURL: "pkg:npm/foo@1.0.0?vcs_url=https://github.com/example/foo.git"}},
			want: "github.com/example/foo",
		},
		{
			name: "ResolvedURL https tarball",
			pkg:  &sdk.Package{Coordinates: sdk.Coordinates{PURL: "pkg:npm/bar@1.0.0"}, ResolvedURL: "https://github.com/example/bar/archive/refs/tags/v1.0.0.tar.gz"},
			want: "github.com/example/bar",
		},
		{
			name: "ResolvedURL ssh form",
			pkg: &sdk.Package{
				ResolvedURL: "git@github.com:example/baz.git",
			},
			want: "github.com/example/baz",
		},
		{
			name: "no github reference anywhere",
			pkg:  &sdk.Package{Coordinates: sdk.Coordinates{PURL: "pkg:npm/qux@1.0.0"}, ResolvedURL: "https://registry.npmjs.org/qux/-/qux-1.0.0.tgz"},
			want: "",
		},
		{
			name: "qualifier on non-github host",
			pkg:  &sdk.Package{Coordinates: sdk.Coordinates{PURL: "pkg:npm/foo@1.0.0?repository_url=https://gitlab.com/example/foo.git"}},
			want: "",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := resolveRepo(tc.pkg)
			if got != tc.want {
				t.Errorf("resolveRepo(%q) = %q, want %q", describePkg(tc.pkg), got, tc.want)
			}
		})
	}
}

func describePkg(pkg *sdk.Package) string {
	if pkg == nil {
		return "<nil>"
	}
	if pkg.PURL != "" {
		return pkg.PURL
	}
	if pkg.ResolvedURL != "" {
		return pkg.ResolvedURL
	}
	return pkg.Name
}
