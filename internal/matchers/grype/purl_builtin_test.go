//go:build !bomly_external_grype

package grype

import (
	"testing"

	grypepkg "github.com/anchore/grype/grype/pkg"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/bomly-dev/bomly-sdk"
)

func TestDistroFromPURL(t *testing.T) {
	cases := []struct {
		name        string
		purl        string
		wantDistro  string
		wantVersion string
	}{
		{
			name:        "alpine apk",
			purl:        "pkg:apk/alpine/openssl@3.0.8-r0?arch=x86_64&distro=alpine-3.17.2&upstream=openssl",
			wantDistro:  "alpine",
			wantVersion: "3.17.2",
		},
		{
			name:        "debian deb",
			purl:        "pkg:deb/debian/libc6@2.31-13?arch=amd64&distro=debian-11",
			wantDistro:  "debian",
			wantVersion: "11",
		},
		{
			name:        "rhel rpm",
			purl:        "pkg:rpm/rhel/openssl@1:1.1.1k-9.el8?arch=x86_64&distro=rhel-8.6",
			wantDistro:  "redhat",
			wantVersion: "8.6",
		},
		{
			name:       "distro without version",
			purl:       "pkg:apk/wolfi/openssl@3.0.8-r0?distro=wolfi",
			wantDistro: "wolfi",
		},
		{
			name: "no distro qualifier",
			purl: "pkg:apk/openssl@3.0.8-r0",
		},
		{
			name: "language package",
			purl: "pkg:npm/lodash@4.17.20",
		},
		{
			name: "unparseable purl",
			purl: "not-a-purl",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			distro := distroFromPURL(tc.purl)
			if tc.wantDistro == "" {
				if distro != nil {
					t.Fatalf("distroFromPURL(%q) = %v, want nil", tc.purl, distro)
				}
				return
			}
			if distro == nil {
				t.Fatalf("distroFromPURL(%q) = nil, want %q", tc.purl, tc.wantDistro)
			}
			if got := distro.Name(); got != tc.wantDistro {
				t.Errorf("distro name = %q, want %q", got, tc.wantDistro)
			}
			if got := distro.Version; got != tc.wantVersion {
				t.Errorf("distro version = %q, want %q", got, tc.wantVersion)
			}
		})
	}
}

func TestUpstreamsFromPURL(t *testing.T) {
	cases := []struct {
		name     string
		purl     string
		pkgName  string
		syftType syftPkg.Type
		want     []grypepkg.UpstreamPackage
	}{
		{
			name:     "apk origin package",
			purl:     "pkg:apk/alpine/libcrypto3@3.0.8-r0?arch=x86_64&distro=alpine-3.17.2&upstream=openssl",
			pkgName:  "libcrypto3",
			syftType: syftPkg.ApkPkg,
			want:     []grypepkg.UpstreamPackage{{Name: "openssl"}},
		},
		{
			name:     "deb source package with version",
			purl:     "pkg:deb/debian/libssl1.1@1.1.1n-0%2Bdeb11u4?arch=amd64&distro=debian-11&upstream=openssl%401.1.1n-0%2Bdeb11u4",
			pkgName:  "libssl1.1",
			syftType: syftPkg.DebPkg,
			want:     []grypepkg.UpstreamPackage{{Name: "openssl", Version: "1.1.1n-0+deb11u4"}},
		},
		{
			name:     "source rpm",
			purl:     "pkg:rpm/rhel/openssl-libs@1:1.1.1k-9.el8?arch=x86_64&distro=rhel-8.6&upstream=openssl-1.1.1k-9.el8.src.rpm",
			pkgName:  "openssl-libs",
			syftType: syftPkg.RpmPkg,
			want:     []grypepkg.UpstreamPackage{{Name: "openssl", Version: "1.1.1k-9.el8"}},
		},
		{
			name:     "source rpm matching package name is dropped",
			purl:     "pkg:rpm/rhel/openssl@1:1.1.1k-9.el8?arch=x86_64&distro=rhel-8.6&upstream=openssl-1.1.1k-9.el8.src.rpm",
			pkgName:  "openssl",
			syftType: syftPkg.RpmPkg,
		},
		{
			name:     "malformed source rpm",
			purl:     "pkg:rpm/rhel/openssl-libs@1:1.1.1k-9.el8?distro=rhel-8.6&upstream=openssl",
			pkgName:  "openssl-libs",
			syftType: syftPkg.RpmPkg,
		},
		{
			name:     "upstream matching package name is dropped",
			purl:     "pkg:apk/alpine/openssl@3.0.8-r0?distro=alpine-3.17.2&upstream=openssl",
			pkgName:  "openssl",
			syftType: syftPkg.ApkPkg,
		},
		{
			name:     "no upstream qualifier",
			purl:     "pkg:apk/alpine/openssl@3.0.8-r0?distro=alpine-3.17.2",
			pkgName:  "openssl",
			syftType: syftPkg.ApkPkg,
		},
		{
			name:     "language package",
			purl:     "pkg:npm/lodash@4.17.20",
			pkgName:  "lodash",
			syftType: syftPkg.NpmPkg,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := upstreamsFromPURL(tc.purl, tc.pkgName, tc.syftType)
			if len(got) != len(tc.want) {
				t.Fatalf("upstreamsFromPURL(%q) = %+v, want %+v", tc.purl, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("upstream[%d] = %+v, want %+v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// An OS package has to reach Grype with a distro attached: every OS matcher
// bails out without one, which is why container OS packages used to come back
// clean instead of vulnerable (issue #316).
func TestGraphPkgToGrypePkgCarriesDistroAndUpstreams(t *testing.T) {
	pkg := graphPkgToGrypePkg(&sdk.Package{
		Coordinates: sdk.Coordinates{
			PURL:      "pkg:apk/alpine/libcrypto3@3.0.8-r0?arch=x86_64&distro=alpine-3.17.2&upstream=openssl",
			Ecosystem: sdk.EcosystemAPK,
			Name:      "libcrypto3",
			Version:   "3.0.8-r0",
		},
	})

	if pkg.Type != syftPkg.ApkPkg {
		t.Errorf("type = %q, want %q", pkg.Type, syftPkg.ApkPkg)
	}
	if pkg.Distro == nil {
		t.Fatal("distro = nil, want alpine 3.17.2")
	}
	if got, want := pkg.Distro.Name(), "alpine"; got != want {
		t.Errorf("distro name = %q, want %q", got, want)
	}
	if got, want := pkg.Distro.Version, "3.17.2"; got != want {
		t.Errorf("distro version = %q, want %q", got, want)
	}
	if len(pkg.Upstreams) != 1 || pkg.Upstreams[0].Name != "openssl" {
		t.Errorf("upstreams = %+v, want [{openssl }]", pkg.Upstreams)
	}
}

// Language packages must be unaffected: no distro, no upstreams.
func TestGraphPkgToGrypePkgLanguagePackageUnchanged(t *testing.T) {
	pkg := graphPkgToGrypePkg(&sdk.Package{
		Coordinates: sdk.Coordinates{
			PURL:      "pkg:npm/lodash@4.17.20",
			Ecosystem: sdk.EcosystemNPM,
			Name:      "lodash",
			Version:   "4.17.20",
		},
	})

	if pkg.Distro != nil {
		t.Errorf("distro = %v, want nil", pkg.Distro)
	}
	if len(pkg.Upstreams) != 0 {
		t.Errorf("upstreams = %+v, want none", pkg.Upstreams)
	}
	if pkg.Language != syftPkg.JavaScript {
		t.Errorf("language = %q, want %q", pkg.Language, syftPkg.JavaScript)
	}
}
