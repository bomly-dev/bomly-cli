//go:build !bomly_external_grype

package grype

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	v6dist "github.com/anchore/grype/grype/db/v6/distribution"
	grypeName "github.com/anchore/grype/grype/db/v6/name"
	grypematch "github.com/anchore/grype/grype/match"
	grypepkg "github.com/anchore/grype/grype/pkg"
	grypevuln "github.com/anchore/grype/grype/vulnerability"
	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestDescriptor_Name(t *testing.T) {
	a := Matcher{}
	d := a.Descriptor()
	if d.Name != "grype" {
		t.Errorf("Descriptor.Name = %q, want %q", d.Name, "grype")
	}
	// Builtin mode matches a bounded set — see supportedEcosystems in
	// builtin.go. External mode declares nil instead.
	if len(d.SupportedEcosystems) == 0 {
		t.Fatal("SupportedEcosystems should list the ecosystems builtin mode can match")
	}
	found := false
	for _, eco := range d.SupportedEcosystems {
		if eco == sdk.EcosystemNPM {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("SupportedEcosystems = %v, expected it to include npm", d.SupportedEcosystems)
	}
}

func TestMatch_NilGraph_ReturnsEmpty(t *testing.T) {
	a := Matcher{}
	registry := sdk.NewPackageRegistry()
	result, err := a.Match(context.Background(), sdk.MatchRequest{Graph: nil, Registry: registry})
	if err != nil {
		t.Fatalf("Match with nil graph: %v", err)
	}
	if result.Registry.Len() != 0 {
		t.Errorf("expected empty registry result for nil input graph")
	}
}

func TestReady_TrueWhenDBDirAbsent(t *testing.T) {
	a := Matcher{DBDir: filepath.Join(t.TempDir(), "nonexistent-db")}
	if err := a.Ready(context.Background(), sdk.MatchRequest{}); err != nil {
		t.Errorf("Ready() = %v, want nil because the bundled matcher can download the DB", err)
	}
}

func TestDBExists_TrueWhenDBDirExists(t *testing.T) {
	dir := t.TempDir()
	a := Matcher{DBDir: dir}
	if !a.dbExists() {
		t.Error("dbExists() = false, want true when DB dir exists")
	}
}

func TestMatch_DBNotPresent_AttemptsDownloadAndReturnsEmpty(t *testing.T) {
	// Inject a bad LatestURL so the download fails fast without network access.
	// Match should warn and return an empty result rather than hard-failing.
	badDist := v6dist.DefaultConfig()
	badDist.LatestURL = "http://127.0.0.1:0/no-such-db" // immediately refused
	badDist.CheckTimeout = 2 * time.Second

	a := Matcher{
		DBDir:              filepath.Join(t.TempDir(), "no-db"),
		DistConfigOverride: &badDist,
	}

	dep := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: "npm", Name: "lodash", Version: "4.17.15", PURL: "pkg:npm/lodash@4.17.15"}})
	g := sdk.New()
	if err := g.AddNode(dep); err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	registry := sdk.NewPackageRegistry()

	result, err := a.Match(context.Background(), sdk.MatchRequest{Graph: g, Registry: registry})
	if err == nil {
		t.Fatal("expected non-nil error when DB download fails")
	}
	if result.Registry != registry {
		t.Fatalf("expected original registry to be returned when DB download fails")
	}
}

func TestDBDir_DefaultUsesOSCacheDir(t *testing.T) {
	a := Matcher{}
	dir := a.dbDir()
	if dir == "" {
		t.Error("dbDir() = empty string, want non-empty path")
	}
	// Should end in grype/db.
	cacheDir, err := os.UserCacheDir()
	if err == nil {
		want := filepath.Join(cacheDir, "grype", "db")
		if dir != want {
			t.Errorf("dbDir() = %q, want %q", dir, want)
		}
	}
}

func TestGraphPkgToGrypePkg_FieldMapping(t *testing.T) {
	p := &sdk.Package{Coordinates: sdk.Coordinates{Name: "lodash",
		Version:   "4.17.15",
		PURL:      "pkg:npm/lodash@4.17.15",
		Ecosystem: "npm"},
	}
	gp := graphPkgToGrypePkg(p)
	if gp.Name != "lodash" {
		t.Errorf("Name = %q, want lodash", gp.Name)
	}
	if gp.Version != "4.17.15" {
		t.Errorf("Version = %q, want 4.17.15", gp.Version)
	}
	if gp.PURL != "pkg:npm/lodash@4.17.15" {
		t.Errorf("PURL = %q, want pkg:npm/lodash@4.17.15", gp.PURL)
	}
	if string(gp.ID) != "pkg:npm/lodash@4.17.15" {
		t.Errorf("ID = %q, want PURL as correlation id", gp.ID)
	}
}

// Grype searches its DB by the name it is handed, so a scoped npm package must
// arrive as "@scope/name" — the bare name would query the unscoped package and
// attach its advisories to the scoped one. See issue #319.
func TestGraphPkgToGrypePkg_EcosystemNativeName(t *testing.T) {
	cases := []struct {
		name string
		pkg  sdk.Coordinates
		want string
	}{
		{
			name: "npm scoped",
			pkg:  sdk.Coordinates{Org: "tailwindcss", Name: "postcss", Version: "4.3.3", PURL: "pkg:npm/%40tailwindcss/postcss@4.3.3", Ecosystem: sdk.EcosystemNPM},
			want: "@tailwindcss/postcss",
		},
		{
			name: "npm unscoped",
			pkg:  sdk.Coordinates{Name: "postcss", Version: "8.5.16", PURL: "pkg:npm/postcss@8.5.16", Ecosystem: sdk.EcosystemNPM},
			want: "postcss",
		},
		{
			name: "go module path",
			pkg:  sdk.Coordinates{Org: "github.com/spf13", Name: "cobra", Version: "v1.8.0", PURL: "pkg:golang/github.com/spf13/cobra@v1.8.0", Ecosystem: sdk.EcosystemGo},
			want: "github.com/spf13/cobra",
		},
		// OS packages carry the distro in Org. Grype's distro-namespace
		// matchers query the bare name, so joining would miss every OS
		// advisory — see the distro/upstream plumbing in purl_builtin.go.
		{
			name: "apk keeps bare name",
			pkg:  sdk.Coordinates{Org: "alpine", Name: "libcrypto3", Version: "3.0.8-r0", PURL: "pkg:apk/alpine/libcrypto3@3.0.8-r0?arch=x86_64&distro=alpine-3.17.2&upstream=openssl", Ecosystem: sdk.EcosystemAPK},
			want: "libcrypto3",
		},
		{
			name: "dpkg keeps bare name",
			pkg:  sdk.Coordinates{Org: "debian", Name: "libc6", Version: "2.31-13", PURL: "pkg:deb/debian/libc6@2.31-13?arch=amd64&distro=debian-11", Ecosystem: sdk.EcosystemDPKG},
			want: "libc6",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := graphPkgToGrypePkg(&sdk.Package{Coordinates: tc.pkg}).Name; got != tc.want {
				t.Errorf("Name = %q, want %q", got, tc.want)
			}
		})
	}
}

// Closes the loop on the mapping above: grypeName.PackageNames is what the
// matchers hand to the DB search, so this asserts the scoped package is looked
// up under its own name only and never under the unscoped "postcss".
func TestGrypeSearchNamesKeepNPMScope(t *testing.T) {
	scoped := graphPkgToGrypePkg(&sdk.Package{Coordinates: sdk.Coordinates{
		Org: "tailwindcss", Name: "postcss", Version: "4.3.3",
		PURL: "pkg:npm/%40tailwindcss/postcss@4.3.3", Ecosystem: sdk.EcosystemNPM,
	}})

	names := grypeName.PackageNames(scoped)
	if len(names) != 1 || names[0] != "@tailwindcss/postcss" {
		t.Fatalf("PackageNames() = %v, want [@tailwindcss/postcss]", names)
	}
	for _, n := range names {
		if n == "postcss" {
			t.Errorf("scoped package searched under unscoped name %q", n)
		}
	}
}

// The ecosystem-native name and the distro/upstream plumbing have to hold at
// the same time: an OS package must reach Grype under its bare name *and* keep
// the distro its advisories are namespaced by.
func TestGraphPkgToGrypePkg_OSPackageKeepsBareNameAndDistro(t *testing.T) {
	gp := graphPkgToGrypePkg(&sdk.Package{Coordinates: sdk.Coordinates{
		Org: "alpine", Name: "libcrypto3", Version: "3.0.8-r0",
		PURL:      "pkg:apk/alpine/libcrypto3@3.0.8-r0?arch=x86_64&distro=alpine-3.17.2&upstream=openssl",
		Ecosystem: sdk.EcosystemAPK,
	}})

	if gp.Name != "libcrypto3" {
		t.Errorf("Name = %q, want libcrypto3", gp.Name)
	}
	if gp.Distro == nil {
		t.Fatal("Distro = nil, want alpine-3.17.2")
	}
	if got := gp.Distro.Name(); got != "alpine" {
		t.Errorf("distro name = %q, want alpine", got)
	}
	if len(gp.Upstreams) != 1 || gp.Upstreams[0].Name != "openssl" {
		t.Errorf("Upstreams = %v, want [{openssl }]", gp.Upstreams)
	}
	// The upstream is resolved against the package's own name; a joined name
	// would stop matching it against the upstream= qualifier.
	if names := grypeName.PackageNames(gp); len(names) != 1 || names[0] != "libcrypto3" {
		t.Errorf("PackageNames() = %v, want [libcrypto3]", names)
	}
}

func TestMapBuiltinMatchCarriesRichFields(t *testing.T) {
	v := mapBuiltinMatch(grypematch.Match{
		Package: grypepkg.Package{ID: "pkg-1", Name: "lodash", Version: "4.17.15", PURL: "pkg:npm/lodash@4.17.15"},
		Vulnerability: grypevuln.Vulnerability{
			Reference: grypevuln.Reference{ID: "CVE-2020-8203", Namespace: "github:language:javascript"},
			Fix: grypevuln.Fix{
				Versions: []string{"4.17.19"},
				State:    grypevuln.FixStateFixed,
				Available: []grypevuln.FixAvailable{{
					Version: "4.17.19",
					Date:    time.Date(2020, 7, 1, 0, 0, 0, 0, time.UTC),
					Kind:    "first-observed",
				}},
			},
			Advisories:             []grypevuln.Advisory{{ID: "GHSA-p6mc-m468-83gw", Link: "https://github.com/advisories/GHSA-p6mc-m468-83gw"}},
			RelatedVulnerabilities: []grypevuln.Reference{{ID: "GHSA-p6mc-m468-83gw", Namespace: "github:language:javascript"}},
			Metadata: &grypevuln.Metadata{
				DataSource:  "https://nvd.nist.gov/vuln/detail/CVE-2020-8203",
				Namespace:   "nvd:cpe",
				Severity:    "High",
				Description: "Prototype pollution",
				URLs:        []string{"https://example.test/advisory"},
				Cvss: []grypevuln.Cvss{{
					Source:  "nvd",
					Version: "3.1",
					Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
					Metrics: grypevuln.CvssMetrics{BaseScore: 9.8},
				}},
				KnownExploited: []grypevuln.KnownExploited{{CVE: "CVE-2020-8203", KnownRansomwareCampaignUse: "Known"}},
				EPSS:           []grypevuln.EPSS{{CVE: "CVE-2020-8203", EPSS: 0.25, Percentile: 0.9, Date: time.Date(2024, 5, 1, 0, 0, 0, 0, time.UTC)}},
				CWEs:           []grypevuln.CWE{{CVE: "CVE-2020-8203", CWE: "CWE-1321", Source: "nvd", Type: "primary"}},
			},
		},
	})
	if v.FixedIn != "4.17.19" || v.FixState != "fixed" {
		t.Fatalf("fix data missing: %#v", v)
	}
	if len(v.CVSS) != 1 || len(v.EPSS) != 1 || len(v.CWEs) != 1 || len(v.KnownExploited) != 1 || len(v.Aliases) != 1 {
		t.Fatalf("rich fields missing: %#v", v)
	}
}
