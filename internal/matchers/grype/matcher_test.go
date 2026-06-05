//go:build !bomly_external_grype

package grype

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	v6dist "github.com/anchore/grype/grype/db/v6/distribution"
	grypematch "github.com/anchore/grype/grype/match"
	grypepkg "github.com/anchore/grype/grype/pkg"
	grypevuln "github.com/anchore/grype/grype/vulnerability"
	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestDescriptor_Name(t *testing.T) {
	a := Matcher{Priority: 90}
	d := a.Descriptor()
	if d.Name != "grype" {
		t.Errorf("Descriptor.Name = %q, want %q", d.Name, "grype")
	}
	if d.Priority != 90 {
		t.Errorf("Descriptor.Priority = %d, want 90", d.Priority)
	}
	if d.SupportedEcosystems != nil {
		t.Error("SupportedEcosystems should be nil (all ecosystems)")
	}
}

func TestMatch_NilGraph_ReturnsEmpty(t *testing.T) {
	a := Matcher{Priority: 90}
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
	a := Matcher{Priority: 90, DBDir: filepath.Join(t.TempDir(), "nonexistent-db")}
	if !a.Ready() {
		t.Error("Ready() = false, want true because the bundled matcher can download the DB")
	}
}

func TestDBExists_TrueWhenDBDirExists(t *testing.T) {
	dir := t.TempDir()
	a := Matcher{Priority: 90, DBDir: dir}
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
		Priority:           90,
		DBDir:              filepath.Join(t.TempDir(), "no-db"),
		DistConfigOverride: &badDist,
	}

	dep := sdk.NewDependency(sdk.Dependency{Ecosystem: "npm", Name: "lodash", Version: "4.17.15", PURL: "pkg:npm/lodash@4.17.15"})
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
	a := Matcher{Priority: 90}
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
	p := &sdk.Package{
		Name:      "lodash",
		Version:   "4.17.15",
		PURL:      "pkg:npm/lodash@4.17.15",
		Ecosystem: "npm",
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
