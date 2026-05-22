package grype

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestMapGrypeAdvisoryCarriesRichFields(t *testing.T) {
	v := mapGrypeAdvisory(grypeAdvisory{
		ID:                   "CVE-2024-1234",
		Namespace:            "github:language:javascript",
		DataSource:           "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
		Severity:             "High",
		SeveritySource:       "nvd",
		Description:          "important vuln",
		URLs:                 []string{"https://example.test/advisory"},
		CVSS:                 []sdk.CVSSScore{{Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Score: 9.8, Version: "3.1", Source: "nvd"}},
		FixedVersions:        []string{"1.2.3", "1.3.0"},
		FixState:             "fixed",
		FixAvailable:         []sdk.FixAvailable{{Version: "1.2.3", Date: "2024-01-02", Kind: "first-observed"}},
		AffectedVersionRange: "< 1.2.3",
		References:           []sdk.Reference{{URL: "https://patch.test/1", Type: "GHSA-xxxx"}},
		Aliases:              []string{"GHSA-xxxx"},
		KnownExploited:       []sdk.KnownExploited{{CVE: "CVE-2024-1234", KnownRansomwareCampaignUse: "Known"}},
		EPSS:                 []sdk.EPSSScore{{CVE: "CVE-2024-1234", EPSS: 0.42, Percentile: 0.97, Date: "2024-05-01"}},
		CWEs:                 []sdk.CWE{{CVE: "CVE-2024-1234", ID: "CWE-79", Source: "nvd", Type: "primary"}},
		RiskScore:            88.2,
		CPEs:                 []string{"cpe:2.3:a:example:pkg:1.0:*:*:*:*:*:*:*"},
	})

	if v.FixedIn != "1.2.3" {
		t.Fatalf("FixedIn = %q, want 1.2.3", v.FixedIn)
	}
	if len(v.FixedVersions) != 2 || v.FixedVersions[1] != "1.3.0" {
		t.Fatalf("FixedVersions = %#v", v.FixedVersions)
	}
	if v.Severity != "high" || v.Title != "important vuln" || v.Source != matcherName {
		t.Fatalf("unexpected core fields: %#v", v)
	}
	if len(v.CVSS) != 1 || v.CVSS[0].Score != 9.8 {
		t.Fatalf("CVSS = %#v", v.CVSS)
	}
	if len(v.References) != 3 {
		t.Fatalf("References = %#v, want patch, data source, and URL refs", v.References)
	}
	if !v.KEVExploited || len(v.KnownExploited) != 1 {
		t.Fatalf("known exploited data not mapped: %#v", v.KnownExploited)
	}
	if len(v.EPSS) != 1 || v.EPSS[0].Percentile != 0.97 {
		t.Fatalf("EPSS = %#v", v.EPSS)
	}
	if len(v.CWEs) != 1 || v.CWEs[0].ID != "CWE-79" {
		t.Fatalf("CWEs = %#v", v.CWEs)
	}
	if v.RiskScore != 88.2 || v.DataSource == "" || v.Namespace == "" || len(v.CPEs) != 1 {
		t.Fatalf("rich metadata missing: %#v", v)
	}
}

func TestMapGrypeAdvisoryPrefersSuggestedFixedIn(t *testing.T) {
	v := mapGrypeAdvisory(grypeAdvisory{
		ID:            "CVE-2024-1234",
		Severity:      "medium",
		FixedIn:       "2.0.0",
		FixedVersions: []string{"1.2.3"},
	})
	if v.FixedIn != "2.0.0" {
		t.Fatalf("FixedIn = %q, want suggested version", v.FixedIn)
	}
}

func TestAppendOrMergeVulnerabilityUnionsFields(t *testing.T) {
	existing := []sdk.PackageVulnerability{{
		ID:      "CVE-1",
		Source:  matcherName,
		FixedIn: "1.0.0",
		Aliases: []string{"GHSA-1"},
		CVSS:    []sdk.CVSSScore{{Vector: "v1", Source: "nvd"}},
		Reasons: []string{"old"},
	}}
	incoming := sdk.PackageVulnerability{
		ID:             "CVE-1",
		Source:         matcherName,
		FixState:       "fixed",
		FixedVersions:  []string{"1.0.0", "1.1.0"},
		Aliases:        []string{"GHSA-1", "ALIAS-2"},
		CVSS:           []sdk.CVSSScore{{Vector: "v2", Source: "vendor"}},
		KnownExploited: []sdk.KnownExploited{{CVE: "CVE-1"}},
		Reasons:        []string{"old", "new"},
	}
	got := appendOrMergeVulnerability(existing, incoming)
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	merged := got[0]
	if merged.FixedIn != "1.0.0" || merged.FixState != "fixed" {
		t.Fatalf("unexpected fix fields: %#v", merged)
	}
	if len(merged.FixedVersions) != 2 || len(merged.Aliases) != 2 || len(merged.CVSS) != 2 || len(merged.Reasons) != 2 {
		t.Fatalf("merge did not union fields: %#v", merged)
	}
	if !merged.IsExploitable() {
		t.Fatal("merged vulnerability should be exploitable")
	}
}
