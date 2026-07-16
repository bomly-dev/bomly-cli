//go:build bomly_external_grype

package grype

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestParseGrypeJSONOutputCarriesRichFields(t *testing.T) {
	registry := sdk.NewPackageRegistry()
	const purl = "pkg:npm/lodash@4.17.15"
	registry.Ensure(purl)

	data := []byte(`{
		"matches": [{
			"vulnerability": {
				"id": "CVE-2020-8203",
				"dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2020-8203",
				"namespace": "github:language:javascript",
				"severity": "High",
				"urls": ["https://example.test/advisory"],
				"description": "Prototype pollution",
				"cvss": [{
					"source": "nvd",
					"type": "CVSS",
					"version": "3.1",
					"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
					"metrics": {"baseScore": 9.8}
				}],
				"knownExploited": [{
					"cve": "CVE-2020-8203",
					"knownRansomwareCampaignUse": "Known",
					"urls": ["https://kev.test"]
				}],
				"epss": [{"cve": "CVE-2020-8203", "epss": 0.25, "percentile": 0.9, "date": "2024-05-01"}],
				"cwes": [{"cve": "CVE-2020-8203", "cwe": "CWE-1321", "source": "nvd", "type": "primary"}],
				"fix": {"versions": ["4.17.19"], "state": "fixed", "available": [{"version": "4.17.19", "date": "2020-07-01", "kind": "first-observed"}]},
				"advisories": [{"id": "GHSA-p6mc-m468-83gw", "link": "https://github.com/advisories/GHSA-p6mc-m468-83gw"}],
				"risk": 75.5
			},
			"relatedVulnerabilities": [{"id": "GHSA-p6mc-m468-83gw", "namespace": "github:language:javascript"}],
			"matchDetails": [{
				"found": {"constraint": "< 4.17.19"},
				"fix": {"suggestedVersion": "4.17.21"}
			}],
			"artifact": {
				"id": "pkg-1",
				"name": "lodash",
				"version": "4.17.15",
				"purl": "pkg:npm/lodash@4.17.15",
				"cpes": ["cpe:2.3:a:lodash:lodash:4.17.15:*:*:*:*:*:*:*"]
			}
		}]
	}`)
	if _, _, err := parseGrypeJSONOutput(data, registry, nil); err != nil {
		t.Fatalf("parseGrypeJSONOutput: %v", err)
	}
	pkg, ok := registry.Get(purl)
	if !ok {
		t.Fatalf("expected registry package for %q", purl)
	}
	if len(pkg.Vulnerabilities) != 1 {
		t.Fatalf("len vulnerabilities = %d, want 1", len(pkg.Vulnerabilities))
	}
	v := pkg.Vulnerabilities[0]
	if v.FixedIn != "4.17.21" {
		t.Fatalf("FixedIn = %q, want suggested version", v.FixedIn)
	}
	if v.AffectedVersionRange != "< 4.17.19" || len(v.FixedVersions) != 1 || v.FixState != "fixed" {
		t.Fatalf("fix/range data missing: %#v", v)
	}
	if len(v.CVSS) != 1 || len(v.EPSS) != 1 || len(v.CWEs) != 1 || len(v.KnownExploited) != 1 || len(v.CPEs) != 1 {
		t.Fatalf("rich fields missing: %#v", v)
	}
}

func TestParseGrypeJSONOutputSkipsFirstPartyPURLs(t *testing.T) {
	registry := sdk.NewPackageRegistry()
	const firstParty = "pkg:npm/my-app@1.0.0"
	const thirdParty = "pkg:npm/lodash@4.17.15"

	data := []byte(`{
		"matches": [
			{"vulnerability": {"id": "CVE-0000-0001"}, "artifact": {"name": "my-app", "version": "1.0.0", "purl": "pkg:npm/my-app@1.0.0"}},
			{"vulnerability": {"id": "CVE-2020-8203"}, "artifact": {"name": "lodash", "version": "4.17.15", "purl": "pkg:npm/lodash@4.17.15"}}
		]
	}`)
	skip := map[string]struct{}{firstParty: {}}
	matched, vulnerabilities, err := parseGrypeJSONOutput(data, registry, skip)
	if err != nil {
		t.Fatalf("parseGrypeJSONOutput: %v", err)
	}
	if matched != 1 || vulnerabilities != 1 {
		t.Fatalf("matched, vulnerabilities = %d, %d; want 1, 1 (first-party match dropped)", matched, vulnerabilities)
	}
	if _, ok := registry.Get(firstParty); ok {
		t.Fatalf("first-party PURL %q must not be added to the registry", firstParty)
	}
	pkg, ok := registry.Get(thirdParty)
	if !ok || len(pkg.Vulnerabilities) != 1 {
		t.Fatalf("expected third-party match to survive, got %#v", pkg)
	}
}

func TestFirstPartyPURLs(t *testing.T) {
	graph := sdk.New()
	app := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{
		Name: "my-app", Version: "1.0.0", PURL: "pkg:npm/my-app@1.0.0",
		Ecosystem: "npm", Type: sdk.PackageTypeApplication,
	}})
	dep := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{
		Name: "lodash", Version: "4.17.15", PURL: "pkg:npm/lodash@4.17.15", Ecosystem: "npm",
	}})
	_ = graph.AddNode(app)
	_ = graph.AddNode(dep)

	skip := firstPartyPURLs(graph)
	if _, ok := skip["pkg:npm/my-app@1.0.0"]; !ok {
		t.Fatal("expected application-typed node PURL in the skip set")
	}
	if _, ok := skip["pkg:npm/lodash@4.17.15"]; ok {
		t.Fatal("package-typed node PURL must not be in the skip set")
	}
}
