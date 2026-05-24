package grant

import (
	"context"
	"reflect"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestDescriptor(t *testing.T) {
	c := mustNew(t)
	d := c.Descriptor()
	if d.Name != MatcherName {
		t.Fatalf("Name = %q, want %q", d.Name, MatcherName)
	}
	if !d.Enabled {
		t.Fatalf("Enabled = false, want true (matcher is enabled by default)")
	}
	if d.Origin != sdk.BundledOrigin {
		t.Fatalf("Origin = %v, want BundledOrigin", d.Origin)
	}
	if d.Priority != 85 {
		t.Fatalf("Priority = %d, want 85", d.Priority)
	}
	if len(d.Capabilities) == 0 || d.Capabilities[0] != "license-enrichment" {
		t.Fatalf("Capabilities = %v, want [license-enrichment]", d.Capabilities)
	}
}

func TestApplicable(t *testing.T) {
	c := mustNew(t)
	ok, err := c.Applicable(context.Background(), sdk.MatchRequest{})
	if err != nil {
		t.Fatalf("Applicable err = %v", err)
	}
	if ok {
		t.Fatalf("Applicable with nil graph = true, want false")
	}
	g := sdk.New()
	ok, err = c.Applicable(context.Background(), sdk.MatchRequest{Graph: g})
	if err != nil {
		t.Fatalf("Applicable err = %v", err)
	}
	if !ok {
		t.Fatalf("Applicable with graph = false, want true")
	}
}

func TestApplyLicensesSkipsWhenAlreadySet(t *testing.T) {
	pkg := &sdk.Package{
		Name:     "foo",
		Version:  "1.0.0",
		Licenses: []sdk.PackageLicense{{Value: "MIT", SPDXExpression: "MIT", Type: "external-depsdev"}},
	}
	if applyLicenses(pkg, []string{"Apache-2.0"}) {
		t.Fatalf("applyLicenses overwrote existing licenses")
	}
	if pkg.Licenses[0].Type != "external-depsdev" {
		t.Fatalf("existing license overwritten: %#v", pkg.Licenses[0])
	}
}

func TestApplyLicensesAttributesSource(t *testing.T) {
	pkg := &sdk.Package{Name: "foo", Version: "1.0.0"}
	if !applyLicenses(pkg, []string{"MIT", "MIT", " Apache-2.0 "}) {
		t.Fatalf("applyLicenses returned false on non-empty input")
	}
	if len(pkg.Licenses) != 2 {
		t.Fatalf("len Licenses = %d, want 2 (dedupe + trim)", len(pkg.Licenses))
	}
	for _, lic := range pkg.Licenses {
		if lic.Type != SourceType {
			t.Fatalf("license type = %q, want %q", lic.Type, SourceType)
		}
	}
	if !pkg.Matched {
		t.Fatalf("Matched = false, want true after enrichment")
	}
}

func TestLookupKeyNormalizesNameAndVersion(t *testing.T) {
	if lookupKey("LoDash", "4.17.15") != lookupKey(" lodash ", "4.17.15") {
		t.Fatalf("lookupKey does not normalize case/whitespace")
	}
}

func TestParseGrantJSONOutputExtractsLicenses(t *testing.T) {
	raw := []byte(`{
		"run": {
			"targets": [{
				"evaluation": {
					"findings": {
						"packages": [
							{"name":"lodash","version":"4.17.15","licenses":[{"id":"MIT"}]},
							{"name":"left-pad","version":"1.3.0","licenses":[{"id":"","name":"WTFPL"}]},
							{"name":"unlicensed","version":"0.1.0","licenses":[]}
						]
					}
				}
			}]
		}
	}`)
	got, err := parseGrantJSONOutput(raw)
	if err != nil {
		t.Fatalf("parseGrantJSONOutput err = %v", err)
	}
	want := map[string][]string{
		"lodash@4.17.15": {"MIT"},
		"left-pad@1.3.0": {"WTFPL"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseGrantJSONOutput = %#v, want %#v", got, want)
	}
}

func TestParseGrantJSONOutputEmpty(t *testing.T) {
	got, err := parseGrantJSONOutput(nil)
	if err != nil {
		t.Fatalf("err on empty: %v", err)
	}
	if got != nil {
		t.Fatalf("got %#v on empty, want nil", got)
	}
}

func TestParseGrantJSONOutputDedupesAcrossTargets(t *testing.T) {
	raw := []byte(`{
		"run": {
			"targets": [
				{"evaluation":{"findings":{"packages":[{"name":"x","version":"1","licenses":[{"id":"MIT"}]}]}}},
				{"evaluation":{"findings":{"packages":[{"name":"x","version":"1","licenses":[{"id":"MIT"},{"id":"Apache-2.0"}]}]}}}
			]
		}
	}`)
	got, err := parseGrantJSONOutput(raw)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if want := []string{"MIT", "Apache-2.0"}; !reflect.DeepEqual(got["x@1"], want) {
		t.Fatalf("dedupe across targets = %v, want %v", got["x@1"], want)
	}
}

func mustNew(t *testing.T) *Checker {
	t.Helper()
	cfg := DefaultConfig()
	cfg.CacheDir = t.TempDir()
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}
