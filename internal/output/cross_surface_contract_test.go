package output

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestStructuredAndSARIFFindingContractsAgree(t *testing.T) {
	const purl = "pkg:npm/@scope/library@1.0.0"
	registry := sdk.NewPackageRegistry()
	registry.Add(&sdk.Package{
		Coordinates: sdk.Coordinates{
			PURL: purl, Ecosystem: sdk.EcosystemNPM, Org: "scope", Name: "library", Version: "1.0.0",
		},
		Vulnerabilities: []sdk.Vulnerability{{
			ID:             "GHSA-contract",
			Aliases:        []string{"CVE-2026-4242"},
			ParsedSeverity: sdk.SeverityHigh,
			FixedIn:        "1.1.0",
			Reachability: &sdk.Reachability{
				Status: sdk.ReachabilityReachable,
				Tier:   sdk.TierPackage,
				Reason: "imported package",
			},
		}},
	})
	findings := []sdk.Finding{{
		ID:              "GHSA-contract",
		Kind:            sdk.FindingKindVulnerability,
		Title:           "Contract fixture",
		Severity:        sdk.SeverityHigh,
		PolicyStatus:    sdk.FindingPolicyStatusSuppressed,
		RuleID:          "advisory",
		PackageRef:      purl,
		DependencyRefs:  []string{"dep-contract"},
		VulnerabilityID: "GHSA-contract",
	}}

	structured := FindingsFromScan(findings, registry)
	if len(structured) != 1 {
		t.Fatalf("structured finding count = %d", len(structured))
	}
	if structured[0].ID != findings[0].ID ||
		structured[0].PolicyStatus != findings[0].PolicyStatus ||
		structured[0].RuleID != findings[0].RuleID ||
		structured[0].Package.Purl != purl {
		t.Fatalf("structured finding lost canonical fields: %#v", structured[0])
	}

	var encoded bytes.Buffer
	if err := WriteSARIF(&encoded, findings, registry, "bomly", "test", SARIFOptions{IncludeReachability: true}); err != nil {
		t.Fatal(err)
	}
	var document struct {
		Runs []struct {
			Results []struct {
				RuleID       string `json:"ruleId"`
				Level        string `json:"level"`
				Suppressions []struct {
					Kind string `json:"kind"`
				} `json:"suppressions"`
				Properties struct {
					RuleID       string   `json:"rule_id"`
					PackageRef   string   `json:"package_ref"`
					Dependencies []string `json:"dependency_refs"`
					Reachability string   `json:"reachability"`
				} `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(encoded.Bytes(), &document); err != nil {
		t.Fatalf("decode SARIF: %v", err)
	}
	result := document.Runs[0].Results[0]
	if result.RuleID != findings[0].ID ||
		result.Level != "note" ||
		len(result.Suppressions) != 1 ||
		result.Suppressions[0].Kind != "external" ||
		result.Properties.RuleID != findings[0].RuleID ||
		result.Properties.PackageRef != purl ||
		len(result.Properties.Dependencies) != 1 ||
		result.Properties.Reachability != string(sdk.ReachabilityReachable) {
		t.Fatalf("SARIF finding disagrees with structured contract: %#v", result)
	}
}
