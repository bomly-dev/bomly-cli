package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	model "github.com/bomly-dev/bomly-cli/sdk"
)

// fixtureRegistryWithVuln builds a single-package PURL-keyed registry where
// `purl` carries one Vulnerability — used by SARIF reachability tests to
// supply the data the writer now resolves through *sdk.PackageRegistry.
func fixtureRegistryWithVuln(purl string, vuln model.Vulnerability) *model.PackageRegistry {
	reg := model.NewPackageRegistry()
	pkg := reg.Ensure(purl)
	pkg.Vulnerabilities = []model.Vulnerability{vuln}
	return reg
}

func TestWriteSARIFEmitsCodeFlowsAndPropertiesForReachableFinding(t *testing.T) {
	const purl = "pkg:go/lib@1.0.0"
	reg := fixtureRegistryWithVuln(purl, model.Vulnerability{
		ID:    "GHSA-test",
		Title: "vuln",
		Reachability: &model.Reachability{
			Status:   model.ReachabilityReachable,
			Tier:     model.TierSymbol,
			Analyzer: "govulncheck",
			Reason:   "called-from-app",
			CallPaths: []model.CallPath{
				{
					Sink: model.AffectedSymbol{Symbol: "Decode", Package: "lib"},
					Frames: []model.CallFrame{
						{Function: "main", Package: "main", Position: model.SourcePosition{File: "main.go", Line: 12, Column: 4}},
						{Function: "Decode", Package: "lib", Position: model.SourcePosition{File: "lib/decode.go", Line: 88}},
					},
				},
			},
		},
	})
	findings := []model.Finding{
		{
			ID:              "GHSA-test",
			VulnerabilityID: "GHSA-test",
			Kind:            model.FindingKindVulnerability,
			PackageRef:      purl,
			Severity:        "high",
			Title:           "vuln",
			Source:          "osv",
		},
	}

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, findings, reg, "bomly", "test", SARIFOptions{IncludeReachability: true}); err != nil {
		t.Fatalf("WriteSARIF error: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}

	if !strings.Contains(buf.String(), `"codeFlows"`) {
		t.Errorf("expected codeFlows in SARIF output; got:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), `"reachability": "reachable"`) {
		t.Errorf("expected reachability property in SARIF output; got:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), `"main.go"`) {
		t.Errorf("expected call frame URI 'main.go'; got:\n%s", buf.String())
	}
}

func TestWriteSARIFOmitsReachabilityWhenDisabled(t *testing.T) {
	const purl = "pkg:go/lib@1.0.0"
	reg := fixtureRegistryWithVuln(purl, model.Vulnerability{
		ID:      "GHSA-test",
		FixedIn: "1.0.1",
		Reachability: &model.Reachability{
			Status: model.ReachabilityReachable,
			Tier:   model.TierSymbol,
			CallPaths: []model.CallPath{{
				Sink:   model.AffectedSymbol{Symbol: "Decode", Package: "lib"},
				Frames: []model.CallFrame{{Function: "main", Package: "main", Position: model.SourcePosition{File: "main.go", Line: 12}}},
			}},
		},
	})
	findings := []model.Finding{
		{
			ID:              "GHSA-test",
			VulnerabilityID: "GHSA-test",
			Kind:            model.FindingKindVulnerability,
			PackageRef:      purl,
			Severity:        "high",
			Title:           "vuln",
			Source:          "osv",
		},
	}

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, findings, reg, "bomly", "test", SARIFOptions{IncludeReachability: false}); err != nil {
		t.Fatalf("WriteSARIF error: %v", err)
	}
	if strings.Contains(buf.String(), `"codeFlows"`) {
		t.Errorf("codeFlows should be absent when reachability is disabled; got:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), `"reachability"`) {
		t.Errorf("reachability properties should be absent when disabled; got:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), `"fixed_in": "1.0.1"`) {
		t.Errorf("non-reachability SARIF properties should still be emitted; got:\n%s", buf.String())
	}
}

func TestWriteSARIFOmitsCodeFlowsWhenNoReachability(t *testing.T) {
	const purl = "pkg:go/lib@1.0.0"
	reg := fixtureRegistryWithVuln(purl, model.Vulnerability{ID: "X"})
	findings := []model.Finding{
		{ID: "X", VulnerabilityID: "X", Kind: model.FindingKindVulnerability, PackageRef: purl, Severity: "high", Title: "x", Source: "osv"},
	}
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, findings, reg, "bomly", "test"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), `"codeFlows"`) {
		t.Errorf("codeFlows should be absent when no reachability; got:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), `"properties"`) {
		t.Errorf("properties should be absent when no reachability; got:\n%s", buf.String())
	}
}
