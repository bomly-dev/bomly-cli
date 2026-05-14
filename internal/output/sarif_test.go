package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestWriteSARIF_ValidDocument(t *testing.T) {
	pkg := &sdk.Package{Name: "lodash", Version: "4.17.15"}
	findings := []sdk.Finding{
		{
			ID:       "CVE-2021-23337",
			Kind:     sdk.FindingKindVulnerability,
			Package:  pkg,
			Title:    "Prototype pollution in lodash",
			Severity: "high",
			Reasons:  []string{"Fix available: upgrade to 4.17.21"},
			Source:   "osv",
		},
		{
			ID:       "CVE-2020-8203",
			Kind:     sdk.FindingKindVulnerability,
			Package:  pkg,
			Title:    "Prototype pollution",
			Severity: "critical",
			Source:   "osv",
		},
	}

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, findings, "bomly", "0.9.0-test"); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}

	// Must be valid JSON.
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("WriteSARIF output is not valid JSON: %v\noutput: %s", err, buf.String())
	}

	// Schema version
	if doc["version"] != "2.1.0" {
		t.Errorf("version = %v, want 2.1.0", doc["version"])
	}

	// Runs slice must have one run.
	runs, ok := doc["runs"].([]any)
	if !ok || len(runs) == 0 {
		t.Fatal("expected at least one run in SARIF output")
	}

	run, ok := runs[0].(map[string]any)
	if !ok {
		t.Fatal("expected runs[0] to be a map")
	}

	// Validate tool driver name.
	tool, _ := run["tool"].(map[string]any)
	driver, _ := tool["driver"].(map[string]any)
	if driver["name"] != "bomly" {
		t.Errorf("tool.driver.name = %v, want bomly", driver["name"])
	}

	// Validate rules deduplication: 2 findings → 2 rules.
	rules, _ := driver["rules"].([]any)
	if len(rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(rules))
	}

	// Validate results count matches findings.
	results, _ := run["results"].([]any)
	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}
}

func TestWriteSARIF_RuleDeduplication(t *testing.T) {
	pkg := &sdk.Package{Name: "lodash", Version: "4.17.15"}
	// Same finding ID appears twice (e.g. affects two packages).
	findings := []sdk.Finding{
		{ID: "CVE-2021-23337", Package: pkg, Title: "Pollution", Severity: "high", Source: "osv"},
		{ID: "CVE-2021-23337", Package: pkg, Title: "Pollution", Severity: "high", Source: "osv"},
	}

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, findings, "bomly", "0.1.0"); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	runs := doc["runs"].([]any)
	run := runs[0].(map[string]any)
	tool := run["tool"].(map[string]any)
	driver := tool["driver"].(map[string]any)
	rules := driver["rules"].([]any)
	if len(rules) != 1 {
		t.Errorf("expected 1 deduplicated rule, got %d", len(rules))
	}

	// Two results (one per finding), but only one rule.
	results := run["results"].([]any)
	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}
}

func TestSeverityToSARIFLevel(t *testing.T) {
	tests := []struct {
		sev   string
		level string
	}{
		{"critical", "error"},
		{"high", "error"},
		{"medium", "warning"},
		{"low", "note"},
		{"unknown", "note"},
		{"", "note"},
	}
	for _, tt := range tests {
		got := severityToSARIFLevel(tt.sev)
		if got != tt.level {
			t.Errorf("severityToSARIFLevel(%q) = %q, want %q", tt.sev, got, tt.level)
		}
	}
}

func TestWriteSARIF_OSVHelpURI(t *testing.T) {
	pkg := &sdk.Package{Name: "lodash", Version: "4.17.15"}
	findings := []sdk.Finding{
		{ID: "CVE-2021-23337", Package: pkg, Title: "Vuln", Severity: "high", Source: "osv"},
	}
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, findings, "bomly", "0.1.0"); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	if !strings.Contains(buf.String(), "osv.dev/vulnerability/CVE-2021-23337") {
		t.Error("expected OSV help URI in SARIF output")
	}
}

func TestWriteSARIF_EmitsRegionFromPackageLocation(t *testing.T) {
	pkg := &sdk.Package{
		Name:    "lodash",
		Version: "4.17.15",
		Locations: []sdk.PackageLocation{
			{
				RealPath:   "package-lock.json",
				AccessPath: "package-lock.json",
				Position: &sdk.SourcePosition{
					File: "package-lock.json",
					Line: 142,
				},
			},
		},
	}
	findings := []sdk.Finding{
		{ID: "CVE-2021-23337", Kind: sdk.FindingKindVulnerability, Package: pkg, Title: "Vuln", Severity: "high", Source: "osv"},
	}

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, findings, "bomly", "0.1.0"); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	results := doc["runs"].([]any)[0].(map[string]any)["results"].([]any)
	if len(results) != 1 {
		t.Fatalf("results = %d, want 1", len(results))
	}
	locations := results[0].(map[string]any)["locations"].([]any)
	if len(locations) != 1 {
		t.Fatalf("locations = %d, want 1", len(locations))
	}
	pl := locations[0].(map[string]any)["physicalLocation"].(map[string]any)
	if pl["artifactLocation"].(map[string]any)["uri"] != "package-lock.json" {
		t.Errorf("artifactLocation.uri = %v, want package-lock.json", pl["artifactLocation"])
	}
	region, ok := pl["region"].(map[string]any)
	if !ok {
		t.Fatal("expected physicalLocation.region")
	}
	if region["startLine"] != float64(142) {
		t.Errorf("region.startLine = %v, want 142", region["startLine"])
	}
}

func TestWriteSARIF_EmitsMultipleLocationsWhenPackageHasSeveral(t *testing.T) {
	pkg := &sdk.Package{
		Name:    "express",
		Version: "4.18.0",
		Locations: []sdk.PackageLocation{
			{RealPath: "package-lock.json", Position: &sdk.SourcePosition{File: "package-lock.json", Line: 50}},
			{RealPath: "apps/api/package-lock.json", Position: &sdk.SourcePosition{File: "apps/api/package-lock.json", Line: 12}},
		},
	}
	findings := []sdk.Finding{
		{ID: "CVE-test", Kind: sdk.FindingKindVulnerability, Package: pkg, Title: "Vuln", Severity: "high"},
	}
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, findings, "bomly", "0.1.0"); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	var doc map[string]any
	_ = json.Unmarshal(buf.Bytes(), &doc)
	locations := doc["runs"].([]any)[0].(map[string]any)["results"].([]any)[0].(map[string]any)["locations"].([]any)
	if len(locations) != 2 {
		t.Fatalf("locations = %d, want 2", len(locations))
	}
}

func TestWriteSARIF_FallsBackToPackageNameWhenNoLocations(t *testing.T) {
	pkg := &sdk.Package{Name: "lodash", Version: "4.17.15"}
	findings := []sdk.Finding{
		{ID: "CVE-2021-23337", Kind: sdk.FindingKindVulnerability, Package: pkg, Title: "Vuln", Severity: "high"},
	}
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, findings, "bomly", "0.1.0"); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	var doc map[string]any
	_ = json.Unmarshal(buf.Bytes(), &doc)
	pl := doc["runs"].([]any)[0].(map[string]any)["results"].([]any)[0].(map[string]any)["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)
	if pl["artifactLocation"].(map[string]any)["uri"] != "lodash" {
		t.Errorf("fallback uri = %v, want package qualified name", pl["artifactLocation"])
	}
	if _, hasRegion := pl["region"]; hasRegion {
		t.Errorf("fallback location should have no region")
	}
}

func TestWriteSARIF_LocationWithoutPositionSkipsRegion(t *testing.T) {
	pkg := &sdk.Package{
		Name:    "lodash",
		Version: "4.17.15",
		Locations: []sdk.PackageLocation{
			{RealPath: "package-lock.json"},
		},
	}
	findings := []sdk.Finding{
		{ID: "CVE-2021-23337", Kind: sdk.FindingKindVulnerability, Package: pkg, Title: "Vuln", Severity: "high"},
	}
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, findings, "bomly", "0.1.0"); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	var doc map[string]any
	_ = json.Unmarshal(buf.Bytes(), &doc)
	pl := doc["runs"].([]any)[0].(map[string]any)["results"].([]any)[0].(map[string]any)["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)
	if pl["artifactLocation"].(map[string]any)["uri"] != "package-lock.json" {
		t.Errorf("uri = %v, want package-lock.json", pl["artifactLocation"])
	}
	if _, hasRegion := pl["region"]; hasRegion {
		t.Error("location without Position should not have a region")
	}
}
