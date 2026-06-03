package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

const sarifTestPURL = "pkg:npm/lodash@4.17.15"

func TestWriteSARIF_ValidDocument(t *testing.T) {
	findings := []sdk.Finding{
		{
			ID:         "CVE-2021-23337",
			Kind:       sdk.FindingKindVulnerability,
			PackageRef: sarifTestPURL,
			Title:      "Prototype pollution in lodash",
			Severity:   "high",
			Reasons:    []string{"Fix available: upgrade to 4.17.21"},
			Source:     "osv",
		},
		{
			ID:         "CVE-2020-8203",
			Kind:       sdk.FindingKindVulnerability,
			PackageRef: sarifTestPURL,
			Title:      "Prototype pollution",
			Severity:   "critical",
			Source:     "osv",
		},
	}

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, findings, nil, "bomly", "0.9.0-test"); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("WriteSARIF output is not valid JSON: %v\noutput: %s", err, buf.String())
	}

	if doc["version"] != "2.1.0" {
		t.Errorf("version = %v, want 2.1.0", doc["version"])
	}

	runs, ok := doc["runs"].([]any)
	if !ok || len(runs) == 0 {
		t.Fatal("expected at least one run in SARIF output")
	}

	run, ok := runs[0].(map[string]any)
	if !ok {
		t.Fatal("expected runs[0] to be a map")
	}

	tool, _ := run["tool"].(map[string]any)
	driver, _ := tool["driver"].(map[string]any)
	if driver["name"] != "bomly" {
		t.Errorf("tool.driver.name = %v, want bomly", driver["name"])
	}

	rules, _ := driver["rules"].([]any)
	if len(rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(rules))
	}

	results, _ := run["results"].([]any)
	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}
}

func TestWriteSARIF_RuleDeduplication(t *testing.T) {
	findings := []sdk.Finding{
		{ID: "CVE-2021-23337", PackageRef: sarifTestPURL, Title: "Pollution", Severity: "high", Source: "osv"},
		{ID: "CVE-2021-23337", PackageRef: sarifTestPURL, Title: "Pollution", Severity: "high", Source: "osv"},
	}

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, findings, nil, "bomly", "0.1.0"); err != nil {
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

	results := run["results"].([]any)
	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}
}

func TestWriteSARIF_EmptyFindingsEncodeArrayFields(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, nil, nil, "bomly", "0.1.0"); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	run := doc["runs"].([]any)[0].(map[string]any)
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	rules, ok := driver["rules"].([]any)
	if !ok {
		t.Fatalf("tool.driver.rules has type %T, want array; output:\n%s", driver["rules"], buf.String())
	}
	if len(rules) != 0 {
		t.Fatalf("rules = %d, want 0", len(rules))
	}
	results, ok := run["results"].([]any)
	if !ok {
		t.Fatalf("results has type %T, want array; output:\n%s", run["results"], buf.String())
	}
	if len(results) != 0 {
		t.Fatalf("results = %d, want 0", len(results))
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
	findings := []sdk.Finding{
		{ID: "CVE-2021-23337", PackageRef: sarifTestPURL, Title: "Vuln", Severity: "high", Source: "osv"},
	}
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, findings, nil, "bomly", "0.1.0"); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	if !strings.Contains(buf.String(), "osv.dev/vulnerability/CVE-2021-23337") {
		t.Error("expected OSV help URI in SARIF output")
	}
}

// TestWriteSARIF_LocationsFallBackToPURL verifies the writer synthesizes a
// SARIF location keyed on the PackageRef PURL when nothing richer is
// available. Per-dependency file/line locations are a detection-time concern
// on *sdk.Dependency; the registry Package carries the PURL identity, which
// the writer uses as the synthetic SARIF URI.
func TestWriteSARIF_LocationsFallBackToPURL(t *testing.T) {
	findings := []sdk.Finding{
		{ID: "CVE-2021-23337", Kind: sdk.FindingKindVulnerability, PackageRef: sarifTestPURL, Title: "Vuln", Severity: "high"},
	}
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, findings, nil, "bomly", "0.1.0"); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	var doc map[string]any
	_ = json.Unmarshal(buf.Bytes(), &doc)
	pl := doc["runs"].([]any)[0].(map[string]any)["results"].([]any)[0].(map[string]any)["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)
	if pl["artifactLocation"].(map[string]any)["uri"] != sarifTestPURL {
		t.Errorf("fallback uri = %v, want %s", pl["artifactLocation"], sarifTestPURL)
	}
	if _, hasRegion := pl["region"]; hasRegion {
		t.Errorf("fallback location should have no region")
	}
}
