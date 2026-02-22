package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	model "github.com/bomly-dev/bomly-cli/sdk"
)

func TestWriteSARIF_ValidDocument(t *testing.T) {
	pkg := &model.Package{Name: "lodash", Version: "4.17.15"}
	findings := []model.Finding{
		{
			ID:       "CVE-2021-23337",
			Kind:     model.FindingKindVulnerability,
			Package:  pkg,
			Title:    "Prototype pollution in lodash",
			Severity: "high",
			Reasons:  []string{"Fix available: upgrade to 4.17.21"},
			Source:   "osv",
		},
		{
			ID:       "CVE-2020-8203",
			Kind:     model.FindingKindVulnerability,
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
	pkg := &model.Package{Name: "lodash", Version: "4.17.15"}
	// Same finding ID appears twice (e.g. affects two packages).
	findings := []model.Finding{
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
	pkg := &model.Package{Name: "lodash", Version: "4.17.15"}
	findings := []model.Finding{
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
