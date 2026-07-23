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
			Severity:   sdk.SeverityHigh,
			Reasons:    []string{"Fix available: upgrade to 4.17.21"},
			Source:     "osv",
		},
		{
			ID:         "CVE-2020-8203",
			Kind:       sdk.FindingKindVulnerability,
			PackageRef: sarifTestPURL,
			Title:      "Prototype pollution",
			Severity:   sdk.SeverityCritical,
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
		{ID: "CVE-2021-23337", PackageRef: sarifTestPURL, Title: "Pollution", Severity: sdk.SeverityHigh, Source: "osv"},
		{ID: "CVE-2021-23337", PackageRef: sarifTestPURL, Title: "Pollution", Severity: sdk.SeverityHigh, Source: "osv"},
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

func TestDispositionToSARIFLevel(t *testing.T) {
	tests := []struct {
		disposition sdk.FindingDisposition
		level       string
	}{
		{sdk.FindingDispositionFail, "error"},
		{sdk.FindingDispositionWarn, "warning"},
		{sdk.FindingDispositionSuppressed, "note"},
		{"", "error"}, // unset disposition is treated as failing, like FailingFindingCount
	}
	for _, tt := range tests {
		got := dispositionToSARIFLevel(tt.disposition)
		if got != tt.level {
			t.Errorf("dispositionToSARIFLevel(%q) = %q, want %q", tt.disposition, got, tt.level)
		}
	}
}

// TestSARIFLevelIgnoresSeverity locks in the point that job impact and
// severity are orthogonal: a Low-severity finding that fails the build is
// still "error", and a Critical one that's only a warning is still "warning".
func TestSARIFLevelIgnoresSeverity(t *testing.T) {
	findings := []sdk.Finding{
		{ID: "fail-low", PackageRef: sarifTestPURL, Title: "x", Severity: sdk.SeverityLow, Disposition: sdk.FindingDispositionFail},
		{ID: "warn-critical", PackageRef: sarifTestPURL, Title: "y", Severity: sdk.SeverityCritical, Disposition: sdk.FindingDispositionWarn},
	}
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, findings, nil, "bomly", "0.1.0"); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	var doc sarifLog
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("decode SARIF: %v\n%s", err, buf.String())
	}
	byID := map[string]sarifRule{}
	for _, r := range doc.Runs[0].Tool.Driver.Rules {
		byID[r.ID] = r
	}
	if got := byID["fail-low"].DefaultConfig.Level; got != "error" {
		t.Errorf("low-severity failing finding level = %q, want error", got)
	}
	if got := byID["warn-critical"].DefaultConfig.Level; got != "warning" {
		t.Errorf("critical-severity warning finding level = %q, want warning", got)
	}
}

func TestWriteSARIF_SecuritySeverityAndFormattedHelp(t *testing.T) {
	findings := []sdk.Finding{
		{
			ID:         "CVE-2025-48924",
			Kind:       sdk.FindingKindVulnerability,
			PackageRef: sarifTestPURL,
			Title:      "Uncontrolled recursion in commons-lang",
			Severity:   sdk.SeverityMedium,
			Source:     "osv",
			Reasons: []string{
				"Fix available: upgrade to 3.18.0",
				"Also known as: CVE-2025-48924",
				"https://nvd.nist.gov/vuln/detail/CVE-2025-48924",
			},
		},
		{
			ID:          "INVALID-abcd-efgh-ijkl",
			Kind:        sdk.FindingKindLicense,
			PackageRef:  sarifTestPURL,
			Title:       "Package has invalid SPDX license: non-standard",
			Severity:    sdk.SeverityWarning,
			Disposition: sdk.FindingDispositionWarn,
			Source:      "license",
		},
	}

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, findings, nil, "bomly", "0.1.0"); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}

	var doc sarifLog
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("decode SARIF: %v\n%s", err, buf.String())
	}
	rules := doc.Runs[0].Tool.Driver.Rules
	byID := map[string]sarifRule{}
	for _, r := range rules {
		byID[r.ID] = r
	}

	vuln, ok := byID["CVE-2025-48924"]
	if !ok {
		t.Fatal("missing vulnerability rule")
	}
	if vuln.Properties == nil || vuln.Properties.SecuritySeverity != "5.5" {
		t.Fatalf("vuln security-severity = %+v, want 5.5 (medium midpoint)", vuln.Properties)
	}
	if vuln.Properties == nil || len(vuln.Properties.Tags) == 0 || vuln.Properties.Tags[0] != "security" {
		t.Fatalf("vuln rule should carry the security tag, got %+v", vuln.Properties)
	}
	if !strings.Contains(vuln.FullDescription.Markdown, "- Fix available: upgrade to 3.18.0") {
		t.Errorf("expected bulleted fact in markdown, got %q", vuln.FullDescription.Markdown)
	}
	if !strings.Contains(vuln.FullDescription.Markdown, "**References**") || !strings.Contains(vuln.FullDescription.Markdown, "nvd.nist.gov") {
		t.Errorf("expected references section in markdown, got %q", vuln.FullDescription.Markdown)
	}

	lic, ok := byID["INVALID-abcd-efgh-ijkl"]
	if !ok {
		t.Fatal("missing license rule")
	}
	if lic.Properties != nil {
		t.Errorf("license rule should not carry security-severity, got %+v", lic.Properties)
	}
	if lic.DefaultConfig.Level != "warning" {
		t.Errorf("license rule level = %q, want warning", lic.DefaultConfig.Level)
	}
}

func TestWriteSARIF_OSVHelpURI(t *testing.T) {
	findings := []sdk.Finding{
		{ID: "CVE-2021-23337", PackageRef: sarifTestPURL, Title: "Vuln", Severity: sdk.SeverityHigh, Source: "osv"},
	}
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, findings, nil, "bomly", "0.1.0"); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	if !strings.Contains(buf.String(), "osv.dev/vulnerability/CVE-2021-23337") {
		t.Error("expected OSV help URI in SARIF output")
	}
}

func TestWriteSARIF_EmitsBaselineStateAndStableFingerprint(t *testing.T) {
	findings := []sdk.Finding{
		{ID: "BOMLY-LIC-UNKNOWN", Kind: sdk.FindingKindLicense, PackageRef: sarifTestPURL, Title: "Package license is unknown", Severity: sdk.SeverityLow, Source: "license"},
	}
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, findings, nil, "bomly", "0.1.0", SARIFOptions{BaselineState: "new"}); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	result := doc["runs"].([]any)[0].(map[string]any)["results"].([]any)[0].(map[string]any)
	if got := result["baselineState"]; got != "new" {
		t.Fatalf("baselineState = %v, want new", got)
	}
	fingerprints := result["partialFingerprints"].(map[string]any)
	if got := fingerprints["bomlyStableId/v1"]; got == "" {
		t.Fatalf("expected stable fingerprint, got %#v", fingerprints)
	}
}

// TestWriteSARIF_LocationsFallBackToRepoFile verifies the writer uses a
// GitHub-compatible repository file when no richer dependency location is
// available. Package identity stays in the SARIF properties bag.
func TestWriteSARIF_LocationsFallBackToRepoFile(t *testing.T) {
	findings := []sdk.Finding{
		{ID: "CVE-2021-23337", Kind: sdk.FindingKindVulnerability, PackageRef: sarifTestPURL, Title: "Vuln", Severity: sdk.SeverityHigh},
	}
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, findings, nil, "bomly", "0.1.0"); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	var doc map[string]any
	_ = json.Unmarshal(buf.Bytes(), &doc)
	result := doc["runs"].([]any)[0].(map[string]any)["results"].([]any)[0].(map[string]any)
	pl := result["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)
	if pl["artifactLocation"].(map[string]any)["uri"] != "README.md" {
		t.Errorf("fallback uri = %v, want README.md", pl["artifactLocation"])
	}
	if _, hasRegion := pl["region"]; hasRegion {
		t.Errorf("fallback location should have no region")
	}
	props := result["properties"].(map[string]any)
	if props["package_ref"] != sarifTestPURL {
		t.Errorf("package_ref property = %v, want %s", props["package_ref"], sarifTestPURL)
	}
	locationURIs := props["location_uris"].([]any)
	if len(locationURIs) != 1 || locationURIs[0] != sarifTestPURL {
		t.Errorf("location_uris = %#v, want [%s]", locationURIs, sarifTestPURL)
	}
}

func TestWriteSARIF_UsesDependencyLocationsFromGraph(t *testing.T) {
	graph := sdk.New()
	dep := sdk.NewDependencyWithID("lodash@4.17.15", sdk.Dependency{Coordinates: sdk.Coordinates{Name: "lodash"}, PackageRef: sarifTestPURL,
		Locations: []sdk.PackageLocation{
			{
				RealPath: "package-lock.json",
				Position: &sdk.SourcePosition{
					File:    "package-lock.json",
					Line:    42,
					Column:  5,
					EndLine: 42,
				},
			},
		},
	})
	if err := graph.AddNode(dep); err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	findings := []sdk.Finding{
		{
			ID:             "CVE-2021-23337",
			Kind:           sdk.FindingKindVulnerability,
			PackageRef:     sarifTestPURL,
			DependencyRefs: []string{dep.ID},
			Title:          "Vuln",
			Severity:       sdk.SeverityHigh,
		},
	}

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, findings, nil, "bomly", "0.1.0", SARIFOptions{LocationGraphs: []*sdk.Graph{graph}}); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	var doc map[string]any
	_ = json.Unmarshal(buf.Bytes(), &doc)
	result := doc["runs"].([]any)[0].(map[string]any)["results"].([]any)[0].(map[string]any)
	pl := result["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)
	if pl["artifactLocation"].(map[string]any)["uri"] != "package-lock.json" {
		t.Errorf("location uri = %v, want package-lock.json", pl["artifactLocation"])
	}
	region := pl["region"].(map[string]any)
	if region["startLine"] != float64(42) || region["startColumn"] != float64(5) {
		t.Errorf("region = %#v, want line 42 column 5", region)
	}
	props := result["properties"].(map[string]any)
	if refs := props["dependency_refs"].([]any); len(refs) != 1 || refs[0] != dep.ID {
		t.Errorf("dependency_refs = %#v, want [%s]", refs, dep.ID)
	}
}

// TestWriteSARIF_UnionsLocationsAcrossGraphs pins the multi-module regression:
// when the same dependency ref resolves to distinct node instances across
// entry graphs (a gradle `api` dependency appears in both the declaring
// subproject's graph and each consumer's graph) and only a later graph's
// instance carries manifest locations, the located instance must win instead
// of the location-less first match falling back to the repository file.
func TestWriteSARIF_UnionsLocationsAcrossGraphs(t *testing.T) {
	consumer := sdk.New()
	bare := sdk.NewDependencyWithID("org.apache.commons:commons-text@1.9", sdk.Dependency{
		Coordinates: sdk.Coordinates{Name: "commons-text"},
		PackageRef:  sarifTestPURL,
	})
	if err := consumer.AddNode(bare); err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	declaring := sdk.New()
	located := sdk.NewDependencyWithID("org.apache.commons:commons-text@1.9", sdk.Dependency{
		Coordinates: sdk.Coordinates{Name: "commons-text"},
		PackageRef:  sarifTestPURL,
		Locations: []sdk.PackageLocation{
			{
				RealPath: "lib/build.gradle",
				Position: &sdk.SourcePosition{File: "lib/build.gradle", Line: 7},
			},
		},
	})
	if err := declaring.AddNode(located); err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	findings := []sdk.Finding{
		{
			ID:             "CVE-2022-42889",
			Kind:           sdk.FindingKindVulnerability,
			PackageRef:     sarifTestPURL,
			DependencyRefs: []string{bare.ID},
			Title:          "Vuln",
			Severity:       sdk.SeverityCritical,
		},
	}

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, findings, nil, "bomly", "0.1.0", SARIFOptions{LocationGraphs: []*sdk.Graph{consumer, declaring}}); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	var doc map[string]any
	_ = json.Unmarshal(buf.Bytes(), &doc)
	result := doc["runs"].([]any)[0].(map[string]any)["results"].([]any)[0].(map[string]any)
	locations := result["locations"].([]any)
	if len(locations) != 1 {
		t.Fatalf("locations = %#v, want exactly the declaring module location", locations)
	}
	pl := locations[0].(map[string]any)["physicalLocation"].(map[string]any)
	if uri := pl["artifactLocation"].(map[string]any)["uri"]; uri != "lib/build.gradle" {
		t.Errorf("location uri = %v, want lib/build.gradle", uri)
	}
	if region := pl["region"].(map[string]any); region["startLine"] != float64(7) {
		t.Errorf("region = %#v, want startLine 7", region)
	}
}

func TestWriteSARIF_PrefersLocationIntersectingChangedLines(t *testing.T) {
	graph := sdk.New()
	dep := sdk.NewDependencyWithID("actions:checkout@v5", sdk.Dependency{Coordinates: sdk.Coordinates{Name: "actions/checkout"}, PackageRef: "actions:checkout@v5",
		Locations: []sdk.PackageLocation{
			{RealPath: ".github/workflows/old.yml", Position: &sdk.SourcePosition{File: ".github/workflows/old.yml", Line: 4}},
			{RealPath: ".github/workflows/guard.yml", Position: &sdk.SourcePosition{File: ".github/workflows/guard.yml", Line: 12}},
		},
	})
	if err := graph.AddNode(dep); err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	finding := sdk.Finding{ID: "policy:actions", PackageRef: dep.PackageRef, DependencyRefs: []string{dep.ID}, Title: "Denied action"}

	var buf bytes.Buffer
	err := WriteSARIF(&buf, []sdk.Finding{finding}, nil, "bomly", "0.1.0", SARIFOptions{
		LocationGraphs: []*sdk.Graph{graph},
		ChangedLines: map[string][]SARIFLineRange{
			".github/workflows/guard.yml": {{Start: 12, End: 12}},
		},
	})
	if err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	var doc sarifLog
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("decode SARIF: %v\n%s", err, buf.String())
	}
	locations := doc.Runs[0].Results[0].Locations
	if len(locations) != 1 {
		t.Fatalf("locations = %d, want only changed-line location", len(locations))
	}
	if got := locations[0].PhysicalLocation.ArtifactLocation.URI; got != ".github/workflows/guard.yml" {
		t.Fatalf("location uri = %q, want changed workflow", got)
	}
}

func TestWriteSARIF_PrefersChangedFileWhenLineDoesNotIntersect(t *testing.T) {
	graph := sdk.New()
	dep := sdk.NewDependencyWithID("lodash@4.17.21", sdk.Dependency{Coordinates: sdk.Coordinates{Name: "lodash"}, PackageRef: sarifTestPURL,
		Locations: []sdk.PackageLocation{
			{RealPath: "package-lock.json", Position: &sdk.SourcePosition{File: "package-lock.json", Line: 8}},
			{RealPath: "package.json", Position: &sdk.SourcePosition{File: "package.json", Line: 22}},
		},
	})
	if err := graph.AddNode(dep); err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	finding := sdk.Finding{ID: "CVE-2021-23337", PackageRef: dep.PackageRef, DependencyRefs: []string{dep.ID}, Title: "Vuln"}

	var buf bytes.Buffer
	err := WriteSARIF(&buf, []sdk.Finding{finding}, nil, "bomly", "0.1.0", SARIFOptions{
		LocationGraphs: []*sdk.Graph{graph},
		ChangedLines: map[string][]SARIFLineRange{
			"package.json": {{Start: 30, End: 30}},
		},
	})
	if err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	var doc sarifLog
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("decode SARIF: %v\n%s", err, buf.String())
	}
	locations := doc.Runs[0].Results[0].Locations
	if len(locations) != 1 {
		t.Fatalf("locations = %d, want only changed-file location", len(locations))
	}
	if got := locations[0].PhysicalLocation.ArtifactLocation.URI; got != "package.json" {
		t.Fatalf("location uri = %q, want changed file", got)
	}
}

func TestWriteSARIF_SelectsChangedLocationsPerDependency(t *testing.T) {
	graph := sdk.New()
	touched := sdk.NewDependencyWithID("lodash@4.17.21", sdk.Dependency{Coordinates: sdk.Coordinates{Name: "lodash"}, PackageRef: "pkg:npm/lodash@4.17.21",
		Locations: []sdk.PackageLocation{
			{RealPath: "package-lock.json", Position: &sdk.SourcePosition{File: "package-lock.json", Line: 9}},
			{RealPath: "package.json", Position: &sdk.SourcePosition{File: "package.json", Line: 22}},
		},
	})
	unchanged := sdk.NewDependencyWithID("minimist@1.2.8", sdk.Dependency{Coordinates: sdk.Coordinates{Name: "minimist"}, PackageRef: "pkg:npm/minimist@1.2.8",
		Locations: []sdk.PackageLocation{
			{RealPath: "yarn.lock", Position: &sdk.SourcePosition{File: "yarn.lock", Line: 33}},
		},
	})
	if err := graph.AddNode(touched); err != nil {
		t.Fatalf("AddNode touched: %v", err)
	}
	if err := graph.AddNode(unchanged); err != nil {
		t.Fatalf("AddNode unchanged: %v", err)
	}
	finding := sdk.Finding{
		ID:             "policy:multi",
		PackageRef:     touched.PackageRef,
		DependencyRefs: []string{touched.ID, unchanged.ID},
		Title:          "Denied package set",
	}

	var buf bytes.Buffer
	err := WriteSARIF(&buf, []sdk.Finding{finding}, nil, "bomly", "0.1.0", SARIFOptions{
		LocationGraphs: []*sdk.Graph{graph},
		ChangedLines: map[string][]SARIFLineRange{
			"package.json": {{Start: 22, End: 22}},
		},
	})
	if err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	var doc sarifLog
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("decode SARIF: %v\n%s", err, buf.String())
	}
	locations := doc.Runs[0].Results[0].Locations
	if len(locations) != 2 {
		t.Fatalf("locations = %d, want changed touched dep plus unchanged dep", len(locations))
	}
	got := map[string]int{}
	for _, loc := range locations {
		got[loc.PhysicalLocation.ArtifactLocation.URI] = loc.PhysicalLocation.Region.StartLine
	}
	if got["package.json"] != 22 {
		t.Fatalf("locations = %#v, want package.json line 22", got)
	}
	if got["yarn.lock"] != 33 {
		t.Fatalf("locations = %#v, want yarn.lock line 33", got)
	}
	if _, hasOld := got["package-lock.json"]; hasOld {
		t.Fatalf("locations = %#v, did not expect non-changed candidate for touched dep", got)
	}
}

func TestWriteSARIF_RewritesNonFileLocationSchemes(t *testing.T) {
	graph := sdk.New()
	dep := sdk.NewDependencyWithID("actions:checkout@v5", sdk.Dependency{Coordinates: sdk.Coordinates{Name: "actions/checkout"}, PackageRef: "actions:checkout@v5",
		Locations: []sdk.PackageLocation{{RealPath: "actions:checkout@v5"}},
	})
	if err := graph.AddNode(dep); err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	findings := []sdk.Finding{
		{
			ID:             "policy:actions",
			Kind:           sdk.FindingKindPackage,
			PackageRef:     "actions:checkout@v5",
			DependencyRefs: []string{dep.ID},
			Title:          "Denied action",
			Severity:       sdk.SeverityHigh,
		},
	}

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, findings, nil, "bomly", "0.1.0", SARIFOptions{LocationGraphs: []*sdk.Graph{graph}}); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	var doc map[string]any
	_ = json.Unmarshal(buf.Bytes(), &doc)
	result := doc["runs"].([]any)[0].(map[string]any)["results"].([]any)[0].(map[string]any)
	pl := result["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)
	if pl["artifactLocation"].(map[string]any)["uri"] != "README.md" {
		t.Errorf("non-file scheme uri = %v, want README.md", pl["artifactLocation"])
	}
	props := result["properties"].(map[string]any)
	locationURIs := props["location_uris"].([]any)
	if len(locationURIs) != 1 || locationURIs[0] != "actions:checkout@v5" {
		t.Errorf("location_uris = %#v, want [actions:checkout@v5]", locationURIs)
	}
}
