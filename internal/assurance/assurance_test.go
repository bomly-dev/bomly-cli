package assurance

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var updateGoldens = flag.Bool("update", false, "rewrite golden files")

func loadFixture(t *testing.T, name string) []CheckResult {
	t.Helper()
	results, err := LoadResults(filepath.Join("testdata", "fixtures", name, "results"))
	if err != nil {
		t.Fatalf("load %s fixture: %v", name, err)
	}
	return results
}

func fixtureCatalog(t *testing.T) Catalog {
	t.Helper()
	catalog, err := LoadCatalog(filepath.Join("testdata", "catalog.json"))
	if err != nil {
		t.Fatalf("load fixture catalog: %v", err)
	}
	return catalog
}

func buildFixtureReport(t *testing.T, fixture string, previous *Report) Report {
	t.Helper()
	return BuildReport(fixtureCatalog(t), loadFixture(t, fixture), BuildOptions{
		Release:         Release{Tag: "v9.9.9", Version: "9.9.9", Commit: "0f2103c7e671653e519cf5edb0d3e86020202ecf"},
		Previous:        previous,
		IncludeEvidence: true,
		GeneratedBy:     "assurance-test",
		Now:             time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC),
	})
}

func TestStatusSeverityOrdering(t *testing.T) {
	ordered := []Status{StatusPass, StatusSkip, StatusMissing, StatusDegraded, StatusFail}
	for index := 1; index < len(ordered); index++ {
		if ordered[index].Severity() <= ordered[index-1].Severity() {
			t.Fatalf("%s must be more severe than %s", ordered[index], ordered[index-1])
		}
		if got := Worse(ordered[index-1], ordered[index]); got != ordered[index] {
			t.Fatalf("Worse(%s, %s) = %s", ordered[index-1], ordered[index], got)
		}
	}
}

func TestParseCheckResultRejectsInvalidDocuments(t *testing.T) {
	valid := CheckResult{
		SchemaVersion: CheckSchema, ID: "smoke", Instance: "go",
		Stage: StagePrerequisites, Level: LevelGate, Status: StatusPass,
		Summary: "18 of 18 tests passed.",
	}
	encoded, err := valid.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := ParseCheckResult(encoded); err != nil {
		t.Fatalf("valid result rejected: %v", err)
	}

	cases := map[string]func(*CheckResult){
		"bad schema":                func(r *CheckResult) { r.SchemaVersion = "other/v1" },
		"bad id":                    func(r *CheckResult) { r.ID = "Smoke Tests" },
		"bad instance":              func(r *CheckResult) { r.Instance = "go/../etc" },
		"bad stage":                 func(r *CheckResult) { r.Stage = "whenever" },
		"bad level":                 func(r *CheckResult) { r.Level = "critical" },
		"bad status":                func(r *CheckResult) { r.Status = "green" },
		"missing is not reportable": func(r *CheckResult) { r.Status = StatusMissing },
		"no summary":                func(r *CheckResult) { r.Summary = "  " },
		"bad detail status":         func(r *CheckResult) { r.Details = []Detail{{Name: "x", Status: "green"}} },
		"detail without name":       func(r *CheckResult) { r.Details = []Detail{{Name: "", Status: StatusPass}} },
		"link without url":          func(r *CheckResult) { r.Links = []Link{{Label: "run"}} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			broken := valid
			mutate(&broken)
			data, err := json.Marshal(broken)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if _, err := ParseCheckResult(data); err == nil {
				t.Fatal("expected the document to be rejected")
			}
		})
	}
}

func TestParseCheckResultRejectsUnknownFields(t *testing.T) {
	data := []byte(`{"schema_version":"bomly.assurance-check/v1","id":"smoke","stage":"prerequisites",` +
		`"status":"pass","summary":"ok","surprise":true}`)
	if _, err := ParseCheckResult(data); err == nil {
		t.Fatal("expected unknown fields to be rejected")
	}
}

func TestLoadResultsIgnoresForeignJSON(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "artifact")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "run-manifest.json"),
		[]byte(`{"schema_version":"bomly.benchmark-run/v1"}`), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	result := CheckResult{
		SchemaVersion: CheckSchema, ID: "fuzz", Stage: StagePrerequisites,
		Level: LevelAdvisory, Status: StatusPass, Summary: "28 targets ran.",
	}
	encoded, err := result.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := os.WriteFile(filepath.Join(nested, result.FileName()), encoded, 0o644); err != nil {
		t.Fatalf("write result: %v", err)
	}
	loaded, err := LoadResults(dir)
	if err != nil {
		t.Fatalf("load results: %v", err)
	}
	if len(loaded) != 1 || loaded[0].ID != "fuzz" {
		t.Fatalf("expected only the check result, got %+v", loaded)
	}
}

func TestBuildReportMergesInstancesAndFlagsGaps(t *testing.T) {
	report := buildFixtureReport(t, "mixed-failure", nil)

	smoke, found := report.Check("smoke")
	if !found {
		t.Fatal("smoke check missing from the report")
	}
	if smoke.Status != StatusMissing {
		t.Fatalf("smoke status = %s, want missing because one slice reported nothing", smoke.Status)
	}
	if len(smoke.MissingInstances) != 1 || smoke.MissingInstances[0] != "node" {
		t.Fatalf("missing instances = %v, want [node]", smoke.MissingInstances)
	}
	if report.Verdict.Overall != StatusMissing && report.Verdict.Overall != StatusFail {
		t.Fatalf("overall verdict = %s, want a blocking verdict", report.Verdict.Overall)
	}
	if !report.Verdict.Blocking() {
		t.Fatal("a failed gate check must block")
	}
	if len(report.Unknown) != 1 || report.Unknown[0].ID != "mystery-check" {
		t.Fatalf("unknown results = %+v, want the undeclared check", report.Unknown)
	}
	if len(report.Stages) != 3 {
		t.Fatalf("stages = %d, want 3", len(report.Stages))
	}
	for _, stage := range report.Stages {
		if stage.Title != stage.ID.Title() {
			t.Fatalf("stage %s title = %q", stage.ID, stage.Title)
		}
	}
}

func TestBuildReportPassesWhenEveryCheckReports(t *testing.T) {
	report := buildFixtureReport(t, "all-pass", nil)
	if report.Verdict.Overall != StatusPass {
		t.Fatalf("overall verdict = %s, want pass", report.Verdict.Overall)
	}
	if report.Verdict.Blocking() {
		t.Fatal("a passing report must not block")
	}
	smoke, _ := report.Check("smoke")
	if len(smoke.Instances) != 2 {
		t.Fatalf("smoke instances = %d, want 2", len(smoke.Instances))
	}
	if smoke.Metrics["tests_total"] != 42 {
		t.Fatalf("merged tests_total = %v, want 42", smoke.Metrics["tests_total"])
	}
	if len(report.Coverage.Ecosystems) != 2 {
		t.Fatalf("coverage ecosystems = %v", report.Coverage.Ecosystems)
	}
	if len(report.Evidence) != 1 || report.Evidence[0].Status != StatusPass {
		t.Fatalf("evidence = %+v, want the go graph claim passing", report.Evidence)
	}
}

func TestBuildReportAdvisoryFailureDegradesButDoesNotBlock(t *testing.T) {
	results := loadFixture(t, "all-pass")
	for index := range results {
		if results[index].ID == "perf-samples" {
			results[index].Status = StatusFail
		}
	}
	report := BuildReport(fixtureCatalog(t), results, BuildOptions{
		Release: Release{Tag: "v9.9.9"}, Now: time.Unix(0, 0).UTC(),
	})
	if report.Verdict.Overall != StatusDegraded {
		t.Fatalf("overall verdict = %s, want degraded", report.Verdict.Overall)
	}
	if report.Verdict.Blocking() {
		t.Fatal("an advisory failure must not block a release")
	}
}

func TestTrendsCompareMetricsAndStatuses(t *testing.T) {
	previous := buildFixtureReport(t, "all-pass", nil)
	current := buildFixtureReport(t, "mixed-failure", &previous)
	if current.Trends == nil {
		t.Fatal("expected trends against the previous release")
	}
	if current.Trends.PreviousTag != "v9.9.9" {
		t.Fatalf("previous tag = %q", current.Trends.PreviousTag)
	}
	var found bool
	for _, metric := range current.Trends.Metrics {
		if metric.CheckID == "perf-samples" && metric.Metric == "cold_median_ms" {
			found = true
			if metric.Delta != 293 {
				t.Fatalf("cold_median_ms delta = %v, want 293", metric.Delta)
			}
			if metric.Better != betterLower {
				t.Fatalf("cold_median_ms better = %q, want lower", metric.Better)
			}
		}
	}
	if !found {
		t.Fatal("expected a cold_median_ms trend")
	}
	if len(current.Trends.Changed) == 0 {
		t.Fatal("expected changed checks between the two fixtures")
	}
}

func TestReportGoldens(t *testing.T) {
	previous := buildFixtureReport(t, "all-pass", nil)
	for _, testCase := range []struct {
		name     string
		previous *Report
	}{
		{name: "all-pass"},
		{name: "mixed-failure", previous: &previous},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			report := buildFixtureReport(t, testCase.name, testCase.previous)
			encoded, err := report.Encode()
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			compareGolden(t, testCase.name+".report.json", encoded)
			markdown := RenderMarkdown(report, MarkdownOptions{IncludeChecks: true, IncludeTrends: true})
			compareGolden(t, testCase.name+".summary.md", []byte(markdown))

			// The report must survive a round trip through its own parser.
			if _, err := ParseReport(encoded); err != nil {
				t.Fatalf("parse encoded report: %v", err)
			}
		})
	}
}

func compareGolden(t *testing.T, name string, actual []byte) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name)
	if *updateGoldens {
		if err := os.WriteFile(path, actual, 0o644); err != nil {
			t.Fatalf("update golden: %v", err)
		}
		return
	}
	expected, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v (run go test ./internal/assurance -update)", name, err)
	}
	if string(expected) != string(actual) {
		t.Fatalf("golden %s differs; run go test ./internal/assurance -update to refresh", name)
	}
}

func TestParseGoTestEventsSummarisesRuns(t *testing.T) {
	stream := strings.Join([]string{
		`{"Action":"run","Package":"github.com/bomly-dev/bomly-cli/test/smoke","Test":"TestScan"}`,
		`{"Action":"output","Package":"github.com/bomly-dev/bomly-cli/test/smoke","Test":"TestScan","Output":"=== RUN\n"}`,
		`{"Action":"pass","Package":"github.com/bomly-dev/bomly-cli/test/smoke","Test":"TestScan/scan-go","Elapsed":41.5}`,
		`{"Action":"fail","Package":"github.com/bomly-dev/bomly-cli/test/smoke","Test":"TestScan/scan-npm","Elapsed":2}`,
		`{"Action":"skip","Package":"github.com/bomly-dev/bomly-cli/test/smoke","Test":"TestScan/scan-bun","Elapsed":0}`,
		`{"Action":"fail","Package":"github.com/bomly-dev/bomly-cli/test/smoke","Test":"TestScan","Elapsed":44}`,
		`{"Action":"fail","Package":"github.com/bomly-dev/bomly-cli/test/smoke","Elapsed":44}`,
		"go: downloading something",
	}, "\n")
	summary, err := ParseGoTestEvents(strings.NewReader(stream), nil)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if summary.Total != 4 || summary.Passed != 1 || summary.Failed != 2 || summary.Skipped != 1 {
		t.Fatalf("summary = %+v", summary)
	}
	if len(summary.Anomalies) != 1 {
		t.Fatalf("anomalies = %v, want the non-JSON line", summary.Anomalies)
	}
	result := summary.ToCheckResult(CheckResult{
		SchemaVersion: CheckSchema, ID: "smoke", Instance: "go",
		Stage: StagePrerequisites, Level: LevelGate,
	}, 1)
	if err := result.Validate(); err != nil {
		t.Fatalf("converted result invalid: %v", err)
	}
	if result.Status != StatusFail {
		t.Fatalf("status = %s, want fail", result.Status)
	}
	if result.Metrics["tests_failed"] != 2 {
		t.Fatalf("tests_failed = %v", result.Metrics["tests_failed"])
	}
}

func TestParseGoTestEventsBuildFailure(t *testing.T) {
	summary, err := ParseGoTestEvents(strings.NewReader("# github.com/example\nsyntax error\n"), nil)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	result := summary.ToCheckResult(CheckResult{
		SchemaVersion: CheckSchema, ID: "smoke", Stage: StagePrerequisites, Level: LevelGate,
	}, 2)
	if result.Status != StatusFail {
		t.Fatalf("status = %s, want fail when no test ran and the command failed", result.Status)
	}
	if !strings.Contains(result.Summary, "exited with code 2") {
		t.Fatalf("summary = %q", result.Summary)
	}
}

// TestGoTestZeroTestsFailsInsteadOfSkipping guards the case where a -run
// pattern stops matching: the command succeeds, no test runs, and the check
// must not be able to slide past a gate.
func TestGoTestZeroTestsFailsInsteadOfSkipping(t *testing.T) {
	summary, err := ParseGoTestEvents(strings.NewReader(""), nil)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	result := summary.ToCheckResult(CheckResult{
		SchemaVersion: CheckSchema, ID: "smoke", Instance: "go",
		Stage: StagePrerequisites, Level: LevelGate,
	}, 0)
	if result.Status != StatusFail {
		t.Fatalf("status = %s, want fail when no test ran", result.Status)
	}
	if !strings.Contains(result.Summary, "proved nothing") {
		t.Fatalf("summary = %q", result.Summary)
	}
}

// TestSkippedGateBlocks keeps a gate check that did not run from being counted
// as a pass.
func TestSkippedGateBlocks(t *testing.T) {
	results := loadFixture(t, "all-pass")
	for index := range results {
		if results[index].ID == "release-checksums" {
			results[index].Status = StatusSkip
		}
	}
	report := BuildReport(fixtureCatalog(t), results, BuildOptions{
		Release: Release{Tag: "v9.9.9"}, Now: time.Unix(0, 0).UTC(),
	})
	if !report.Verdict.Blocking() {
		t.Fatal("a skipped gate check must block a release")
	}
}

func TestMatchJobURLPicksTheRunningJobOnThisRunner(t *testing.T) {
	payload := []byte(`{"jobs":[
	  {"name":"Portable suite (ubuntu-latest)","status":"completed","runner_name":"GitHub Actions 3","html_url":"https://example.test/job/1"},
	  {"name":"Portable suite (macos-latest)","status":"in_progress","runner_name":"GitHub Actions 7","html_url":"https://example.test/job/2"},
	  {"name":"Portable suite (windows-latest)","status":"in_progress","runner_name":"GitHub Actions 9","html_url":"https://example.test/job/3"}
	]}`)
	url, err := MatchJobURL(payload, "GitHub Actions 7")
	if err != nil {
		t.Fatalf("match: %v", err)
	}
	if url != "https://example.test/job/2" {
		t.Fatalf("url = %q, want the running job on this runner", url)
	}

	for name, args := range map[string][2]string{
		"unknown runner": {string(payload), "GitHub Actions 42"},
		"no runner name": {string(payload), ""},
		"empty payload":  {`{"jobs":[]}`, "GitHub Actions 7"},
	} {
		t.Run(name, func(t *testing.T) {
			url, err := MatchJobURL([]byte(args[0]), args[1])
			if err != nil {
				t.Fatalf("match: %v", err)
			}
			if url != "" {
				t.Fatalf("url = %q, want no match so the caller links the run", url)
			}
		})
	}

	ambiguous := []byte(`{"jobs":[
	  {"name":"a","status":"in_progress","runner_name":"shared","html_url":"https://example.test/job/1"},
	  {"name":"b","status":"in_progress","runner_name":"shared","html_url":"https://example.test/job/2"}
	]}`)
	if url, err := MatchJobURL(ambiguous, "shared"); err != nil || url != "" {
		t.Fatalf("ambiguous match returned %q (err=%v), want no link", url, err)
	}

	if _, err := MatchJobURL([]byte("not json"), "runner"); err == nil {
		t.Fatal("expected malformed payload to be reported")
	}
}

// TestSchemaVersionsArePinned makes a schema change a deliberate act. The
// published reports are read by bomly.dev, which renders a known list of
// versions: adding an optional field keeps the version, while removing or
// repurposing one has to raise it and be taught to the site first.
func TestSchemaVersionsArePinned(t *testing.T) {
	for name, actual := range map[string]string{
		"check":   CheckSchema,
		"catalog": CatalogSchema,
		"report":  ReportSchema,
		"index":   IndexSchema,
	} {
		expected := map[string]string{
			"check":   "bomly.assurance-check/v1",
			"catalog": "bomly.assurance-catalog/v1",
			"report":  "bomly.assurance-report/v1",
			"index":   "bomly.assurance-index/v1",
		}[name]
		if actual != expected {
			t.Errorf("%s schema is %q, want %q; raising it requires teaching bomly.dev the new shape first "+
				"(SUPPORTED_REPORT_SCHEMAS in lib/assurance.ts and REPORT_SCHEMAS in scripts/sync-assurance.mjs)",
				name, actual, expected)
		}
	}
}
