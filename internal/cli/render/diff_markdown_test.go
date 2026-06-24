package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestHumanizeDurationMS(t *testing.T) {
	cases := []struct {
		ms   int64
		want string
	}{
		{0, "0ms"},
		{250, "250ms"},
		{1500, "1.5s"},
		{66953, "1m 6s"},
	}
	for _, tc := range cases {
		if got := humanizeDurationMS(tc.ms); got != tc.want {
			t.Errorf("humanizeDurationMS(%d) = %q, want %q", tc.ms, got, tc.want)
		}
	}
}

func TestDirectCell(t *testing.T) {
	yes, no := true, false
	if got := directCell(nil); got != "-" {
		t.Errorf("directCell(nil) = %q, want -", got)
	}
	if got := directCell(&yes); got != "Yes" {
		t.Errorf("directCell(true) = %q, want Yes", got)
	}
	if got := directCell(&no); got != "No" {
		t.Errorf("directCell(false) = %q, want No", got)
	}
}

func TestDiffVulnerabilityMarkdownPersistedMessage(t *testing.T) {
	payload := output.DiffResponse{
		Results: output.DiffResults{
			Vulnerabilities: output.DiffVulnerabilityResults{
				Persisted: []output.DiffVulnerabilityChange{{
					Package:       output.PackageRef{Name: "commons-lang3", Version: "3.18.0"},
					Vulnerability: output.VulnerabilityRef{ID: "CVE-2025-48924", Severity: sdk.SeverityMedium},
				}},
			},
		},
	}
	lines := diffVulnerabilityMarkdown(payload)
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "0 introduced, 1 persisted, 0 resolved") {
		t.Errorf("expected persisted count in summary, got:\n%s", joined)
	}
	if !strings.Contains(joined, "still affected") || !strings.Contains(joined, "does not remediate") {
		t.Errorf("expected still-affected message, got:\n%s", joined)
	}
	if !strings.Contains(joined, "Persisted Vulnerabilities") {
		t.Errorf("expected persisted table, got:\n%s", joined)
	}
}

func TestDiffPostureMarkdownDistinguishesScorecardRun(t *testing.T) {
	ran := output.DiffResponse{Metadata: output.Metadata{ScorecardEnabled: true}}
	if got := strings.Join(diffPostureMarkdown(ran), "\n"); !strings.Contains(got, "Scorecard ran") {
		t.Errorf("expected scorecard-ran message, got %q", got)
	}
	notRun := output.DiffResponse{Metadata: output.Metadata{ScorecardEnabled: false}}
	if got := strings.Join(diffPostureMarkdown(notRun), "\n"); !strings.Contains(got, "was not selected") {
		t.Errorf("expected not-selected message, got %q", got)
	}
}

func TestDiffMarkdownFindingsTableHasLegendNoDisposition(t *testing.T) {
	payload := output.DiffResponse{
		Audit: &output.DiffAudit{
			Introduced: []output.AuditFinding{{
				ID:          "INVALID-abcd-efgh-ijkl",
				Kind:        sdk.FindingKindLicense,
				Auditor:     "license",
				Severity:    sdk.SeverityWarning,
				Disposition: sdk.FindingDispositionWarn,
				Package:     output.PackageRef{Name: "junit", Version: "4.12"},
				Title:       "Package has invalid SPDX license: non-standard",
			}},
		},
	}
	var buf bytes.Buffer
	if err := DiffMarkdown(&buf, payload); err != nil {
		t.Fatalf("DiffMarkdown: %v", err)
	}
	report := buf.String()
	if !strings.Contains(report, "**Legend:**") {
		t.Errorf("expected findings legend footnote, got:\n%s", report)
	}
	if strings.Contains(report, "Disposition") || strings.Contains(report, "Exploitability") {
		t.Errorf("findings table should not have Disposition/Exploitability columns, got:\n%s", report)
	}
}
