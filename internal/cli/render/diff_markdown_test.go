package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestDiffOverviewMarkdownPersistedFailingCountsAsFailing(t *testing.T) {
	// A persisted finding is tied to a package the diff actually changed, so
	// the Overview status must reflect it as a failure, not a softer warning.
	payload := output.DiffResponse{
		Audit: &output.DiffAudit{
			Persisted: []output.AuditFinding{{ID: "CVE-PERSISTS", PolicyStatus: sdk.FindingPolicyStatusFail}},
		},
	}
	got := strings.Join(diffOverviewMarkdown(payload), "\n")
	if !strings.Contains(got, "❌ Failing findings") {
		t.Errorf("expected failing status for a failing persisted finding, got %q", got)
	}
}

func TestDiffOverviewMarkdownPersistedWarningsAreWarnings(t *testing.T) {
	payload := output.DiffResponse{
		Audit: &output.DiffAudit{
			Persisted: []output.AuditFinding{{ID: "license:warn", PolicyStatus: sdk.FindingPolicyStatusWarn}},
		},
	}
	got := strings.Join(diffOverviewMarkdown(payload), "\n")
	if !strings.Contains(got, "⚠️ Warnings") {
		t.Errorf("expected a warning status for a warn-only persisted finding, got %q", got)
	}
	if strings.Contains(got, "❌") {
		t.Errorf("did not expect a failing status, got %q", got)
	}
}

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
		t.Errorf("expected scorecard-ran-no-data message, got %q", got)
	}
	notRun := output.DiffResponse{Metadata: output.Metadata{ScorecardEnabled: false}}
	if got := strings.Join(diffPostureMarkdown(notRun), "\n"); !strings.Contains(got, "was not selected") {
		t.Errorf("expected not-selected message, got %q", got)
	}
}

func TestDiffPostureMarkdownDoesNotConflateNoDataWithNoChange(t *testing.T) {
	// A package with identical Scorecard data on both sides of a version bump
	// has posture data, but buildPostureDelta drops it (no meaningful score
	// change), so delta.isEmpty() is true here for a different reason than
	// "scorecard found nothing" — the message must reflect that distinction.
	card := &sdk.PackageScorecard{Repository: "github.com/example/repo", AggregateScore: 7.5}
	payload := output.DiffResponse{
		Metadata: output.Metadata{ScorecardEnabled: true},
		Results: output.DiffResults{
			Dependencies: output.DiffDependencyResults{
				Changed: []output.DiffChangedPackage{{
					Before: output.PackageRef{Name: "lib", Version: "1.0.0", Scorecard: card},
					After:  output.PackageRef{Name: "lib", Version: "1.0.1", Scorecard: card},
				}},
			},
		},
	}
	got := strings.Join(diffPostureMarkdown(payload), "\n")
	if !strings.Contains(got, "No project posture changes") {
		t.Errorf("expected a plain no-changes message, got %q", got)
	}
	if strings.Contains(got, "no project posture data was found") {
		t.Errorf("message should not claim no data was found when data exists, got %q", got)
	}
}

func TestPersistedLicenseFindingCountDedupesByPackage(t *testing.T) {
	// Two persisted license findings on the same package must count as one
	// package, so the count matches the "N packages" wording in
	// licensePersistedNote.
	pkg := output.FindingPackageRef{Purl: "pkg:npm/lib@1.0.0"}
	audit := &output.DiffAudit{
		Persisted: []output.AuditFinding{
			{Kind: sdk.FindingKindLicense, Package: pkg},
			{Kind: sdk.FindingKindLicense, Package: pkg},
			{Kind: sdk.FindingKindVulnerability, Package: pkg},
		},
	}
	if got := persistedLicenseFindingCount(audit); got != 1 {
		t.Errorf("persistedLicenseFindingCount() = %d, want 1 (deduplicated by package)", got)
	}
}

func TestDiffMarkdownFindingsTableHasLegendNoPolicyStatus(t *testing.T) {
	payload := output.DiffResponse{
		Audit: &output.DiffAudit{
			Introduced: []output.AuditFinding{{
				ID:           "INVALID-abcd-efgh-ijkl",
				Kind:         sdk.FindingKindLicense,
				Auditor:      "license",
				Severity:     sdk.SeverityWarning,
				PolicyStatus: sdk.FindingPolicyStatusWarn,
				Package:      output.FindingPackageRef{Name: "junit", Version: "4.12"},
				Title:        "Package has invalid SPDX license: non-standard",
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
	if strings.Contains(report, "PolicyStatus") || strings.Contains(report, "Exploitability") {
		t.Errorf("findings table should not have PolicyStatus/Exploitability columns, got:\n%s", report)
	}
	if !strings.Contains(report, "Package has invalid SPDX license: **non-standard**") {
		t.Errorf("expected the offending license to be bolded in the findings table, got:\n%s", report)
	}
}

func TestEmphasizeFindingTitle(t *testing.T) {
	tests := []struct {
		name    string
		finding output.AuditFinding
		want    string
	}{
		{
			name:    "invalid license bolds the offending expression",
			finding: output.AuditFinding{Kind: sdk.FindingKindLicense, Title: "Package has invalid SPDX license: non-standard"},
			want:    "Package has invalid SPDX license: **non-standard**",
		},
		{
			name:    "invalid license with multiple expressions bolds all of them",
			finding: output.AuditFinding{Kind: sdk.FindingKindLicense, Title: "Package has invalid SPDX license: foo, bar"},
			want:    "Package has invalid SPDX license: **foo, bar**",
		},
		{
			name:    "license title without a colon value is unchanged",
			finding: output.AuditFinding{Kind: sdk.FindingKindLicense, Title: "Package license is unknown"},
			want:    "Package license is unknown",
		},
		{
			name:    "non-license finding is never emphasized",
			finding: output.AuditFinding{Kind: sdk.FindingKindVulnerability, Title: "Prototype pollution: critical impact"},
			want:    "Prototype pollution: critical impact",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := emphasizeFindingTitle(tt.finding); got != tt.want {
				t.Errorf("emphasizeFindingTitle() = %q, want %q", got, tt.want)
			}
		})
	}
}
