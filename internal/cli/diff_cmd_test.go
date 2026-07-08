package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/cli/render"
	diffengine "github.com/bomly-dev/bomly-cli/internal/engine/diff"
	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestRenderDiffTextShowsFindingsSummaryLine(t *testing.T) {
	payload := output.DiffResponse{
		Comparison: output.DiffComparison{Base: "main", Head: "feature"},
		Summary: output.DiffSummary{
			UnchangedManifestCount: 1,
		},
		Audit: &output.DiffAudit{
			AuditSummary: &output.AuditSummary{High: 1, Total: 1},
		},
		Metadata: output.Metadata{DurationMS: time.Second.Milliseconds()},
	}

	var out bytes.Buffer
	if err := render.Diff(&out, payload); err != nil {
		t.Fatalf("renderDiffText() error = %v", err)
	}

	report := render.StripANSI(out.String())
	if !strings.Contains(report, "No findings introduced or persisted.") {
		t.Fatalf("expected findings summary line, got:\n%s", report)
	}
	// Removed sections should not appear
	for _, absent := range []string{
		"Dependency diff",
		"Policy Evaluation",
		"Current findings:",
		"Change summary:",
	} {
		if strings.Contains(report, absent) {
			t.Fatalf("expected %q to be absent from compact diff output, got:\n%s", absent, report)
		}
	}
}

func TestDiffSARIFFindingsIncludesIntroducedAndPersisted(t *testing.T) {
	// Persisted findings are always tied to a package the diff changed, so
	// they must stay in the SARIF output or GitHub closes their alert as if
	// the issue had been resolved.
	introduced := sdk.Finding{ID: "new", PackageRef: "pkg:npm/new@1.0.0"}
	resolved := sdk.Finding{ID: "old", PackageRef: "pkg:npm/old@1.0.0"}
	persisted := sdk.Finding{ID: "kept", PackageRef: "pkg:npm/kept@1.0.0"}

	got := diffSARIFFindings(&diffengine.Audit{
		Introduced: []sdk.Finding{introduced},
		Resolved:   []sdk.Finding{resolved},
		Persisted:  []sdk.Finding{persisted},
	})
	gotIDs := make(map[string]bool, len(got))
	for _, f := range got {
		gotIDs[f.ID] = true
	}
	if len(got) != 2 || !gotIDs[introduced.ID] || !gotIDs[persisted.ID] {
		t.Fatalf("diffSARIFFindings() = %#v, want introduced + persisted, excluding resolved", got)
	}

	if got := diffSARIFFindings(&diffengine.Audit{Resolved: []sdk.Finding{resolved}}); len(got) != 0 {
		t.Fatalf("resolved-only SARIF findings = %#v, want none", got)
	}
}

func TestDiffPolicyExit_PersistedFailingFindingsAlsoFailTheJob(t *testing.T) {
	// Regression: a version bump that doesn't remediate an advisory classifies
	// as persisted (see PR fixing diff section agreement), and that must still
	// fail --fail-on any, since the finding is tied to a package this diff
	// actually changed.
	err := diffPolicyExit(true, &diffengine.Audit{
		Persisted: []sdk.Finding{{ID: "CVE-PERSISTS", Disposition: sdk.FindingDispositionFail}},
	})
	if err == nil {
		t.Fatal("expected a policy violation error for a failing persisted finding")
	}
}

func TestDiffPolicyExit_PersistedWarningsDoNotFailTheJob(t *testing.T) {
	err := diffPolicyExit(true, &diffengine.Audit{
		Persisted: []sdk.Finding{{ID: "license:warn", Disposition: sdk.FindingDispositionWarn}},
	})
	if err != nil {
		t.Fatalf("expected no policy violation for a warning-only persisted finding, got %v", err)
	}
}

func TestDiffPolicyExit_NoAuditNoExit(t *testing.T) {
	if err := diffPolicyExit(false, &diffengine.Audit{
		Persisted: []sdk.Finding{{ID: "x", Disposition: sdk.FindingDispositionFail}},
	}); err != nil {
		t.Fatalf("expected no exit error when audit is disabled, got %v", err)
	}
}

func TestRenderDiffTextShowsHighFindingsWhenIntroduced(t *testing.T) {
	payload := output.DiffResponse{
		Audit: &output.DiffAudit{
			Introduced: []output.AuditFinding{
				{ID: "CVE-2024-1234", Severity: "high"},
				{ID: "CVE-2024-5678", Severity: "critical"},
			},
		},
	}
	var out bytes.Buffer
	if err := render.Diff(&out, payload); err != nil {
		t.Fatalf("render.Diff() error = %v", err)
	}
	report := render.StripANSI(out.String())
	if !strings.Contains(report, "2 new finding(s) introduced.") {
		t.Fatalf("expected high-severity count line, got:\n%s", report)
	}
}

func TestRenderDiffTextShowsPersistedFindings(t *testing.T) {
	payload := output.DiffResponse{
		Audit: &output.DiffAudit{
			Persisted: []output.AuditFinding{
				{ID: "CVE-2024-1234", Severity: "high", Package: output.FindingPackageRef{Name: "minimist", Version: "0.0.10"}},
				{ID: "CVE-2024-5678", Severity: "medium", Package: output.FindingPackageRef{Name: "minimist", Version: "1.2.8"}},
			},
		},
	}
	var out bytes.Buffer
	if err := render.Diff(&out, payload); err != nil {
		t.Fatalf("render.Diff() error = %v", err)
	}
	report := render.StripANSI(out.String())
	for _, want := range []string{
		"2 finding(s) persisted.",
		"persisted  [HIGH]      CVE-2024-1234  minimist@0.0.10",
		"persisted  [MEDIUM]    CVE-2024-5678  minimist@1.2.8",
	} {
		if !strings.Contains(report, want) {
			t.Fatalf("expected text report to contain %q, got:\n%s", want, report)
		}
	}
	if strings.Contains(report, "No new findings introduced.") {
		t.Fatalf("did not expect stale no-new-findings message, got:\n%s", report)
	}
}

func TestRenderDiffTextShowsIntroducedAndPersistedFindings(t *testing.T) {
	payload := output.DiffResponse{
		Audit: &output.DiffAudit{
			Introduced: []output.AuditFinding{
				{ID: "CVE-NEW", Severity: "critical", Package: output.FindingPackageRef{Name: "react", Version: "19.0.0"}},
			},
			Persisted: []output.AuditFinding{
				{ID: "CVE-KEPT", Severity: "high", Package: output.FindingPackageRef{Name: "minimist", Version: "1.2.8"}},
			},
		},
	}
	var out bytes.Buffer
	if err := render.Diff(&out, payload); err != nil {
		t.Fatalf("render.Diff() error = %v", err)
	}
	report := render.StripANSI(out.String())
	for _, want := range []string{
		"1 new finding(s) introduced; 1 finding(s) persisted.",
		"introduced  [CRITICAL]  CVE-NEW",
		"persisted   [HIGH]      CVE-KEPT",
	} {
		if !strings.Contains(report, want) {
			t.Fatalf("expected text report to contain %q, got:\n%s", want, report)
		}
	}
}

func TestRenderDiffMarkdownIncludesPatchedVersionsByDefault(t *testing.T) {
	payload := output.DiffResponse{
		Comparison: output.DiffComparison{Base: "main", Head: "feature"},
		Results: output.DiffResults{
			Dependencies: output.DiffDependencyResults{
				Added:   []output.DiffPackageChange{{Package: output.PackageRef{Name: "react", Version: "18.2.0"}}},
				Changed: []output.DiffChangedPackage{{After: output.PackageRef{Name: "zod", Version: "3.23.0"}, Before: output.PackageRef{Name: "zod", Version: "3.22.0"}}},
			},
			Vulnerabilities: output.DiffVulnerabilityResults{
				Added: []output.DiffVulnerabilityChange{{
					Package: output.PackageRef{Name: "react", Version: "18.2.0"},
					Vulnerability: output.VulnerabilityRef{
						ID:       "OSV-123",
						Severity: "high",
						Source:   "osv",
						Title:    "Prototype pollution in react",
						FixedIn:  "18.2.1",
					},
				}},
			},
		},
		Packages: []output.ScanPackageEntry{{
			Purl: "pkg:npm/react@18.2.0",
			Name: "react",
			Vulnerabilities: []output.VulnerabilityRef{{
				ID:      "OSV-123",
				Source:  "osv",
				FixedIn: "18.2.1",
			}},
		}},
		Audit: &output.DiffAudit{
			Introduced: []output.AuditFinding{{
				ID:              "OSV-123",
				VulnerabilityID: "OSV-123",
				Severity:        "high",
				Auditor:         "vulnerability",
				Disposition:     "fail",
				Package:         output.FindingPackageRef{Name: "react", Version: "18.2.0", Purl: "pkg:npm/react@18.2.0"},
				Title:           "Prototype pollution in react",
			}},
		},
	}

	var out bytes.Buffer
	if err := render.DiffMarkdown(&out, payload); err != nil {
		t.Fatalf("DiffMarkdown() error = %v", err)
	}

	report := out.String()
	for _, want := range []string{
		"# Bomly Diff Summary",
		"Compared `main` to `feature`.",
		"**Summary:** 1 added, 1 changed, 0 removed.",
		"| added | react@18.2.0 | 18.2.0 | - | unknown | - |",
		"| changed | zod | 3.22.0 → 3.23.0 | - | unknown | - |",
		"## Vulnerabilities",
		"| introduced | HIGH | OSV-123 | react@18.2.0 | 18.2.1 | osv | Prototype pollution in react |",
		"## Policy Findings",
		"| ❌ | introduced | vulnerability | HIGH | OSV-123 | react@18.2.0 | 18.2.1 | Prototype pollution in react |",
	} {
		if !strings.Contains(report, want) {
			t.Fatalf("expected Markdown report to contain %q, got:\n%s", want, report)
		}
	}
}

func TestRenderDiffMarkdownRendersScopedPolicyPayloadDirectly(t *testing.T) {
	payload := output.DiffResponse{
		Comparison: output.DiffComparison{Base: "main", Head: "feature"},
		Results: output.DiffResults{
			Dependencies: output.DiffDependencyResults{
				Changed: []output.DiffChangedPackage{{
					Before: output.PackageRef{Name: "react", Version: "18.2.0"},
					After:  output.PackageRef{Name: "react", Version: "18.2.1"},
				}},
			},
		},
		Audit: &output.DiffAudit{
			Introduced: []output.AuditFinding{{
				ID:          "license:unknown",
				Auditor:     "license",
				Disposition: "warn",
				Package:     output.FindingPackageRef{Name: "new-package", Version: "1.0.0"},
				Title:       "Package license is unknown",
			}},
			Persisted: []output.AuditFinding{
				{ID: "CVE-REACT", Auditor: "vulnerability", Severity: "medium", Package: output.FindingPackageRef{Name: "react", Version: "18.2.1"}, Title: "React finding"},
				{ID: "CVE-LODASH", Auditor: "vulnerability", Severity: "medium", Package: output.FindingPackageRef{Name: "lodash", Version: "4.17.20"}, Title: "Unrelated finding"},
			},
			Resolved: []output.AuditFinding{
				{ID: "CVE-REACT-OLD", Auditor: "vulnerability", Severity: "medium", Package: output.FindingPackageRef{Name: "react", Version: "18.2.0"}, Title: "Old React finding"},
				{ID: "CVE-MINIMIST", Auditor: "vulnerability", Severity: "medium", Package: output.FindingPackageRef{Name: "minimist", Version: "1.2.5"}, Title: "Unrelated resolved finding"},
			},
		},
	}

	var out bytes.Buffer
	if err := render.DiffMarkdown(&out, payload); err != nil {
		t.Fatalf("DiffMarkdown() error = %v", err)
	}

	report := out.String()
	for _, want := range []string{
		"1 introduced / 2 persisted / 2 resolved",
		"2 persisted",
		"2 resolved",
		"Persisted Findings",
		"Resolved Findings",
		"CVE-REACT",
		"CVE-REACT-OLD",
		"CVE-LODASH",
		"CVE-MINIMIST",
	} {
		if !strings.Contains(report, want) {
			t.Fatalf("expected Markdown report to contain %q, got:\n%s", want, report)
		}
	}
	for _, unwanted := range []string{"omitted", "on Changed Dependencies"} {
		if strings.Contains(report, unwanted) {
			t.Fatalf("did not expect Markdown report to contain %q, got:\n%s", unwanted, report)
		}
	}
}

func TestWriteRenderedOutputCreatesParentDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "summary.md")
	if err := writeRenderedOutput(bytes.NewBuffer(nil), render.OutputSpec{Format: output.FormatMarkdown, Label: "markdown", Path: path}, func(w io.Writer) error {
		_, err := w.Write([]byte("# Summary\n"))
		return err
	}); err != nil {
		t.Fatalf("writeRenderedOutput() error = %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read summary file: %v", err)
	}
	if string(data) != "# Summary\n" {
		t.Fatalf("unexpected summary file content: %q", data)
	}
}

func TestRenderDiffTextShowsHighFindingCountWhenIntroducedFindings(t *testing.T) {
	payload := output.DiffResponse{
		Comparison: output.DiffComparison{Base: "base.spdx", Head: "head.spdx"},
		Audit: &output.DiffAudit{
			Introduced: []output.AuditFinding{
				{ID: "OSV-123", Severity: "high", Package: output.FindingPackageRef{Name: "react", Version: "18.2.0"}, Title: "Prototype pollution in react"},
			},
			Resolved: []output.AuditFinding{
				{ID: "OSV-345", Severity: "low", Package: output.FindingPackageRef{Name: "minimist", Version: "1.2.5"}},
			},
			AuditSummary: &output.AuditSummary{High: 1, Medium: 1, Total: 2},
		},
	}

	var out bytes.Buffer
	if err := render.Diff(&out, payload); err != nil {
		t.Fatalf("renderDiffText() error = %v", err)
	}

	report := render.StripANSI(out.String())
	if !strings.Contains(report, "1 new finding(s) introduced.") {
		t.Fatalf("expected high-severity summary line, got:\n%s", report)
	}
	// Verbose policy sections are not shown in the compact text format.
	for _, absent := range []string{"Policy Evaluation", "Introduced Findings", "Resolved Findings", "Change summary:"} {
		if strings.Contains(report, absent) {
			t.Fatalf("expected %q absent from compact diff output, got:\n%s", absent, report)
		}
	}
}
