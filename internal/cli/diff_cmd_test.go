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
	if !strings.Contains(report, "No new findings introduced.") {
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

func TestDiffSARIFFindingsOnlyIncludesIntroduced(t *testing.T) {
	introduced := sdk.Finding{ID: "new", PackageRef: "pkg:npm/new@1.0.0"}
	resolved := sdk.Finding{ID: "old", PackageRef: "pkg:npm/old@1.0.0"}
	persisted := sdk.Finding{ID: "kept", PackageRef: "pkg:npm/kept@1.0.0"}

	got := diffSARIFFindings(&diffengine.Audit{
		Introduced: []sdk.Finding{introduced},
		Resolved:   []sdk.Finding{resolved},
		Persisted:  []sdk.Finding{persisted},
	})
	if len(got) != 1 || got[0].ID != introduced.ID {
		t.Fatalf("diffSARIFFindings() = %#v, want only introduced finding", got)
	}

	if got := diffSARIFFindings(&diffengine.Audit{Resolved: []sdk.Finding{resolved}}); len(got) != 0 {
		t.Fatalf("resolved-only SARIF findings = %#v, want none", got)
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
		Audit: &output.DiffAudit{
			Introduced: []output.AuditFinding{{
				ID:          "OSV-123",
				Severity:    "high",
				Auditor:     "vulnerability",
				Disposition: "fail",
				Package:     output.PackageRef{Name: "react", Version: "18.2.0"},
				Title:       "Prototype pollution in react",
				FixedIn:     "18.2.1",
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
		"| ❌ | introduced | HIGH | OSV-123 | react@18.2.0 | 18.2.1 | osv | Prototype pollution in react |",
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
				Package:     output.PackageRef{Name: "new-package", Version: "1.0.0"},
				Title:       "Package license is unknown",
			}},
			Persisted: []output.AuditFinding{
				{ID: "CVE-REACT", Auditor: "vulnerability", Severity: "medium", Package: output.PackageRef{Name: "react", Version: "18.2.1"}, Title: "React finding"},
				{ID: "CVE-LODASH", Auditor: "vulnerability", Severity: "medium", Package: output.PackageRef{Name: "lodash", Version: "4.17.20"}, Title: "Unrelated finding"},
			},
			Resolved: []output.AuditFinding{
				{ID: "CVE-REACT-OLD", Auditor: "vulnerability", Severity: "medium", Package: output.PackageRef{Name: "react", Version: "18.2.0"}, Title: "Old React finding"},
				{ID: "CVE-MINIMIST", Auditor: "vulnerability", Severity: "medium", Package: output.PackageRef{Name: "minimist", Version: "1.2.5"}, Title: "Unrelated resolved finding"},
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
				{ID: "OSV-123", Severity: "high", Package: output.PackageRef{Name: "react", Version: "18.2.0"}, Title: "Prototype pollution in react"},
			},
			Resolved: []output.AuditFinding{
				{ID: "OSV-345", Severity: "low", Package: output.PackageRef{Name: "minimist", Version: "1.2.5"}},
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
