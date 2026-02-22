package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/bomly/bomly-cli/internal/output"
	"github.com/bomly/bomly-cli/internal/viewmodel"
)

func TestRenderDiffTextIncludesAuditOutcomeWithoutChanges(t *testing.T) {
	payload := viewmodel.DiffResponse{
		Comparison: viewmodel.DiffComparison{Base: "main", Head: "feature"},
		Summary: viewmodel.DiffSummary{
			UnchangedManifestCount: 1,
		},
		Audit: &viewmodel.DiffAudit{
			AuditSummary: &viewmodel.AuditSummary{High: 1, Total: 1},
		},
		Metadata: output.Metadata{DurationMS: time.Second.Milliseconds()},
	}

	var out bytes.Buffer
	if err := renderDiffText(&out, payload); err != nil {
		t.Fatalf("renderDiffText() error = %v", err)
	}

	report := out.String()
	for _, want := range []string{
		"Dependency diff main -> feature",
		"Policy Outcome",
		"Current findings: 1 total (1 high).",
		"Change summary: 0 introduced, 0 persisted, and 0 resolved findings.",
		"No policy differences were identified between the base and head dependency sets.",
	} {
		if !strings.Contains(report, want) {
			t.Fatalf("expected diff report to contain %q, got:\n%s", want, report)
		}
	}
}

func TestRenderDiffTextIncludesAuditSections(t *testing.T) {
	payload := viewmodel.DiffResponse{
		Comparison: viewmodel.DiffComparison{Base: "base.spdx", Head: "head.spdx"},
		Summary: viewmodel.DiffSummary{
			ChangedManifestCount: 1,
			AddedPackageCount:    1,
			RemovedPackageCount:  1,
		},
		Audit: &viewmodel.DiffAudit{
			Introduced: []viewmodel.AuditFinding{{
				ID:       "OSV-123",
				Severity: "high",
				Package:  output.PackageRef{Name: "react", Version: "18.2.0"},
				Title:    "Prototype pollution in react",
				Source:   "osv",
			}},
			Persisted: []viewmodel.AuditFinding{{
				ID:       "OSV-234",
				Severity: "medium",
				Package:  output.PackageRef{Name: "lodash", Version: "4.17.20"},
				Source:   "osv",
			}},
			Resolved: []viewmodel.AuditFinding{{
				ID:       "OSV-345",
				Severity: "low",
				Package:  output.PackageRef{Name: "minimist", Version: "1.2.5"},
				Source:   "osv",
			}},
			AuditSummary: &viewmodel.AuditSummary{High: 1, Medium: 1, Low: 1, Total: 3},
		},
	}

	var out bytes.Buffer
	if err := renderDiffText(&out, payload); err != nil {
		t.Fatalf("renderDiffText() error = %v", err)
	}

	report := out.String()
	for _, want := range []string{
		"Policy Outcome",
		"Current findings: 3 total (1 high, 1 medium, 1 low).",
		"Change summary: 1 introduced, 1 persisted, and 1 resolved findings.",
		"Introduced Findings",
		"Persisted Findings",
		"Resolved Findings",
		"OSV-123 react@18.2.0 (osv): Prototype pollution in react",
		"OSV-234 lodash@4.17.20 (osv)",
		"OSV-345 minimist@1.2.5 (osv)",
	} {
		if !strings.Contains(report, want) {
			t.Fatalf("expected diff report to contain %q, got:\n%s", want, report)
		}
	}
}
