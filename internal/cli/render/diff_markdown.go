package render

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/output"
)

// DiffMarkdown writes a GitHub-flavored Markdown diff report.
func DiffMarkdown(w io.Writer, payload output.DiffResponse) error {
	return writeMarkdownReport(w, MarkdownReport[output.DiffResponse]{
		Title: "Bomly Diff Summary",
		Intro: func(payload output.DiffResponse) []string {
			return []string{fmt.Sprintf("Compared `%s` to `%s`.", markdownInline(payload.Comparison.Base), markdownInline(payload.Comparison.Head))}
		},
		Sections: []MarkdownSection[output.DiffResponse]{
			{Title: "Dependency Changes", Lines: diffDependencyMarkdown},
			{Title: "Vulnerabilities", Lines: func(payload output.DiffResponse) []string {
				return diffFindingMarkdown(filterAuditFindings(payload.Audit, "vulnerability", ""))
			}},
			{Title: "License Policy", Lines: func(payload output.DiffResponse) []string {
				return diffFindingMarkdown(filterAuditFindings(payload.Audit, "license", ""))
			}},
			{Title: "Package Policy", Lines: func(payload output.DiffResponse) []string {
				return diffFindingMarkdown(filterAuditFindings(payload.Audit, "package", ""))
			}},
			{Title: "Policy Evaluation", Lines: diffPolicyEvaluationMarkdown},
		},
	}, payload)
}

func filterAuditFindings(audit *output.DiffAudit, auditor, idContains string) []output.AuditFinding {
	if audit == nil {
		return nil
	}
	var findings []output.AuditFinding
	for _, finding := range audit.Introduced {
		if auditor != "" && finding.Auditor != auditor {
			continue
		}
		if idContains != "" && !strings.Contains(finding.ID, idContains) {
			continue
		}
		findings = append(findings, finding)
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return severityRankTable(findings[i].Severity) < severityRankTable(findings[j].Severity)
		}
		if findings[i].ID != findings[j].ID {
			return findings[i].ID < findings[j].ID
		}
		return DiffPackageDisplayName(findings[i].Package) < DiffPackageDisplayName(findings[j].Package)
	})
	return findings
}

func diffDependencyMarkdown(payload output.DiffResponse) []string {
	return []string{
		fmt.Sprintf("- Added: %d", len(payload.Results.Dependencies.Added)),
		fmt.Sprintf("- Removed: %d", len(payload.Results.Dependencies.Removed)),
		fmt.Sprintf("- Changed: %d", len(payload.Results.Dependencies.Changed)),
	}
}

func diffFindingMarkdown(findings []output.AuditFinding) []string {
	lines := []string{}
	if len(findings) == 0 {
		return []string{"No introduced findings."}
	}
	for _, finding := range findings {
		disposition := finding.Disposition
		if strings.TrimSpace(disposition) == "" {
			disposition = "fail"
		}
		pkg := DiffPackageDisplayName(finding.Package)
		if pkg == "" {
			pkg = "-"
		}
		patched := ""
		if strings.TrimSpace(finding.FixedIn) != "" {
			patched = fmt.Sprintf(" (patched in `%s`)", markdownInline(finding.FixedIn))
		}
		lines = append(lines, fmt.Sprintf(
			"- [%s] `%s`: %s%s",
			markdownInline(disposition),
			markdownInline(pkg),
			markdownText(finding.Title),
			patched,
		))
	}
	return lines
}

func diffPolicyEvaluationMarkdown(payload output.DiffResponse) []string {
	if payload.Audit == nil {
		return []string{"Policy evaluation was not included."}
	}
	return []string{
		fmt.Sprintf("- Introduced findings: %d", len(payload.Audit.Introduced)),
		fmt.Sprintf("- Persisted findings: %d", len(payload.Audit.Persisted)),
		fmt.Sprintf("- Resolved findings: %d", len(payload.Audit.Resolved)),
	}
}
