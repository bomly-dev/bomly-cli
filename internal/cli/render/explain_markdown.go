package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/output"
)

// ExplainMarkdown writes a GitHub-flavored Markdown explain report.
func ExplainMarkdown(w io.Writer, payload output.ExplainResponse) error {
	return writeMarkdownReport(w, MarkdownReport[output.ExplainResponse]{
		Title: "Bomly Explain Summary",
		Intro: func(payload output.ExplainResponse) []string {
			return []string{fmt.Sprintf("Query: `%s`", markdownInline(payload.Query.Name))}
		},
		Sections: []MarkdownSection[output.ExplainResponse]{
			{Title: "Targets", Lines: explainTargetsMarkdown},
			{Title: "Dependency Paths", Lines: explainPathsMarkdown},
			{Title: "Impact Assessment", Lines: explainImpactMarkdown},
		},
	}, payload)
}

func explainTargetsMarkdown(payload output.ExplainResponse) []string {
	if len(payload.Targets) == 0 {
		return []string{"No matching dependencies were found."}
	}
	rows := make([][]string, 0, len(payload.Targets))
	for _, target := range payload.Targets {
		rows = append(rows, []string{
			ValueOrDash(markdownPackageDisplayName(target.Dependency)),
			ValueOrDash(target.Project.Name),
			ValueOrDash(target.Detector),
			fmt.Sprintf("%d", len(target.Paths)),
		})
	}
	return markdownTable([]string{"Dependency", "Project", "Detector", "Paths"}, rows)
}

func explainPathsMarkdown(payload output.ExplainResponse) []string {
	if len(payload.Targets) == 0 {
		return []string{"No dependency paths found."}
	}
	lines := make([]string, 0)
	for _, target := range payload.Targets {
		if len(payload.Targets) > 1 {
			lines = append(lines, fmt.Sprintf("### `%s`", markdownInline(markdownPackageDisplayName(target.Dependency))), "")
		}
		if len(target.Paths) == 0 {
			lines = append(lines, "No dependency paths found.", "")
			continue
		}
		for _, path := range target.Paths {
			lines = append(lines, "- "+markdownDependencyPath(path))
		}
		if len(payload.Targets) > 1 {
			lines = append(lines, "")
		}
	}
	return trimTrailingMarkdownBlanks(lines)
}

func explainImpactMarkdown(payload output.ExplainResponse) []string {
	if len(payload.Targets) == 0 {
		return []string{"No impact data available."}
	}
	lines := make([]string, 0)
	for _, target := range payload.Targets {
		if len(payload.Targets) > 1 {
			lines = append(lines, fmt.Sprintf("### `%s`", markdownInline(markdownPackageDisplayName(target.Dependency))), "")
		}
		lines = append(lines,
			fmt.Sprintf("- Vulnerabilities: %d", len(target.Dependency.Vulnerabilities)),
			fmt.Sprintf("- Policy findings: %s", scanAuditSummaryMarkdown(target.AuditSummary)),
			fmt.Sprintf("- Licenses: %d", len(target.Dependency.Licenses)),
		)
		if len(target.Findings) > 0 {
			for _, finding := range sortDiffAuditFindings(target.Findings) {
				title := finding.Title
				if title == "" {
					title = finding.ID
				}
				lines = append(lines, fmt.Sprintf(
					"- [%s] `%s`: %s",
					markdownInline(ValueOrDash(finding.Severity)),
					markdownInline(ValueOrDash(finding.ID)),
					markdownText(title),
				))
			}
		}
		if len(payload.Targets) > 1 {
			lines = append(lines, "")
		}
	}
	return trimTrailingMarkdownBlanks(lines)
}

func markdownDependencyPath(path output.DependencyPath) string {
	parts := make([]string, 0, len(path.Packages))
	for _, pkg := range path.Packages {
		parts = append(parts, "`"+markdownInline(markdownPackageDisplayName(pkg))+"`")
	}
	if len(parts) == 0 {
		parts = append(parts, "`-`")
	}
	suffix := ""
	metadata := make([]string, 0, 2)
	if path.Relationship != "" {
		metadata = append(metadata, path.Relationship)
	}
	if path.Cyclic {
		metadata = append(metadata, "cycle to "+path.CycleTo)
	}
	if len(metadata) > 0 {
		suffix = " (" + markdownText(strings.Join(metadata, ", ")) + ")"
	}
	return strings.Join(parts, " -> ") + suffix
}
