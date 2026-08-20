package assurance

import (
	"fmt"
	"strings"
)

// StatusIcon returns the emoji shown next to a status in markdown summaries.
func StatusIcon(status Status) string {
	switch status {
	case StatusPass:
		return "✅"
	case StatusFail:
		return "❌"
	case StatusDegraded:
		return "⚠️"
	case StatusSkip:
		return "⏭️"
	case StatusMissing:
		return "❓"
	default:
		return "•"
	}
}

// MarkdownOptions controls how a report renders as markdown.
type MarkdownOptions struct {
	// Heading is the top-level title; a default is used when empty.
	Heading string
	// IncludeChecks lists every check in a per-stage table.
	IncludeChecks bool
	// IncludeTrends adds the comparison against the previous release.
	IncludeTrends bool
}

// RenderMarkdown renders a report as the markdown used for job summaries and
// the per-release tracking issue.
func RenderMarkdown(report Report, opts MarkdownOptions) string {
	var out strings.Builder
	heading := opts.Heading
	if heading == "" {
		heading = "Release assurance"
		if report.Release.Tag != "" {
			heading += " " + report.Release.Tag
		}
	}
	fmt.Fprintf(&out, "## %s %s\n\n", StatusIcon(report.Verdict.Overall), heading)
	fmt.Fprintf(&out, "%s\n\n", verdictSentence(report.Verdict))

	if len(report.Stages) > 0 {
		out.WriteString("| Stage | Result | Checks | Passed | Failed | Missing |\n")
		out.WriteString("| --- | --- | --- | --- | --- | --- |\n")
		for _, stage := range report.Stages {
			fmt.Fprintf(&out, "| %s | %s %s | %d | %d | %d | %d |\n",
				stage.Title, StatusIcon(stage.Status), stage.Status,
				stage.Verdict.Checks, stage.Verdict.Passed, stage.Verdict.Failed, stage.Verdict.Missing)
		}
		out.WriteString("\n")
	}

	if opts.IncludeChecks {
		for _, stage := range report.Stages {
			if len(stage.CheckIDs) == 0 {
				continue
			}
			fmt.Fprintf(&out, "### %s\n\n", stage.Title)
			out.WriteString("| Check | Level | Result | Summary |\n")
			out.WriteString("| --- | --- | --- | --- |\n")
			for _, id := range stage.CheckIDs {
				check, found := report.Check(id)
				if !found {
					continue
				}
				fmt.Fprintf(&out, "| %s | %s | %s %s | %s |\n",
					check.Title, check.Level, StatusIcon(check.Status), check.Status,
					markdownCell(check.Summary))
			}
			out.WriteString("\n")
		}
	}

	if attention := attentionLines(report); len(attention) > 0 {
		out.WriteString("### Needs attention\n\n")
		for _, line := range attention {
			out.WriteString("- " + line + "\n")
		}
		out.WriteString("\n")
	}

	if opts.IncludeTrends && report.Trends != nil {
		out.WriteString(renderTrends(*report.Trends))
	}
	return out.String()
}

func verdictSentence(verdict Verdict) string {
	switch verdict.Overall {
	case StatusPass:
		return fmt.Sprintf("All %d checks passed.", verdict.Checks)
	case StatusDegraded:
		return fmt.Sprintf("%d of %d checks passed; advisory checks reported problems that do not block the release.",
			verdict.Passed, verdict.Checks)
	case StatusMissing:
		return fmt.Sprintf("%d of %d checks reported nothing, so the release cannot be judged complete.",
			verdict.Missing, verdict.Checks)
	default:
		return fmt.Sprintf("%d of %d checks passed; %d failed and %d reported nothing.",
			verdict.Passed, verdict.Checks, verdict.Failed, verdict.Missing)
	}
}

func attentionLines(report Report) []string {
	var lines []string
	for _, check := range report.Checks {
		if check.Status == StatusPass || check.Status == StatusSkip {
			continue
		}
		line := fmt.Sprintf("%s **%s** (%s, %s) — %s",
			StatusIcon(check.Status), check.Title, check.Level, check.Stage, markdownCell(check.Summary))
		if len(check.MissingInstances) > 0 {
			line += fmt.Sprintf(" Missing: %s.", strings.Join(check.MissingInstances, ", "))
		}
		lines = append(lines, line)
	}
	for _, unknown := range report.Unknown {
		lines = append(lines, fmt.Sprintf("❓ Result `%s` is not declared in the assurance catalog.", unknown.ID))
	}
	return lines
}

func renderTrends(trends Trends) string {
	if len(trends.Changed) == 0 && len(trends.Metrics) == 0 {
		return ""
	}
	var out strings.Builder
	fmt.Fprintf(&out, "### Compared with %s\n\n", trends.PreviousTag)
	for _, change := range trends.Changed {
		fmt.Fprintf(&out, "- `%s`: %s → %s\n", change.CheckID, change.Previous, change.Current)
	}
	shown := 0
	for _, metric := range trends.Metrics {
		if shown >= 8 {
			break
		}
		if metric.Better == betterNeutral && metric.DeltaPct < 5 && metric.DeltaPct > -5 {
			continue
		}
		fmt.Fprintf(&out, "- `%s` %s: %.2f → %.2f (%+.1f%%)\n",
			metric.CheckID, metric.Metric, metric.Previous, metric.Current, metric.DeltaPct)
		shown++
	}
	out.WriteString("\n")
	return out.String()
}

// RenderResultMarkdown renders one check result for a workflow step summary.
// reproduce is the catalog's local reproduction command for the check, shown so
// a reader can run the same thing without hunting for it.
func RenderResultMarkdown(result CheckResult, reproduce [][]string) string {
	var out strings.Builder
	title := result.ID
	if result.Instance != "" {
		title += " (" + result.Instance + ")"
	}
	fmt.Fprintf(&out, "### %s %s\n\n%s\n\n", StatusIcon(result.Status), title, result.Summary)
	if len(result.Details) > 0 {
		out.WriteString("| Item | Result | Note |\n| --- | --- | --- |\n")
		shown := 0
		for _, detail := range result.Details {
			if shown >= 30 {
				fmt.Fprintf(&out, "| … | | %d further items are recorded in the check result |\n",
					len(result.Details)-shown)
				break
			}
			fmt.Fprintf(&out, "| %s | %s %s | %s |\n",
				markdownCell(detail.Name), StatusIcon(detail.Status), detail.Status, markdownCell(detail.Note))
			shown++
		}
		out.WriteString("\n")
	}
	if len(reproduce) > 0 {
		out.WriteString("Reproduce locally:\n\n```sh\n")
		for _, command := range reproduce {
			out.WriteString(shellCommand(command) + "\n")
		}
		out.WriteString("```\n\n")
	}
	return out.String()
}

// shellCommand renders one argument list as a copyable shell command.
func shellCommand(command []string) string {
	quoted := make([]string, len(command))
	for index, argument := range command {
		if argument != "" && strings.IndexFunc(argument, func(r rune) bool {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
				return false
			}
			return !strings.ContainsRune("@%_+=:,./-", r)
		}) == -1 {
			quoted[index] = argument
			continue
		}
		quoted[index] = "'" + strings.ReplaceAll(argument, "'", "'\"'\"'") + "'"
	}
	return strings.Join(quoted, " ")
}

func markdownCell(value string) string {
	cleaned := strings.ReplaceAll(strings.TrimSpace(value), "|", "\\|")
	cleaned = strings.ReplaceAll(cleaned, "\r", " ")
	cleaned = strings.ReplaceAll(cleaned, "\n", " ")
	return cleaned
}
