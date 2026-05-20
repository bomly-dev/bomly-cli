package render

import (
	"fmt"
	"html"
	"io"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/output"
)

// MarkdownReport describes the command-specific sections for a Markdown report.
type MarkdownReport[T any] struct {
	Title    string
	Intro    func(T) []string
	Sections []MarkdownSection[T]
}

// MarkdownSection describes one command-specific section in a Markdown report.
type MarkdownSection[T any] struct {
	Title string
	Lines func(T) []string
}

func writeMarkdownReport[T any](w io.Writer, report MarkdownReport[T], payload T) error {
	lines := []string{"# " + report.Title, ""}
	if report.Intro != nil {
		lines = appendMarkdownBlock(lines, report.Intro(payload)...)
	}
	for _, section := range report.Sections {
		lines = append(lines, "## "+section.Title, "")
		if section.Lines == nil {
			lines = append(lines, "_No details._", "")
			continue
		}
		lines = appendMarkdownBlock(lines, section.Lines(payload)...)
	}
	return writeMarkdownLines(w, lines)
}

func writeMarkdownLines(w io.Writer, lines []string) error {
	for _, line := range lines {
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return nil
}

func appendMarkdownBlock(lines []string, block ...string) []string {
	block = trimTrailingMarkdownBlanks(block)
	lines = append(lines, block...)
	if len(lines) == 0 || lines[len(lines)-1] != "" {
		lines = append(lines, "")
	}
	return lines
}

func trimTrailingMarkdownBlanks(lines []string) []string {
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

func markdownInline(value string) string {
	return strings.ReplaceAll(value, "`", "\\`")
}

func markdownText(value string) string {
	return html.EscapeString(strings.TrimSpace(value))
}

func markdownTable(headers []string, rows [][]string) []string {
	lines := []string{
		"| " + strings.Join(headers, " | ") + " |",
		"| " + strings.Join(markdownTableSeparators(len(headers)), " | ") + " |",
	}
	for _, row := range rows {
		values := make([]string, len(headers))
		for idx := range values {
			if idx < len(row) {
				values[idx] = markdownTableCell(row[idx])
			} else {
				values[idx] = "-"
			}
		}
		lines = append(lines, "| "+strings.Join(values, " | ")+" |")
	}
	return lines
}

func markdownTableSeparators(count int) []string {
	values := make([]string, count)
	for idx := range values {
		values[idx] = "---"
	}
	return values
}

func markdownTableCell(value string) string {
	value = markdownText(value)
	value = strings.ReplaceAll(value, "\r\n", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, "|", "\\|")
	if value == "" {
		return "-"
	}
	return value
}

func markdownPackageDisplayName(pkg output.PackageRef) string {
	switch {
	case pkg.Name != "" && pkg.Version != "":
		return pkg.Name + "@" + pkg.Version
	case pkg.Name != "":
		return pkg.Name
	case pkg.ID != "":
		return pkg.ID
	default:
		return ""
	}
}
