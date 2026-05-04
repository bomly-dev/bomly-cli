package render

import "strings"

// WrapLines wraps each input line to width by hard-cutting at width visible
// columns (counted with ANSI escapes stripped). Empty lines are preserved.
func WrapLines(lines []string, width int) []string {
	if width < 1 {
		width = 1
	}
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if line == "" {
			out = append(out, "")
			continue
		}
		remaining := line
		for len(StripANSI(remaining)) > width {
			visible := StripANSI(remaining)
			out = append(out, visible[:width])
			remaining = visible[width:]
		}
		out = append(out, remaining)
	}
	return out
}

// WrapTextLines splits value into space-delimited words and packs them into
// lines no wider than width visible columns. Words longer than width are
// hard-cut. ANSI escape sequences in value are stripped before measuring.
func WrapTextLines(value string, width int) []string {
	if width < 1 {
		return []string{""}
	}
	text := strings.TrimSpace(StripANSI(value))
	if text == "" {
		return []string{""}
	}
	words := strings.Fields(text)
	if len(words) == 0 {
		return []string{""}
	}
	lines := make([]string, 0, len(words))
	current := words[0]
	for _, word := range words[1:] {
		candidate := current + " " + word
		if len(candidate) <= width {
			current = candidate
			continue
		}
		lines = append(lines, current)
		current = word
		for len(current) > width {
			lines = append(lines, current[:width])
			current = current[width:]
		}
	}
	lines = append(lines, current)
	return lines
}

// TruncateToWidth shortens value to width visible columns, appending "..."
// when it had to truncate (unless width is too small to fit the ellipsis).
func TruncateToWidth(value string, width int) string {
	if width <= 0 {
		return ""
	}
	visible := StripANSI(value)
	if len(visible) <= width {
		return value
	}
	if width <= 3 {
		return visible[:width]
	}
	return visible[:width-3] + "..."
}

// PadRight pads value with spaces to width visible columns, truncating first
// if value is wider than width.
func PadRight(value string, width int) string {
	value = TruncateToWidth(value, width)
	visibleWidth := len(StripANSI(value))
	if visibleWidth >= width {
		return value
	}
	return value + strings.Repeat(" ", width-visibleWidth)
}

// ValueOrDash returns "-" for blank input so report tables show a placeholder
// in empty cells.
func ValueOrDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

// RelationshipOrder returns a sort rank for the named dependency relationship
// (manifest, self, parent, ancestor, root, direct, transitive). Lower wins.
// Unknown relationships sort last.
func RelationshipOrder(relationship string) int {
	switch strings.ToLower(strings.TrimSpace(relationship)) {
	case "manifest":
		return 0
	case "self":
		return 1
	case "parent":
		return 2
	case "ancestor":
		return 3
	case "root":
		return 4
	case "direct":
		return 5
	case "transitive":
		return 6
	default:
		return 99
	}
}
