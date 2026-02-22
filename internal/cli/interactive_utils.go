package cli

import (
	"strings"

	model "github.com/bomly-dev/bomly-cli/sdk"
)

func wrapLines(lines []string, width int) []string {
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
		for len(stripANSI(remaining)) > width {
			visible := stripANSI(remaining)
			out = append(out, visible[:width])
			remaining = visible[width:]
		}
		out = append(out, remaining)
	}
	return out
}

func wrapTextLines(value string, width int) []string {
	if width < 1 {
		return []string{""}
	}
	text := strings.TrimSpace(stripANSI(value))
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

func truncateToWidth(value string, width int) string {
	if width <= 0 {
		return ""
	}
	visible := stripANSI(value)
	if len(visible) <= width {
		return value
	}
	if width <= 3 {
		return visible[:width]
	}
	return visible[:width-3] + "..."
}

func padRight(value string, width int) string {
	value = truncateToWidth(value, width)
	visibleWidth := len(stripANSI(value))
	if visibleWidth >= width {
		return value
	}
	return value + strings.Repeat(" ", width-visibleWidth)
}

func valueOrDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

func interactiveStatusBadge(status string) string {
	label := " " + strings.ToUpper(valueOrDash(status)) + " "
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "manifest":
		return ansiStyled(label, ansiBgBlue, ansiYellow, ansiBold)
	case "self":
		return ansiStyled(label, ansiBgGreen, ansiWhite, ansiBold)
	case "parent":
		return ansiStyled(label, ansiBgCyan, ansiWhite, ansiBold)
	case "ancestor":
		return ansiStyled(label, ansiBgMagenta, ansiWhite, ansiBold)
	case "root":
		return ansiStyled(label, ansiBgBlue, ansiWhite, ansiBold)
	case "direct":
		return ansiStyled(label, ansiBgCyan, ansiWhite, ansiBold)
	case "transitive":
		return ansiStyled(label, ansiBgMagenta, ansiWhite, ansiBold)
	case "added":
		return ansiStyled(label, ansiBgGreen, ansiWhite, ansiBold)
	case "removed":
		return ansiStyled(label, ansiBgRed, ansiWhite, ansiBold)
	case "changed":
		return ansiStyled(label, ansiBgYellow, ansiBold)
	case "unchanged":
		return ansiStyled(label, ansiBgBlue, ansiWhite)
	default:
		return ansiStyled(label, ansiBgCyan, ansiBlue, ansiBold)
	}
}

func interactiveBadgeView(badge interactiveBadge) string {
	label := " " + strings.ToUpper(valueOrDash(badge.label)) + " "
	switch badge.kind {
	case "scope-runtime":
		return ansiStyled(label, ansiBgGreen, ansiWhite, ansiBold)
	case "scope-development":
		return ansiStyled(label, ansiBgYellow, ansiBold)
	case "severity-critical":
		return ansiStyled(label, ansiBgRed, ansiWhite, ansiBold)
	case "severity-high":
		return ansiStyled(label, ansiBgRed, ansiWhite)
	case "severity-medium":
		return ansiStyled(label, ansiBgYellow, ansiBold)
	case "severity-low":
		return ansiStyled(label, ansiBgCyan, ansiBlue, ansiBold)
	default:
		return ansiStyled(label, ansiBgCyan, ansiBlue, ansiBold)
	}
}

func interactiveSeverityRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

func interactiveSeverityText(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return ansiStyled(s, ansiRed, ansiBold)
	case "high":
		return ansiStyled(s, ansiRed)
	case "medium":
		return ansiStyled(s, ansiYellow, ansiBold)
	case "low":
		return ansiStyled(s, ansiCyan)
	default:
		return ansiStyled(s, ansiDim)
	}
}

func interactiveStatusText(status string) string {
	status = valueOrDash(status)
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "self":
		return ansiStyled(status, ansiGreen, ansiBold)
	case "parent":
		return ansiStyled(status, ansiCyan, ansiBold)
	case "ancestor":
		return ansiStyled(status, ansiMagenta, ansiBold)
	case "root":
		return ansiStyled(status, ansiBlue, ansiBold)
	case "direct":
		return ansiStyled(status, ansiGreen, ansiBold)
	case "transitive":
		return ansiStyled(status, ansiMagenta, ansiBold)
	case "added":
		return ansiStyled(status, ansiGreen, ansiBold)
	case "removed":
		return ansiStyled(status, ansiRed, ansiBold)
	case "changed":
		return ansiStyled(status, ansiYellow, ansiBold)
	case "unchanged":
		return ansiStyled(status, ansiCyan, ansiBold)
	default:
		return ansiStyled(status, ansiWhite, ansiBold)
	}
}

func nextInteractiveRelationshipFilter(current string, explainMode bool) string {
	values := []string{"", "root", "direct", "transitive"}
	if explainMode {
		values = []string{"", "self", "parent", "ancestor", "root"}
	}
	return nextInteractiveFilterValue(current, values)
}

func nextInteractiveScopeFilter(current string) string {
	values := []string{"", "runtime", "development", "unset"}
	return nextInteractiveFilterValue(current, values)
}

func nextInteractiveSeverityFilter(current string) string {
	values := []string{"", "critical", "high", "medium", "low"}
	return nextInteractiveFilterValue(current, values)
}

// interactiveMaxSeverityByPkgID returns a map from package ID to the highest
// severity found across all vulnerability findings for that package.
func interactiveMaxSeverityByPkgID(findings []model.Finding) map[string]string {
	result := make(map[string]string)
	for _, f := range findings {
		if f.Kind != model.FindingKindVulnerability || f.Package == nil {
			continue
		}
		current := result[f.Package.ID]
		if interactiveSeverityRank(f.Severity) < interactiveSeverityRank(current) {
			result[f.Package.ID] = f.Severity
		}
	}
	return result
}

func nextInteractiveFilterValue(current string, values []string) string {
	for idx, value := range values {
		if value == current {
			return values[(idx+1)%len(values)]
		}
	}
	return values[0]
}

func filterInteractivePackageRows(rows []interactiveListPackageRow, relationshipFilter, scopeFilter string) []interactiveListPackageRow {
	if relationshipFilter == "" && scopeFilter == "" {
		return rows
	}
	filtered := make([]interactiveListPackageRow, 0, len(rows))
	for _, row := range rows {
		if relationshipFilter != "" && row.relationship != relationshipFilter {
			continue
		}
		if scopeFilter != "" {
			rowScope := row.scope
			if rowScope == "" {
				rowScope = "unset"
			}
			if rowScope != scopeFilter {
				continue
			}
		}
		filtered = append(filtered, row)
	}
	return filtered
}

func interactiveExplainRelationships(graphValue *model.Graph, targetID string) (map[string]string, map[string]int) {
	labels := make(map[string]string)
	counts := map[string]int{
		"self":     0,
		"parent":   0,
		"ancestor": 0,
		"root":     0,
	}
	if graphValue == nil || strings.TrimSpace(targetID) == "" {
		return labels, counts
	}
	targetPkg, ok := graphValue.Package(targetID)
	if ok && targetPkg != nil {
		labels[targetID] = "self"
		counts["self"]++
	}
	rootIDs := make(map[string]struct{})
	for _, pkg := range graphValue.Roots() {
		if pkg != nil {
			rootIDs[pkg.ID] = struct{}{}
		}
	}
	parents, _ := graphValue.Dependents(targetID)
	parentIDs := make(map[string]struct{}, len(parents))
	for _, pkg := range parents {
		if pkg == nil || pkg.ID == targetID {
			continue
		}
		parentIDs[pkg.ID] = struct{}{}
		if _, isRoot := rootIDs[pkg.ID]; isRoot {
			labels[pkg.ID] = "root"
			counts["root"]++
			continue
		}
		labels[pkg.ID] = "parent"
		counts["parent"]++
	}
	for _, pkg := range graphValue.Packages() {
		if pkg == nil || pkg.ID == targetID {
			continue
		}
		if _, ok := labels[pkg.ID]; ok {
			continue
		}
		if _, isRoot := rootIDs[pkg.ID]; isRoot {
			labels[pkg.ID] = "root"
			counts["root"]++
			continue
		}
		labels[pkg.ID] = "ancestor"
		counts["ancestor"]++
	}
	return labels, counts
}

func interactivePackageBadges(row interactiveListPackageRow) []interactiveBadge {
	badges := make([]interactiveBadge, 0, 1)
	switch row.scope {
	case "runtime":
		badges = append(badges, interactiveBadge{label: row.scope, kind: "scope-runtime"})
	case "development":
		badges = append(badges, interactiveBadge{label: row.scope, kind: "scope-development"})
	}
	return badges
}
