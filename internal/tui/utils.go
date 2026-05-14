package tui

import (
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/cli/render"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// Text-formatting helpers live in internal/cli/render. Thin shims keep
// existing call sites in this package readable; new code should call the
// render package directly.
func wrapLines(lines []string, width int) []string   { return render.WrapLines(lines, width) }
func wrapTextLines(value string, width int) []string { return render.WrapTextLines(value, width) }
func truncateToWidth(value string, width int) string { return render.TruncateToWidth(value, width) }
func padRight(value string, width int) string        { return render.PadRight(value, width) }
func valueOrDash(value string) string                { return render.ValueOrDash(value) }

func boxView(title string, content []string, width, height int, color string) []string {
	if width < 4 {
		width = 4
	}
	if height < 2 {
		height = 2
	}
	inner := width - 2
	topLabel := ""
	if strings.TrimSpace(title) != "" {
		topLabel = " " + title + " "
		if len(render.StripANSI(topLabel)) > inner {
			topLabel = truncateToWidth(topLabel, inner)
		}
	}
	topFill := inner - len(render.StripANSI(topLabel))
	if topFill < 0 {
		topFill = 0
	}
	border := func(value string) string {
		if color == "" {
			return render.Style(value, render.Dim, render.Gray)
		}
		return render.Style(value, color)
	}
	lines := []string{border("┌" + topLabel + strings.Repeat("─", topFill) + "┐")}
	contentHeight := height - 2
	horizontalPadding := 1
	contentWidth := inner - horizontalPadding*2
	if contentWidth < 1 {
		horizontalPadding = 0
		contentWidth = inner
	}
	leftPad := strings.Repeat(" ", horizontalPadding)
	rightPad := strings.Repeat(" ", horizontalPadding)
	for idx := 0; idx < contentHeight; idx++ {
		line := ""
		if idx < len(content) {
			line = content[idx]
		}
		padded := leftPad + padRight(truncateToWidth(line, contentWidth), contentWidth) + rightPad
		lines = append(lines, border("│")+padded+border("│"))
	}
	lines = append(lines, border("└"+strings.Repeat("─", inner)+"┘"))
	return lines
}

func keyHint(key, label string) string {
	return render.Style(" "+key+" ", render.BgYellow, render.Bold) + label
}

func statusBar(value string, width int) string {
	if width <= 0 {
		return ""
	}
	return render.Style(padRight(truncateToWidth(value, width), width), render.BgBlue, render.White)
}

func centerLine(value string, width int) string {
	if width <= 0 {
		return ""
	}
	value = truncateToWidth(value, width)
	visible := len([]rune(render.StripANSI(value)))
	if visible >= width {
		return value
	}
	return strings.Repeat(" ", (width-visible)/2) + value
}

func joinColumns(left, right []string, leftWidth, rightWidth int) []string {
	height := len(left)
	if len(right) > height {
		height = len(right)
	}
	out := make([]string, 0, height)
	for idx := 0; idx < height; idx++ {
		l := ""
		if idx < len(left) {
			l = left[idx]
		}
		r := ""
		if idx < len(right) {
			r = right[idx]
		}
		out = append(out, padRight(l, leftWidth)+" "+padRight(r, rightWidth))
	}
	return out
}

func statusBadge(status string) string {
	label := " " + strings.ToUpper(valueOrDash(status)) + " "
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "manifest":
		return render.Style(label, render.BgBlue, render.Yellow, render.Bold)
	case "self":
		return render.Style(label, render.BgGreen, render.White, render.Bold)
	case "parent":
		return render.Style(label, render.BgCyan, render.White, render.Bold)
	case "ancestor":
		return render.Style(label, render.BgMagenta, render.White, render.Bold)
	case "root":
		return render.Style(label, render.BgBlue, render.White, render.Bold)
	case "direct":
		return render.Style(label, render.BgCyan, render.White, render.Bold)
	case "transitive":
		return render.Style(label, render.BgMagenta, render.White, render.Bold)
	case "added":
		return render.Style(label, render.BgGreen, render.White, render.Bold)
	case "removed":
		return render.Style(label, render.BgRed, render.White, render.Bold)
	case "changed":
		return render.Style(label, render.BgYellow, render.Bold)
	case "unchanged":
		return render.Style(label, render.BgBlue, render.White)
	default:
		return render.Style(label, render.BgCyan, render.Blue, render.Bold)
	}
}

func badgeView(badge badge) string {
	label := " " + strings.ToUpper(valueOrDash(badge.label)) + " "
	switch badge.kind {
	case "scope-runtime":
		return render.Style(label, render.BgGreen, render.White, render.Bold)
	case "scope-development":
		return render.Style(label, render.BgYellow, render.Bold)
	case "severity-critical":
		return render.Style(label, render.BgRed, render.White, render.Bold)
	case "severity-high":
		return render.Style(label, render.BgRed, render.White)
	case "severity-medium":
		return render.Style(label, render.BgYellow, render.Bold)
	case "severity-low":
		return render.Style(label, render.BgCyan, render.Blue, render.Bold)
	default:
		return render.Style(label, render.BgCyan, render.Blue, render.Bold)
	}
}

func severityRank(s string) int {
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

func severityText(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return render.Style(s, render.Red, render.Bold)
	case "high":
		return render.Style(s, render.Red)
	case "medium":
		return render.Style(s, render.Yellow, render.Bold)
	case "low":
		return render.Style(s, render.Cyan)
	default:
		return render.Style(s, render.Dim)
	}
}

func statusText(status string) string {
	status = valueOrDash(status)
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "self":
		return render.Style(status, render.Green, render.Bold)
	case "parent":
		return render.Style(status, render.Cyan, render.Bold)
	case "ancestor":
		return render.Style(status, render.Magenta, render.Bold)
	case "root":
		return render.Style(status, render.Blue, render.Bold)
	case "direct":
		return render.Style(status, render.Green, render.Bold)
	case "transitive":
		return render.Style(status, render.Magenta, render.Bold)
	case "added":
		return render.Style(status, render.Green, render.Bold)
	case "removed":
		return render.Style(status, render.Red, render.Bold)
	case "changed":
		return render.Style(status, render.Yellow, render.Bold)
	case "unchanged":
		return render.Style(status, render.Cyan, render.Bold)
	default:
		return render.Style(status, render.White, render.Bold)
	}
}

func nextRelationshipFilter(current string, explainMode bool) string {
	values := []string{"", "root", "direct", "transitive"}
	if explainMode {
		values = []string{"", "self", "parent", "ancestor", "root"}
	}
	return nextFilterValue(current, values)
}

func nextScopeFilter(current string) string {
	values := []string{"", "runtime", "development", "unset"}
	return nextFilterValue(current, values)
}

func nextSeverityFilter(current string) string {
	values := []string{"", "critical", "high", "medium", "low"}
	return nextFilterValue(current, values)
}

// maxSeverityByPkgID returns a map from package ID to the highest
// severity found across all vulnerability findings for that package.
func maxSeverityByPkgID(findings []sdk.Finding) map[string]string {
	result := make(map[string]string)
	for _, f := range findings {
		if f.Kind != sdk.FindingKindVulnerability || f.Package == nil {
			continue
		}
		current := result[f.Package.ID]
		if severityRank(f.Severity) < severityRank(current) {
			result[f.Package.ID] = f.Severity
		}
	}
	return result
}

func nextFilterValue(current string, values []string) string {
	for idx, value := range values {
		if value == current {
			return values[(idx+1)%len(values)]
		}
	}
	return values[0]
}

func filterPackageRows(rows []listPackageRow, relationshipFilter, scopeFilter string) []listPackageRow {
	if relationshipFilter == "" && scopeFilter == "" {
		return rows
	}
	filtered := make([]listPackageRow, 0, len(rows))
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

func explainRelationships(graphValue *sdk.Graph, targetID string) (map[string]string, map[string]int) {
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

func packageBadges(row listPackageRow) []badge {
	badges := make([]badge, 0, 1)
	switch row.scope {
	case "runtime":
		badges = append(badges, badge{label: row.scope, kind: "scope-runtime"})
	case "development":
		badges = append(badges, badge{label: row.scope, kind: "scope-development"})
	}
	return badges
}
