package tui

import (
	"fmt"
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

func formatFloat(value float64) string {
	if value == 0 {
		return ""
	}
	return fmt.Sprintf("%.1f", value)
}

func nonEmptyStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, strings.TrimSpace(value))
		}
	}
	return out
}

func exploitabilityLine(kev bool, known []sdk.KnownExploited, risk float64) string {
	parts := make([]string, 0, 2)
	if kev || len(known) > 0 {
		parts = append(parts, "known exploited")
	}
	if risk > 0 {
		parts = append(parts, fmt.Sprintf("risk %.1f", risk))
	}
	return strings.Join(parts, ", ")
}

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
		return terminalSafeBadge(label, render.BgYellow, render.Black)
	case "self":
		return terminalSafeBadge(label, render.BgBrand, render.White)
	case "parent":
		return terminalSafeBadge(label, render.BgBrand, render.White)
	case "ancestor":
		return terminalSafeBadge(label, render.BgBrand, render.White)
	case "root":
		return terminalSafeBadge(label, render.BgBrand, render.White)
	case "direct":
		return terminalSafeBadge(label, render.BgBrand, render.White)
	case "transitive":
		return terminalSafeBadge(label, render.BgBrand, render.White)
	case "added":
		return terminalSafeBadge(label, render.BgGreen, render.Black)
	case "removed":
		return terminalSafeBadge(label, render.BgRed, render.White)
	case "changed":
		return terminalSafeBadge(label, render.BgYellow, render.Black)
	case "unchanged":
		return terminalSafeBadge(label, render.BgNeutral, render.White)
	case "new": // audit-delta "introduced" (display-side label)
		return terminalSafeBadge(label, render.BgRed, render.White)
	case "old": // audit-delta "persisted"
		return terminalSafeBadge(label, render.BgYellow, render.Black)
	case "fixed": // audit-delta "resolved"
		return terminalSafeBadge(label, render.BgGreen, render.Black)
	case "retired": // license-delta "retired"
		return terminalSafeBadge(label, render.BgRed, render.White)
	case "introduced", "persisted", "resolved":
		// Internal data may still feed the long words through (older code
		// paths, tests). Translate to the short equivalent here and recurse
		// into the colored branches above for the same coloring.
		return statusBadge(auditStatusLabel(status))
	default:
		return terminalSafeBadge(label, render.BgNeutral, render.White)
	}
}

func badgeView(badge badge) string {
	label := " " + strings.ToUpper(valueOrDash(badge.label)) + " "
	switch badge.kind {
	case "scope-runtime":
		return terminalSafeBadge(label, render.BgGreen, render.Black)
	case "scope-development":
		return terminalSafeBadge(label, render.BgYellow, render.Black)
	case "severity-critical":
		return terminalSafeBadge(label, render.BgRed, render.White)
	case "severity-high":
		return terminalSafeBadge(label, render.BgRed, render.White)
	case "severity-medium":
		return terminalSafeBadge(label, render.BgYellow, render.Black)
	case "severity-low":
		return terminalSafeBadge(label, render.BgNeutral, render.White)
	case "reachability-reachable":
		return terminalSafeBadge(label, render.BgRed, render.White)
	case "reachability-unreachable":
		return terminalSafeBadge(label, render.BgNeutral, render.White)
	case "repeated":
		return terminalSafeBadge(label, render.BgNeutral, render.White)
	default:
		return terminalSafeBadge(label, render.BgNeutral, render.White)
	}
}

func terminalSafeBadge(label, background, foreground string) string {
	return render.Style(label, background, foreground, render.Bold)
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
	case "new":
		return render.Style(status, render.Red, render.Bold)
	case "old":
		return render.Style(status, render.Yellow, render.Bold)
	case "fixed":
		return render.Style(status, render.Green, render.Bold)
	case "retired":
		return render.Style(status, render.Red, render.Bold)
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
	values := []string{"", "any", "none", "critical", "high", "medium", "low"}
	return nextFilterValue(current, values)
}

// vulnsForDependency returns the matching-stage vulnerabilities for a
// dependency by resolving its PURL against the registry. Returns nil when
// either input is nil or the registry has no entry for the PURL.
func vulnsForDependency(registry *sdk.PackageRegistry, dep *sdk.Dependency) []sdk.Vulnerability {
	if registry == nil || dep == nil || dep.PURL == "" {
		return nil
	}
	pkg, ok := registry.Get(dep.PURL)
	if !ok || pkg == nil {
		return nil
	}
	return pkg.Vulnerabilities
}

// licensesForDependency returns the matching-stage licenses for a dependency
// when the registry has them; otherwise it falls back to the detection-time
// licenses stashed on the dependency.
func licensesForDependency(registry *sdk.PackageRegistry, dep *sdk.Dependency) []sdk.PackageLicense {
	if registry != nil && dep != nil && dep.PURL != "" {
		if pkg, ok := registry.Get(dep.PURL); ok && pkg != nil && len(pkg.Licenses) > 0 {
			return pkg.Licenses
		}
	}
	return sdk.DetectionLicenses(dep)
}

// maxVulnerabilitySeverityByPkgID returns a map from package ID to the
// highest severity found across that package's enriched vulnerabilities.
func maxVulnerabilitySeverityByPkgID(graphValue *sdk.Graph, registry *sdk.PackageRegistry) map[string]string {
	result := make(map[string]string)
	if graphValue == nil {
		return result
	}
	for _, pkg := range graphValue.Nodes() {
		if pkg == nil {
			continue
		}
		for _, vulnerability := range vulnsForDependency(registry, pkg) {
			current := result[pkg.ID]
			if severityRank(string(vulnerability.ParsedSeverity)) < severityRank(current) {
				result[pkg.ID] = string(vulnerability.ParsedSeverity)
			}
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
	targetPkg, ok := graphValue.Node(targetID)
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
	for _, pkg := range graphValue.Nodes() {
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
	if row.repeated {
		badges = append(badges, badge{label: "repeated", kind: "repeated"})
	}
	return badges
}
