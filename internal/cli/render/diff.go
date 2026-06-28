package render

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// Diff writes the compact human-readable diff report for the diff command.
func Diff(w io.Writer, payload output.DiffResponse) error {
	var lines []string
	lines = append(lines, dependencyTextSections(payload.Results.Dependencies)...)
	lines = append(lines, findingsSummaryLine(payload.Audit)...)
	for _, line := range lines {
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return nil
}

func dependencyTextSections(results output.DiffDependencyResults) []string {
	var lines []string
	nameWidth := dependencyNameWidth(results)
	appendAdded := func() {
		if len(results.Added) == 0 {
			return
		}
		lines = append(lines, Style(fmt.Sprintf("Added (%d)", len(results.Added)), Bold))
		for _, change := range results.Added {
			pkg := change.Package
			vulns := vulnCountsForPackageRef(pkg)
			line := fmt.Sprintf("  + %-*s  %-8s %s%s", nameWidth, DiffPackageDisplayName(pkg), primaryLicense(pkg), displayScope(pkg.Scope), vulns)
			lines = append(lines, Wrap(strings.TrimRight(line, " "), Green))
		}
	}
	appendRemoved := func() {
		if len(results.Removed) == 0 {
			return
		}
		lines = append(lines, Style(fmt.Sprintf("Removed (%d)", len(results.Removed)), Bold))
		for _, change := range results.Removed {
			line := fmt.Sprintf("  - %s", DiffPackageDisplayName(change.Package))
			lines = append(lines, Wrap(line, Red))
		}
	}
	appendChanged := func() {
		if len(results.Changed) == 0 {
			return
		}
		lines = append(lines, Style(fmt.Sprintf("Changed (%d)", len(results.Changed)), Bold))
		for _, change := range results.Changed {
			name := change.After.Name
			if strings.TrimSpace(name) == "" {
				name = change.After.ID
			}
			line := fmt.Sprintf("  ~ %-*s  %s → %s", changedNameWidth(results), name, change.Before.Version, change.After.Version)
			lines = append(lines, Wrap(line, Yellow))
		}
	}
	appendAdded()
	appendRemoved()
	appendChanged()
	if len(lines) == 0 {
		lines = append(lines, Style("No dependency changes.", Dim))
	}
	return lines
}

// findingsSummaryLine produces a summary line plus a list of each introduced or
// persisted finding when audit data is present. N/A-severity findings (e.g. unknown
// license) are omitted — they belong in the policy section, not the compact
// summary. The summary intentionally omits a severity qualifier so it stays
// accurate when only low/medium findings are introduced or persisted.
func findingsSummaryLine(audit *output.DiffAudit) []string {
	if audit == nil {
		return nil
	}
	findings := compactAuditFindings(audit)
	introduced, persisted := auditStatusCounts(findings)
	if len(findings) == 0 {
		return []string{"", Style("No findings introduced or persisted.", Gray)}
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].status != findings[j].status {
			return findings[i].status < findings[j].status
		}
		si := severityRankTable(string(findings[i].finding.Severity))
		sj := severityRankTable(string(findings[j].finding.Severity))
		if si != sj {
			return si < sj
		}
		return findings[i].finding.ID < findings[j].finding.ID
	})

	maxIDWidth := 0
	maxStatusWidth := 0
	for _, item := range findings {
		if l := len(item.finding.ID); l > maxIDWidth {
			maxIDWidth = l
		}
		if l := len(item.status); l > maxStatusWidth {
			maxStatusWidth = l
		}
	}

	lines := []string{"", Style(compactAuditSummary(introduced, persisted), Red)}
	for _, item := range findings {
		f := item.finding
		pkg := DiffPackageDisplayName(f.Package)
		if pkg == "" {
			pkg = "-"
		}
		lines = append(lines, fmt.Sprintf("  %-*s  %s  %-*s  %s", maxStatusWidth, item.status, severityLabelFixed(string(f.Severity)), maxIDWidth, f.ID, pkg))
	}
	return lines
}

type compactAuditFinding struct {
	status  string
	finding output.AuditFinding
}

func compactAuditFindings(audit *output.DiffAudit) []compactAuditFinding {
	var findings []compactAuditFinding
	appendFindings := func(status string, src []output.AuditFinding) {
		for _, f := range src {
			sev := strings.ToLower(strings.TrimSpace(string(f.Severity)))
			if sev == "n/a" || sev == "" {
				continue
			}
			findings = append(findings, compactAuditFinding{status: status, finding: f})
		}
	}
	appendFindings("introduced", audit.Introduced)
	appendFindings("persisted", audit.Persisted)
	return findings
}

func auditStatusCounts(findings []compactAuditFinding) (introduced, persisted int) {
	for _, item := range findings {
		switch item.status {
		case "introduced":
			introduced++
		case "persisted":
			persisted++
		}
	}
	return introduced, persisted
}

func compactAuditSummary(introduced, persisted int) string {
	switch {
	case introduced > 0 && persisted > 0:
		return fmt.Sprintf("%d new finding(s) introduced; %d finding(s) persisted.", introduced, persisted)
	case introduced > 0:
		return fmt.Sprintf("%d new finding(s) introduced.", introduced)
	default:
		return fmt.Sprintf("%d finding(s) persisted.", persisted)
	}
}

// vulnCountsForPackageRef returns a compact coloured vuln-count string like " 1H 2M"
// from an output.PackageRef's pre-populated Vulnerabilities slice. Returns "" when empty.
func vulnCountsForPackageRef(pkg output.PackageRef) string {
	var critical, high, medium, low int
	for _, v := range pkg.Vulnerabilities {
		switch strings.ToLower(string(v.Severity)) {
		case "critical":
			critical++
		case "high":
			high++
		case "medium":
			medium++
		case "low":
			low++
		}
	}
	var parts []string
	if critical > 0 {
		parts = append(parts, Style(fmt.Sprintf("%dC", critical), Red, Bold))
	}
	if high > 0 {
		parts = append(parts, Style(fmt.Sprintf("%dH", high), Red))
	}
	if medium > 0 {
		parts = append(parts, Style(fmt.Sprintf("%dM", medium), Yellow, Bold))
	}
	if low > 0 {
		parts = append(parts, Style(fmt.Sprintf("%dL", low), Cyan))
	}
	if len(parts) == 0 {
		return ""
	}
	return "  " + strings.Join(parts, " ")
}

func dependencyNameWidth(results output.DiffDependencyResults) int {
	width := 0
	for _, change := range results.Added {
		width = max(width, len(DiffPackageDisplayName(change.Package)))
	}
	return width
}

func changedNameWidth(results output.DiffDependencyResults) int {
	width := 0
	for _, change := range results.Changed {
		name := change.After.Name
		if name == "" {
			name = change.After.ID
		}
		width = max(width, len(name))
	}
	return width
}

func primaryLicense(pkg output.PackageRef) string {
	if len(pkg.Licenses) == 0 {
		return "-"
	}
	if value := pkg.Licenses[0].Identifier(); value != "" {
		return value
	}
	return "-"
}

func displayScope(scope string) string {
	if strings.TrimSpace(scope) == "" {
		return "unknown"
	}
	return scope
}

func licenseList(values []output.LicenseRef) string {
	if len(values) == 0 {
		return "-"
	}
	licenses := make([]string, 0, len(values))
	for _, value := range values {
		if id := value.Identifier(); id != "" {
			licenses = append(licenses, id)
		}
	}
	if len(licenses) == 0 {
		return "-"
	}
	sort.Strings(licenses)
	return strings.Join(licenses, ", ")
}

func diffAuditFindingsSummary(summary *output.AuditSummary) string {
	if summary == nil || summary.Total == 0 {
		return "no active findings were reported"
	}
	return formatAuditSummary(summary, true)
}

func sortDiffAuditFindings(findings []output.AuditFinding) []output.AuditFinding {
	sorted := append([]output.AuditFinding(nil), findings...)
	sort.Slice(sorted, func(i, j int) bool {
		si := severityRankTable(string(sorted[i].Severity))
		sj := severityRankTable(string(sorted[j].Severity))
		if si != sj {
			return si < sj
		}
		if sorted[i].ID != sorted[j].ID {
			return sorted[i].ID < sorted[j].ID
		}
		pi := DiffPackageDisplayName(sorted[i].Package)
		pj := DiffPackageDisplayName(sorted[j].Package)
		if pi != pj {
			return pi < pj
		}
		return sorted[i].Title < sorted[j].Title
	})
	return sorted
}

// DiffPackageDisplayName returns a human-readable label for a package.
func DiffPackageDisplayName(pkg output.PackageRef) string {
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

// DiffManifestDisplayLabel returns a human-readable label for a manifest in diff output.
func DiffManifestDisplayLabel(manifest output.DiffManifestResult) string {
	label := manifest.Path
	if strings.TrimSpace(label) == "" {
		label = string(manifest.Kind)
	}
	if strings.TrimSpace(manifest.PackageManager.Name()) != "" {
		return fmt.Sprintf("%s (%s)", label, manifest.PackageManager)
	}
	return label
}

// fixedVersionSummary and exploitabilitySummary are retained for markdown
// renderers that still use them.
func diffVulnerabilityDetails(vulnerability output.VulnerabilityRef, includeReachability bool) string {
	if !includeReachability {
		return ""
	}
	return " [" + "reachability " + formatReachabilityCell(vulnerability.Reachability) + "]"
}

// Ensure sdk import is used (formatReachabilityCell references sdk.Reachability).
var _ = sdk.Reachability{}
