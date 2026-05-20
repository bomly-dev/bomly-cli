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
			{Title: "Overview", Lines: diffOverviewMarkdown},
			{Title: "Dependency Changes", Lines: diffDependencyMarkdown},
			{Title: "Vulnerabilities", Lines: diffVulnerabilityMarkdown},
			{Title: "License Changes", Lines: diffLicenseMarkdown},
			{Title: "Policy Findings", Lines: diffPolicyFindingsMarkdown},
		},
	}, payload)
}

func diffOverviewMarkdown(payload output.DiffResponse) []string {
	audit := payload.Audit
	introduced, persisted, resolved := 0, 0, 0
	if audit != nil {
		introduced = len(audit.Introduced)
		persisted = len(audit.Persisted)
		resolved = len(audit.Resolved)
	}
	status := "✅ Pass"
	if audit != nil && outputAuditFailingCount(audit.Introduced) > 0 {
		status = "❌ Failing findings introduced"
	} else if audit != nil && introduced > 0 {
		status = "⚠️ Warnings introduced"
	}
	return markdownTable(
		[]string{"Status", "Manifests", "Dependencies", "Findings", "Duration"},
		[][]string{{
			status,
			fmt.Sprintf("+%d / ~%d / -%d", payload.Summary.AddedManifestCount, payload.Summary.ChangedManifestCount, payload.Summary.RemovedManifestCount),
			fmt.Sprintf("+%d / ~%d / -%d", payload.Summary.AddedPackageCount, payload.Summary.ChangedPackageCount, payload.Summary.RemovedPackageCount),
			fmt.Sprintf("%d introduced / %d persisted / %d resolved", introduced, persisted, resolved),
			fmt.Sprintf("%dms", payload.Metadata.DurationMS),
		}},
	)
}

func diffDependencyMarkdown(payload output.DiffResponse) []string {
	results := payload.Results.Dependencies
	lines := []string{
		fmt.Sprintf("**Summary:** %d added, %d changed, %d removed.", len(results.Added), len(results.Changed), len(results.Removed)),
		"",
	}
	lines = append(lines, diffAddedRemovedDependencyTable("Added Dependencies", "added", results.Added)...)
	lines = append(lines, diffChangedDependencyTable(results.Changed)...)
	lines = append(lines, diffAddedRemovedDependencyTable("Removed Dependencies", "removed", results.Removed)...)
	if len(results.Added) == 0 && len(results.Changed) == 0 && len(results.Removed) == 0 {
		return []string{"✅ No dependency changes."}
	}
	return trimTrailingMarkdownBlanks(lines)
}

func diffAddedRemovedDependencyTable(title, status string, changes []output.DiffPackageChange) []string {
	if len(changes) == 0 {
		return nil
	}
	rows := make([][]string, 0, len(changes))
	for _, change := range sortPackageChanges(changes) {
		pkg := change.Package
		rows = append(rows, []string{
			status,
			DiffPackageDisplayName(pkg),
			valueOrDash(pkg.Version),
			displayScope(pkg.Scope),
			licenseList(pkg.Licenses),
			valueOrDash(pkg.Purl),
		})
	}
	return append([]string{"### " + title, ""}, append(markdownTable([]string{"Change", "Package", "Version", "Scope", "Licenses", "PURL"}, rows), "")...)
}

func diffChangedDependencyTable(changes []output.DiffChangedPackage) []string {
	if len(changes) == 0 {
		return nil
	}
	rows := make([][]string, 0, len(changes))
	for _, change := range sortChangedPackages(changes) {
		name := change.After.Name
		if strings.TrimSpace(name) == "" {
			name = change.After.ID
		}
		rows = append(rows, []string{
			"changed",
			name,
			fmt.Sprintf("%s → %s", valueOrDash(change.Before.Version), valueOrDash(change.After.Version)),
			displayScope(change.After.Scope),
			licenseList(change.After.Licenses),
			valueOrDash(change.After.Purl),
		})
	}
	return append([]string{"### Changed Dependencies", ""}, append(markdownTable([]string{"Change", "Package", "Version", "Scope", "Licenses", "PURL"}, rows), "")...)
}

func diffVulnerabilityMarkdown(payload output.DiffResponse) []string {
	results := payload.Results.Vulnerabilities
	lines := []string{
		fmt.Sprintf("**Summary:** %d introduced, %d resolved.", len(results.Added), len(results.Removed)),
		"",
	}
	lines = append(lines, diffVulnerabilityTable("Introduced Vulnerabilities", "introduced", results.Added)...)
	lines = append(lines, diffVulnerabilityTable("Resolved Vulnerabilities", "resolved", results.Removed)...)
	if len(results.Added) == 0 && len(results.Removed) == 0 {
		return []string{"✅ No vulnerability changes."}
	}
	return trimTrailingMarkdownBlanks(lines)
}

func diffVulnerabilityTable(title, status string, changes []output.DiffVulnerabilityChange) []string {
	if len(changes) == 0 {
		return nil
	}
	rows := make([][]string, 0, len(changes))
	for _, change := range sortVulnerabilityChanges(changes) {
		vuln := change.Vulnerability
		rows = append(rows, []string{
			findingIcon(status, vuln.Severity, ""),
			status,
			strings.ToUpper(valueOrDash(vuln.Severity)),
			vuln.ID,
			DiffPackageDisplayName(change.Package),
			valueOrDash(vuln.FixedIn),
			valueOrDash(vuln.Source),
			firstNonEmpty(vuln.Title, strings.Join(vuln.Reasons, "; ")),
		})
	}
	return append([]string{"### " + title, ""}, append(markdownTable([]string{"", "Change", "Severity", "ID", "Package", "Fixed In", "Source", "Title"}, rows), "")...)
}

func diffLicenseMarkdown(payload output.DiffResponse) []string {
	results := payload.Results.Licenses
	lines := []string{
		fmt.Sprintf("**Summary:** %d added, %d changed, %d removed.", len(results.Added), len(results.Changed), len(results.Removed)),
		"",
	}
	lines = append(lines, diffLicenseChangeTable("Added Licenses", "added", results.Added)...)
	lines = append(lines, diffLicenseDeltaTable(results.Changed)...)
	lines = append(lines, diffLicenseChangeTable("Removed Licenses", "removed", results.Removed)...)
	if len(results.Added) == 0 && len(results.Changed) == 0 && len(results.Removed) == 0 {
		return []string{"✅ No license changes."}
	}
	return trimTrailingMarkdownBlanks(lines)
}

func diffLicenseChangeTable(title, status string, changes []output.DiffLicenseChange) []string {
	if len(changes) == 0 {
		return nil
	}
	rows := make([][]string, 0, len(changes))
	for _, change := range sortLicenseChanges(changes) {
		rows = append(rows, []string{
			status,
			DiffPackageDisplayName(change.Package),
			licenseList(change.Licenses),
		})
	}
	return append([]string{"### " + title, ""}, append(markdownTable([]string{"Change", "Package", "Licenses"}, rows), "")...)
}

func diffLicenseDeltaTable(changes []output.DiffLicenseDelta) []string {
	if len(changes) == 0 {
		return nil
	}
	rows := make([][]string, 0, len(changes))
	for _, change := range sortLicenseDeltas(changes) {
		rows = append(rows, []string{
			"changed",
			DiffPackageDisplayName(change.Package),
			licenseList(change.Before),
			licenseList(change.After),
		})
	}
	return append([]string{"### Changed Licenses", ""}, append(markdownTable([]string{"Change", "Package", "Before", "After"}, rows), "")...)
}

func diffPolicyFindingsMarkdown(payload output.DiffResponse) []string {
	if payload.Audit == nil {
		return []string{"Policy evaluation was not included."}
	}
	audit := payload.Audit
	lines := []string{
		fmt.Sprintf("**Summary:** %d introduced, %d persisted, %d resolved.", len(audit.Introduced), len(audit.Persisted), len(audit.Resolved)),
		"",
	}
	lines = append(lines, diffAuditFindingTable("Introduced Findings", "introduced", audit.Introduced)...)
	lines = append(lines, diffAuditFindingTable("Persisted Findings", "persisted", audit.Persisted)...)
	lines = append(lines, diffAuditFindingTable("Resolved Findings", "resolved", audit.Resolved)...)
	if len(audit.Introduced) == 0 && len(audit.Persisted) == 0 && len(audit.Resolved) == 0 {
		return []string{"✅ No policy differences were identified."}
	}
	return trimTrailingMarkdownBlanks(lines)
}

func diffAuditFindingTable(title, status string, findings []output.AuditFinding) []string {
	if len(findings) == 0 {
		return nil
	}
	rows := make([][]string, 0, len(findings))
	for _, finding := range sortDiffAuditFindings(findings) {
		rows = append(rows, []string{
			findingIcon(status, finding.Severity, finding.Disposition),
			status,
			valueOrDash(finding.Auditor),
			strings.ToUpper(valueOrDash(finding.Severity)),
			findingDisposition(finding.Disposition),
			valueOrDash(finding.ID),
			DiffPackageDisplayName(finding.Package),
			valueOrDash(finding.FixedIn),
			firstNonEmpty(finding.Title, strings.Join(finding.Reasons, "; ")),
		})
	}
	return append([]string{"### " + title, ""}, append(markdownTable([]string{"", "Status", "Category", "Severity", "Disposition", "ID", "Package", "Fixed In", "Title"}, rows), "")...)
}

func findingIcon(status, severity, disposition string) string {
	if status == "resolved" {
		return "✅"
	}
	if strings.EqualFold(disposition, "warn") {
		return "⚠️"
	}
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "high":
		return "❌"
	default:
		return "⚠️"
	}
}

func findingDisposition(value string) string {
	if strings.TrimSpace(value) == "" {
		return "fail"
	}
	return value
}

func outputAuditFailingCount(findings []output.AuditFinding) int {
	total := 0
	for _, finding := range findings {
		if finding.Disposition == "" || finding.Disposition == "fail" {
			total++
		}
	}
	return total
}

func sortPackageChanges(changes []output.DiffPackageChange) []output.DiffPackageChange {
	sorted := append([]output.DiffPackageChange(nil), changes...)
	sort.Slice(sorted, func(i, j int) bool {
		return DiffPackageDisplayName(sorted[i].Package) < DiffPackageDisplayName(sorted[j].Package)
	})
	return sorted
}

func sortChangedPackages(changes []output.DiffChangedPackage) []output.DiffChangedPackage {
	sorted := append([]output.DiffChangedPackage(nil), changes...)
	sort.Slice(sorted, func(i, j int) bool {
		return DiffPackageDisplayName(sorted[i].After) < DiffPackageDisplayName(sorted[j].After)
	})
	return sorted
}

func sortVulnerabilityChanges(changes []output.DiffVulnerabilityChange) []output.DiffVulnerabilityChange {
	sorted := append([]output.DiffVulnerabilityChange(nil), changes...)
	sort.Slice(sorted, func(i, j int) bool {
		if severityRankTable(sorted[i].Vulnerability.Severity) != severityRankTable(sorted[j].Vulnerability.Severity) {
			return severityRankTable(sorted[i].Vulnerability.Severity) < severityRankTable(sorted[j].Vulnerability.Severity)
		}
		if sorted[i].Vulnerability.ID != sorted[j].Vulnerability.ID {
			return sorted[i].Vulnerability.ID < sorted[j].Vulnerability.ID
		}
		return DiffPackageDisplayName(sorted[i].Package) < DiffPackageDisplayName(sorted[j].Package)
	})
	return sorted
}

func sortLicenseChanges(changes []output.DiffLicenseChange) []output.DiffLicenseChange {
	sorted := append([]output.DiffLicenseChange(nil), changes...)
	sort.Slice(sorted, func(i, j int) bool {
		return DiffPackageDisplayName(sorted[i].Package) < DiffPackageDisplayName(sorted[j].Package)
	})
	return sorted
}

func sortLicenseDeltas(changes []output.DiffLicenseDelta) []output.DiffLicenseDelta {
	sorted := append([]output.DiffLicenseDelta(nil), changes...)
	sort.Slice(sorted, func(i, j int) bool {
		return DiffPackageDisplayName(sorted[i].Package) < DiffPackageDisplayName(sorted[j].Package)
	})
	return sorted
}

func valueOrDash(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return "-"
}
