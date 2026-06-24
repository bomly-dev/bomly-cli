package render

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/sdk"
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
			{Title: "Project Posture", Lines: diffPostureMarkdown},
			{Title: "Policy Findings", Lines: diffPolicyFindingsMarkdown},
		},
	}, payload)
}

func diffOverviewMarkdown(payload output.DiffResponse) []string {
	introduced, persisted, resolved := 0, 0, 0
	if payload.Audit != nil {
		introduced = len(payload.Audit.Introduced)
		persisted = len(payload.Audit.Persisted)
		resolved = len(payload.Audit.Resolved)
	}
	status := "✅ Pass"
	if payload.Audit != nil && outputAuditFailingCount(payload.Audit.Introduced) > 0 {
		status = "❌ Failing findings introduced"
	} else if payload.Audit != nil && introduced > 0 {
		status = "⚠️ Warnings introduced"
	} else if payload.Audit != nil && outputAuditFailingCount(payload.Audit.Persisted) > 0 {
		status = "⚠️ Pre-existing findings unresolved"
	}
	return markdownTable(
		[]string{"Status", "Manifests", "Dependencies", "Findings", "Duration"},
		[][]string{{
			status,
			fmt.Sprintf("+%d / ~%d / -%d", payload.Summary.AddedManifestCount, payload.Summary.ChangedManifestCount, payload.Summary.RemovedManifestCount),
			fmt.Sprintf("+%d / ~%d / -%d", payload.Summary.AddedPackageCount, payload.Summary.ChangedPackageCount, payload.Summary.RemovedPackageCount),
			fmt.Sprintf("%d introduced / %d persisted / %d resolved", introduced, persisted, resolved),
			humanizeDurationMS(payload.Metadata.DurationMS),
		}},
	)
}

// humanizeDurationMS renders a millisecond duration in the largest sensible
// unit: milliseconds under a second, seconds under a minute, otherwise minutes
// and seconds.
func humanizeDurationMS(ms int64) string {
	if ms < 1000 {
		return fmt.Sprintf("%dms", ms)
	}
	if ms < 60000 {
		return fmt.Sprintf("%.1fs", float64(ms)/1000)
	}
	return fmt.Sprintf("%dm %ds", ms/60000, (ms%60000)/1000)
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
			directCell(pkg.Direct),
			displayScope(pkg.Scope),
			licenseList(pkg.Licenses),
		})
	}
	return append([]string{"### " + title, ""}, append(markdownTable([]string{"Change", "Package", "Version", "Direct?", "Scope", "Licenses"}, rows), "")...)
}

// directCell renders a package's directness for the dependency tables. nil
// (directness unknown, e.g. a flat SBOM) renders as a dash.
func directCell(direct *bool) string {
	if direct == nil {
		return "-"
	}
	if *direct {
		return "Yes"
	}
	return "No"
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
			directCell(change.After.Direct),
			displayScope(change.After.Scope),
			licenseList(change.After.Licenses),
		})
	}
	return append([]string{"### Changed Dependencies", ""}, append(markdownTable([]string{"Change", "Package", "Version", "Direct?", "Scope", "Licenses"}, rows), "")...)
}

func diffVulnerabilityMarkdown(payload output.DiffResponse) []string {
	results := payload.Results.Vulnerabilities
	if len(results.Added) == 0 && len(results.Removed) == 0 && len(results.Persisted) == 0 {
		return []string{"✅ No vulnerability changes."}
	}
	lines := []string{
		fmt.Sprintf("**Summary:** %d introduced, %d persisted, %d resolved.", len(results.Added), len(results.Persisted), len(results.Removed)),
		"",
	}
	if len(results.Added) == 0 && len(results.Removed) == 0 && len(results.Persisted) > 0 {
		lines = append(lines, fmt.Sprintf("⚠️ No new or resolved vulnerabilities, but %s — the updated version is still affected.", pluralizeVulnerabilities(len(results.Persisted)))+" This change does not remediate them.", "")
	}
	lines = append(lines, diffVulnerabilityTable("Introduced Vulnerabilities", "introduced", results.Added, payload.Metadata.ReachabilityEnabled)...)
	lines = append(lines, diffVulnerabilityTable("Persisted Vulnerabilities", "persisted", results.Persisted, payload.Metadata.ReachabilityEnabled)...)
	lines = append(lines, diffVulnerabilityTable("Resolved Vulnerabilities", "resolved", results.Removed, payload.Metadata.ReachabilityEnabled)...)
	return trimTrailingMarkdownBlanks(lines)
}

func pluralizeVulnerabilities(n int) string {
	if n == 1 {
		return "1 vulnerability persists"
	}
	return fmt.Sprintf("%d vulnerabilities persist", n)
}

func diffVulnerabilityTable(title, status string, changes []output.DiffVulnerabilityChange, includeReachability bool) []string {
	if len(changes) == 0 {
		return nil
	}
	rows := make([][]string, 0, len(changes))
	for _, change := range sortVulnerabilityChanges(changes) {
		vuln := change.Vulnerability
		row := []string{
			findingIcon(status, string(vuln.Severity), ""),
			status,
			strings.ToUpper(valueOrDash(string(vuln.Severity))),
			vuln.ID,
			DiffPackageDisplayName(change.Package),
		}
		if includeReachability {
			row = append(row, valueOrDash(formatReachabilityCell(vuln.Reachability)))
		}
		row = append(row,
			valueOrDash(fixedVersionSummary(vuln.FixedIn, vuln.FixedVersions)),
			valueOrDash(vuln.Source),
			firstNonEmpty(vuln.Title, strings.Join(vuln.Reasons, "; ")),
		)
		rows = append(rows, row)
	}
	header := []string{"", "Change", "Severity", "ID", "Package"}
	if includeReachability {
		header = append(header, "Reachability")
	}
	header = append(header, "Fixed In", "Source", "Title")
	return append([]string{"### " + title, ""}, append(markdownTable(header, rows), "")...)
}

func diffLicenseMarkdown(payload output.DiffResponse) []string {
	results := payload.Results.Licenses
	persisted := persistedLicenseFindingCount(payload.Audit)
	if len(results.Added) == 0 && len(results.Changed) == 0 && len(results.Removed) == 0 {
		if persisted > 0 {
			return []string{licensePersistedNote(persisted)}
		}
		return []string{"✅ No license changes."}
	}
	lines := []string{
		fmt.Sprintf("**Summary:** %d added, %d changed, %d removed.", len(results.Added), len(results.Changed), len(results.Removed)),
		"",
	}
	if persisted > 0 {
		lines = append(lines, licensePersistedNote(persisted), "")
	}
	lines = append(lines, diffLicenseChangeTable("Added Licenses", "added", results.Added)...)
	lines = append(lines, diffLicenseDeltaTable(results.Changed)...)
	lines = append(lines, diffLicenseChangeTable("Removed Licenses", "removed", results.Removed)...)
	return trimTrailingMarkdownBlanks(lines)
}

// persistedLicenseFindingCount counts distinct packages with a license finding
// that survived the diff (present before and after) so the License section can
// flag that the change did not resolve them, mirroring the persisted-
// vulnerability messaging. Deduplicated by package so the count matches the
// "N packages" wording in licensePersistedNote even if a package ever carries
// more than one persisted license finding.
func persistedLicenseFindingCount(audit *output.DiffAudit) int {
	if audit == nil {
		return 0
	}
	packages := map[string]struct{}{}
	for _, finding := range audit.Persisted {
		if finding.Kind == sdk.FindingKindLicense {
			packages[finding.Package.ID] = struct{}{}
		}
	}
	return len(packages)
}

func licensePersistedNote(n int) string {
	if n == 1 {
		return "⚠️ 1 package still carries an unresolved license issue (see Policy Findings)."
	}
	return fmt.Sprintf("⚠️ %d packages still carry unresolved license issues (see Policy Findings).", n)
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
		diffPolicySummary(audit),
		"",
	}
	lines = append(lines, diffAuditFindingTable("Introduced Findings", "introduced", audit.Introduced, payload.Metadata.ReachabilityEnabled)...)
	lines = append(lines, diffAuditFindingTable("Persisted Findings", "persisted", audit.Persisted, payload.Metadata.ReachabilityEnabled)...)
	lines = append(lines, diffAuditFindingTable("Resolved Findings", "resolved", audit.Resolved, payload.Metadata.ReachabilityEnabled)...)
	if len(audit.Introduced) == 0 && len(audit.Persisted) == 0 && len(audit.Resolved) == 0 {
		return []string{"✅ No policy differences were identified."}
	}
	lines = append(lines, findingIconLegend()...)
	return trimTrailingMarkdownBlanks(lines)
}

func diffPolicySummary(audit *output.DiffAudit) string {
	parts := []string{
		fmt.Sprintf("%d introduced", len(audit.Introduced)),
		fmt.Sprintf("%d persisted", len(audit.Persisted)),
		fmt.Sprintf("%d resolved", len(audit.Resolved)),
	}
	return "**Summary:** " + strings.Join(parts, ", ") + "."
}

func diffAuditFindingTable(title, status string, findings []output.AuditFinding, includeReachability bool) []string {
	if len(findings) == 0 {
		return nil
	}
	rows := make([][]string, 0, len(findings))
	for _, finding := range sortDiffAuditFindings(findings) {
		row := []string{
			findingIcon(status, string(finding.Severity), string(finding.Disposition)),
			status,
			valueOrDash(finding.Auditor),
			strings.ToUpper(valueOrDash(string(finding.Severity))),
			valueOrDash(finding.ID),
			DiffPackageDisplayName(finding.Package),
		}
		if includeReachability {
			row = append(row, valueOrDash(formatReachabilityCell(finding.Reachability)))
		}
		row = append(row,
			valueOrDash(fixedVersionSummary(finding.FixedIn, finding.FixedVersions)),
			firstNonEmpty(finding.Title, strings.Join(finding.Reasons, "; ")),
		)
		rows = append(rows, row)
	}
	header := []string{"", "Status", "Category", "Severity", "ID", "Package"}
	if includeReachability {
		header = append(header, "Reachability")
	}
	header = append(header, "Fixed In", "Title")
	return append([]string{"### " + title, ""}, append(markdownTable(header, rows), "")...)
}

// findingIconLegend explains the leading status icon used in the findings
// tables. The icon encodes the finding's disposition (resolved / failing /
// warning), which is why a dedicated column is no longer needed.
func findingIconLegend() []string {
	return []string{"> **Legend:** ✅ resolved · ❌ failing · ⚠️ warning"}
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
		if severityRankTable(string(sorted[i].Vulnerability.Severity)) != severityRankTable(string(sorted[j].Vulnerability.Severity)) {
			return severityRankTable(string(sorted[i].Vulnerability.Severity)) < severityRankTable(string(sorted[j].Vulnerability.Severity))
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
