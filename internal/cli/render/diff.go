package render

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/output"
)

// DiffManifestStatusOrder returns the sort rank for a diff manifest status.
func DiffManifestStatusOrder(status string) int {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "removed":
		return 0
	case "added":
		return 1
	case "changed":
		return 2
	case "unchanged":
		return 3
	default:
		return 99
	}
}

// Diff writes the human-readable diff report for the diff command.
func Diff(w io.Writer, payload output.DiffResponse) error {
	lines := []string{
		fmt.Sprintf("Dependency diff %s -> %s", payload.Comparison.Base, payload.Comparison.Head),
		fmt.Sprintf(
			"Matches: %d exact, %d fuzzy, %d unmatched",
			payload.Summary.ExactMatchCount,
			payload.Summary.FuzzyMatchCount,
			payload.Summary.UnmatchedPackageCount,
		),
		"",
	}
	lines = append(lines, dependencyTextSections(payload.Results.Dependencies)...)
	lines = append(lines, licenseTextSections(payload.Results.Licenses)...)
	lines = append(lines, vulnerabilityTextSections(payload.Results.Vulnerabilities, payload.Metadata.ReachabilityEnabled)...)
	if section := postureTextSections(payload.Results.Dependencies); len(section) > 0 {
		lines = append(lines, section...)
	}
	if payload.Audit != nil {
		lines = append(lines, policyTextSections(*payload.Audit, payload.Metadata.ReachabilityEnabled)...)
	}
	for _, line := range lines {
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return nil
}

func dependencyTextSections(results output.DiffDependencyResults) []string {
	lines := []string{"Dependencies"}
	nameWidth := dependencyNameWidth(results)
	appendAdded := func() {
		if len(results.Added) == 0 {
			return
		}
		lines = append(lines, fmt.Sprintf("Added (%d)", len(results.Added)))
		for _, change := range results.Added {
			pkg := change.Package
			line := fmt.Sprintf("  + %-*s  %-8s %s", nameWidth, DiffPackageDisplayName(pkg), primaryLicense(pkg), displayScope(pkg.Scope))
			lines = append(lines, Wrap(strings.TrimRight(line, " "), Green))
		}
	}
	appendRemoved := func() {
		if len(results.Removed) == 0 {
			return
		}
		lines = append(lines, fmt.Sprintf("Removed (%d)", len(results.Removed)))
		for _, change := range results.Removed {
			line := fmt.Sprintf("  - %s", DiffPackageDisplayName(change.Package))
			lines = append(lines, Wrap(line, Red))
		}
	}
	appendChanged := func() {
		if len(results.Changed) == 0 {
			return
		}
		lines = append(lines, fmt.Sprintf("Changed (%d)", len(results.Changed)))
		for _, change := range results.Changed {
			name := change.After.Name
			if strings.TrimSpace(name) == "" {
				name = change.After.ID
			}
			line := fmt.Sprintf("  ~ %-*s  %s -> %s", changedNameWidth(results), name, change.Before.Version, change.After.Version)
			lines = append(lines, Wrap(line, Yellow))
		}
	}
	appendAdded()
	appendRemoved()
	appendChanged()
	if len(lines) == 1 {
		lines = append(lines, "  No dependency changes.")
	}
	lines = append(lines, "")
	return lines
}

func licenseTextSections(results output.DiffLicenseResults) []string {
	lines := []string{"Licenses"}
	if len(results.Added) == 0 && len(results.Removed) == 0 && len(results.Changed) == 0 {
		return append(lines, "  No license changes.", "")
	}
	if len(results.Added) > 0 {
		lines = append(lines, fmt.Sprintf("Added (%d)", len(results.Added)))
		for _, change := range results.Added {
			lines = append(lines, Wrap(fmt.Sprintf("  + %s  %s", DiffPackageDisplayName(change.Package), licenseList(change.Licenses)), Green))
		}
	}
	if len(results.Removed) > 0 {
		lines = append(lines, fmt.Sprintf("Removed (%d)", len(results.Removed)))
		for _, change := range results.Removed {
			lines = append(lines, Wrap(fmt.Sprintf("  - %s  %s", DiffPackageDisplayName(change.Package), licenseList(change.Licenses)), Red))
		}
	}
	if len(results.Changed) > 0 {
		lines = append(lines, fmt.Sprintf("Changed (%d)", len(results.Changed)))
		for _, change := range results.Changed {
			lines = append(lines, Wrap(fmt.Sprintf("  ~ %s  %s -> %s", DiffPackageDisplayName(change.Package), licenseList(change.Before), licenseList(change.After)), Yellow))
		}
	}
	return append(lines, "")
}

func vulnerabilityTextSections(results output.DiffVulnerabilityResults, includeReachability bool) []string {
	lines := []string{"Vulnerabilities"}
	if len(results.Added) == 0 && len(results.Removed) == 0 {
		return append(lines, "  No vulnerability changes.", "")
	}
	if len(results.Added) > 0 {
		lines = append(lines, fmt.Sprintf("Added (%d)", len(results.Added)))
		for _, change := range results.Added {
			details := diffVulnerabilityDetails(change.Vulnerability, includeReachability)
			lines = append(lines, Wrap(fmt.Sprintf("  + [%s] %s  %s%s", strings.ToUpper(ValueOrDash(change.Vulnerability.Severity)), change.Vulnerability.ID, DiffPackageDisplayName(change.Package), details), Red))
		}
	}
	if len(results.Removed) > 0 {
		lines = append(lines, fmt.Sprintf("Removed (%d)", len(results.Removed)))
		for _, change := range results.Removed {
			details := diffVulnerabilityDetails(change.Vulnerability, includeReachability)
			lines = append(lines, Wrap(fmt.Sprintf("  - [%s] %s  %s%s", strings.ToUpper(ValueOrDash(change.Vulnerability.Severity)), change.Vulnerability.ID, DiffPackageDisplayName(change.Package), details), Green))
		}
	}
	return append(lines, "")
}

func policyTextSections(audit output.DiffAudit, includeReachability bool) []string {
	lines := []string{
		"Policy Evaluation",
		fmt.Sprintf("  Current findings: %s.", diffAuditFindingsSummary(audit.AuditSummary)),
		fmt.Sprintf("  Change summary: %d introduced, %d persisted, and %d resolved findings.", len(audit.Introduced), len(audit.Persisted), len(audit.Resolved)),
	}
	appendSection := func(title string, findings []output.AuditFinding, color string) {
		if len(findings) == 0 {
			return
		}
		lines = append(lines, title)
		for _, finding := range sortDiffAuditFindings(findings) {
			disposition := strings.ToUpper(ValueOrDash(finding.Disposition))
			line := fmt.Sprintf("  - [%s/%s] %s", strings.ToUpper(ValueOrDash(finding.Severity)), disposition, ValueOrDash(finding.ID))
			if pkgLabel := DiffPackageDisplayName(finding.Package); pkgLabel != "" {
				line += " " + pkgLabel
			}
			if strings.TrimSpace(finding.Title) != "" && finding.Title != finding.ID {
				line += ": " + finding.Title
			}
			var details []string
			if fixed := fixedVersionSummary(finding.FixedIn, finding.FixedVersions); fixed != "" {
				details = append(details, "fixed in "+fixed)
			}
			if exploitability := exploitabilitySummary(finding.KEVExploited, finding.KnownExploited, finding.RiskScore); exploitability != "" {
				details = append(details, exploitability)
			}
			if includeReachability {
				details = append(details, "reachability "+formatReachabilityCell(finding.Reachability))
			}
			if len(details) > 0 {
				line += " [" + strings.Join(details, "; ") + "]"
			}
			if color != "" {
				line = Wrap(line, color)
			}
			lines = append(lines, line)
		}
		lines = append(lines, "")
	}
	appendSection("Introduced Findings", audit.Introduced, Red)
	appendSection("Resolved Findings", audit.Resolved, Green)
	if len(audit.Introduced) == 0 && len(audit.Persisted) == 0 && len(audit.Resolved) == 0 {
		lines = append(lines, "  No policy differences were identified between the base and head dependency sets.")
	}
	return lines
}

func diffVulnerabilityDetails(vulnerability output.VulnerabilityRef, includeReachability bool) string {
	if !includeReachability {
		return ""
	}
	return " [" + "reachability " + formatReachabilityCell(vulnerability.Reachability) + "]"
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
		si := severityRankTable(sorted[i].Severity)
		sj := severityRankTable(sorted[j].Severity)
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
		label = manifest.Kind
	}
	if strings.TrimSpace(manifest.PackageManager) != "" {
		return fmt.Sprintf("%s (%s)", label, manifest.PackageManager)
	}
	return label
}
