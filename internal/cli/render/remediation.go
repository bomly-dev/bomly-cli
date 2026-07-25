package render

import (
	"fmt"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/sdk"
)

type remediationReport struct {
	vulnerablePackages int
	fixablePackages    int
	fixSuggestions     int
	rows               []remediationRow
}

type remediationRow struct {
	packageLabel       string
	status             sdk.PackageRemediationStatus
	recommendedVersion string
	action             sdk.RemediationAction
	actionTarget       string
	manifestPath       string
	advice             string
}

func buildRemediationReport(packages []output.ScanPackageEntry) remediationReport {
	sorted := append([]output.ScanPackageEntry(nil), packages...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Purl < sorted[j].Purl
	})

	var report remediationReport
	for _, pkg := range sorted {
		if len(pkg.Vulnerabilities) == 0 {
			continue
		}
		report.vulnerablePackages++
		if pkg.Remediation == nil || len(pkg.Remediation.Suggestions) == 0 {
			continue
		}
		label := remediationPackageLabel(pkg)
		hasFixSuggestion := false
		for _, suggestion := range pkg.Remediation.Suggestions {
			report.rows = append(report.rows, remediationRow{
				packageLabel:       label,
				status:             pkg.Remediation.Status,
				recommendedVersion: pkg.Remediation.RecommendedVersion,
				action:             suggestion.Action,
				actionTarget:       suggestion.SuggestedActionDependencyRef,
				manifestPath:       suggestion.ManifestPath,
				advice:             suggestion.OverrideAdvice,
			})
			if pkg.Remediation.Status == sdk.PackageRemediationComplete &&
				isConcreteFixAction(suggestion.Action) {
				report.fixSuggestions++
				hasFixSuggestion = true
			}
		}
		if hasFixSuggestion {
			report.fixablePackages++
		}
	}
	return report
}

func isConcreteFixAction(action sdk.RemediationAction) bool {
	switch action {
	case sdk.RemediationActionDirectBump,
		sdk.RemediationActionTransitiveOverride,
		sdk.RemediationActionLockfileRefresh:
		return true
	default:
		return false
	}
}

func remediationPackageLabel(pkg output.ScanPackageEntry) string {
	switch {
	case pkg.Name != "" && pkg.Version != "":
		return pkg.Name + "@" + pkg.Version
	case pkg.Name != "":
		return pkg.Name
	case pkg.Purl != "":
		return pkg.Purl
	default:
		return "-"
	}
}

func remediationSummary(report remediationReport) string {
	if report.fixSuggestions == 0 {
		return fmt.Sprintf(
			"No fix suggestions available for %d vulnerable %s.",
			report.vulnerablePackages,
			pluralWord(report.vulnerablePackages, "package", "packages"),
		)
	}
	return fmt.Sprintf(
		"%d %s for %d of %d vulnerable %s.",
		report.fixSuggestions,
		pluralWord(report.fixSuggestions, "fix suggestion", "fix suggestions"),
		report.fixablePackages,
		report.vulnerablePackages,
		pluralWord(report.vulnerablePackages, "package", "packages"),
	)
}

func pluralWord(count int, singular, plural string) string {
	if count == 1 {
		return singular
	}
	return plural
}

func remediationText(packages []output.ScanPackageEntry) string {
	report := buildRemediationReport(packages)
	if len(report.rows) == 0 {
		return ""
	}
	icon := Style("✓", Green)
	summaryStyle := Green
	if report.fixSuggestions == 0 {
		icon = Style("ℹ", Cyan)
		summaryStyle = Cyan
	}
	return icon + " " + Style(remediationSummary(report), summaryStyle) + "\n" +
		Style("  Run again with --format json to see remediation details.", Dim)
}

func remediationMarkdown(packages []output.ScanPackageEntry) []string {
	report := buildRemediationReport(packages)
	if len(report.rows) == 0 {
		return nil
	}
	icon := "✅"
	if report.fixSuggestions == 0 {
		icon = "ℹ️"
	}
	lines := []string{icon + " " + remediationSummary(report), ""}
	rows := make([][]string, 0, len(report.rows))
	for _, row := range report.rows {
		rows = append(rows, []string{
			row.packageLabel,
			RemediationStatusLabel(row.status),
			ValueOrDash(row.recommendedVersion),
			remediationActionText(row.action),
			ValueOrDash(row.actionTarget),
			ValueOrDash(row.manifestPath),
			ValueOrDash(row.advice),
		})
	}
	return append(lines, markdownTable(
		[]string{"Vulnerable package", "Status", "Recommended version", "Action", "Suggested action for", "Manifest", "Manager advice"},
		rows,
	)...)
}

// RemediationStatusLabel describes package fix coverage in plain language.
func RemediationStatusLabel(status sdk.PackageRemediationStatus) string {
	switch status {
	case sdk.PackageRemediationComplete:
		return "Complete fix available"
	case sdk.PackageRemediationPartial:
		return "Partial fix available"
	case sdk.PackageRemediationUnavailable:
		return "No fix available"
	case sdk.PackageRemediationUnknown:
		return "Fix availability unknown"
	default:
		return "Fix availability unknown"
	}
}

func remediationActionText(action sdk.RemediationAction) string {
	value := strings.ReplaceAll(strings.TrimSpace(string(action)), "-", " ")
	if value == "" {
		return "-"
	}
	return strings.ToUpper(value[:1]) + value[1:]
}

func explainRemediationPackages(target output.ExplainTargetResponse) []output.ScanPackageEntry {
	return []output.ScanPackageEntry{{
		Purl:            target.Dependency.Purl,
		Name:            target.Dependency.Name,
		Version:         target.Dependency.Version,
		Vulnerabilities: target.Dependency.Vulnerabilities,
		Remediation:     target.Dependency.Remediation,
	}}
}

func diffRemediationPackages(payload output.DiffResponse) []output.ScanPackageEntry {
	relevant := make(map[string]struct{})
	for _, change := range payload.Results.Vulnerabilities.Added {
		relevant[change.Package.Purl] = struct{}{}
	}
	for _, change := range payload.Results.Vulnerabilities.Persisted {
		relevant[change.Package.Purl] = struct{}{}
	}
	packages := make([]output.ScanPackageEntry, 0, len(relevant))
	for _, pkg := range payload.Packages {
		if _, ok := relevant[pkg.Purl]; ok {
			packages = append(packages, pkg)
		}
	}
	return packages
}
