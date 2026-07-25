package render

import (
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/sdk"
)

const maxTextRemediationSuggestions = 20

type remediationReport struct {
	vulnerablePackages int
	coveredPackages    int
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
		report.coveredPackages++
		label := remediationPackageLabel(pkg)
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
		}
	}
	return report
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
	return fmt.Sprintf(
		"%d %s for %d of %d vulnerable %s.",
		len(report.rows),
		pluralWord(len(report.rows), "remediation suggestion", "remediation suggestions"),
		report.coveredPackages,
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

	var b strings.Builder
	fmt.Fprintln(&b, Style("Remediation", Bold))
	fmt.Fprintln(&b, Style("✓ "+remediationSummary(report), Green))

	var table strings.Builder
	writer := tabwriter.NewWriter(&table, 0, 4, 2, ' ', 0)
	fmt.Fprintln(writer, "  VULNERABLE PACKAGE\tSTATUS\tRECOMMENDED VERSION\tACTION\tSUGGESTED ACTION FOR\tMANIFEST")
	limit := min(len(report.rows), maxTextRemediationSuggestions)
	for _, row := range report.rows[:limit] {
		fmt.Fprintf(
			writer,
			"  %s\t%s\t%s\t%s\t%s\t%s\n",
			row.packageLabel,
			remediationStatusLabel(row.status),
			ValueOrDash(row.recommendedVersion),
			remediationActionText(row.action),
			ValueOrDash(row.actionTarget),
			ValueOrDash(row.manifestPath),
		)
		if row.advice != "" {
			fmt.Fprintf(writer, "    Advice: %s\t\t\t\t\t\n", row.advice)
		}
	}
	_ = writer.Flush()
	b.WriteString(table.String())
	if omitted := len(report.rows) - limit; omitted > 0 {
		fmt.Fprintf(
			&b,
			"  … %d more %s not shown. Run again with --format json to see every suggestion.\n",
			omitted,
			pluralWord(omitted, "suggestion is", "suggestions are"),
		)
	}
	return strings.TrimRight(b.String(), "\n")
}

func remediationMarkdown(packages []output.ScanPackageEntry) []string {
	report := buildRemediationReport(packages)
	if len(report.rows) == 0 {
		return nil
	}
	lines := []string{"✅ " + remediationSummary(report), ""}
	rows := make([][]string, 0, len(report.rows))
	for _, row := range report.rows {
		rows = append(rows, []string{
			row.packageLabel,
			remediationStatusLabel(row.status),
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

func remediationStatusLabel(status sdk.PackageRemediationStatus) string {
	value := strings.TrimSpace(string(status))
	if value == "" {
		return "-"
	}
	return strings.ToUpper(value[:1]) + value[1:]
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
