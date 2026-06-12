package render

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/output"
)

// ScanMarkdown writes a GitHub-flavored Markdown scan report.
func ScanMarkdown(w io.Writer, payload output.ScanResponse) error {
	return writeMarkdownReport(w, MarkdownReport[output.ScanResponse]{
		Title: "Bomly Scan Summary",
		Intro: func(payload output.ScanResponse) []string {
			project := payload.Project.Name
			if project == "" {
				project = payload.Project.Path
			}
			if project == "" {
				return nil
			}
			return []string{fmt.Sprintf("Project: `%s`", markdownInline(project))}
		},
		Sections: []MarkdownSection[output.ScanResponse]{
			{Title: "Executive Summary", Lines: scanSummaryMarkdown},
			{Title: "Manifests", Lines: scanManifestMarkdown},
			{Title: "Dependency Inventory", Lines: scanInventoryMarkdown},
			{Title: "Policy Findings", Lines: scanFindingsMarkdown},
		},
	}, payload)
}

func scanSummaryMarkdown(payload output.ScanResponse) []string {
	lines := []string{
		fmt.Sprintf("- Manifests: %d", len(payload.Manifests)),
		fmt.Sprintf("- Packages: %d", scanPackageCount(payload.Manifests)),
		fmt.Sprintf("- Policy findings: %s", scanAuditSummaryMarkdown(payload.AuditSummary)),
	}
	if payload.Metadata.ReachabilityEnabled {
		lines = append(lines, fmt.Sprintf("- Reachability: %s", scanReachabilitySummaryMarkdown(payload.Packages)))
	}
	return lines
}

func scanManifestMarkdown(payload output.ScanResponse) []string {
	if len(payload.Manifests) == 0 {
		return []string{"No manifests detected."}
	}
	rows := make([][]string, 0, len(payload.Manifests))
	for _, manifest := range payload.Manifests {
		subproject := manifest.Subproject
		if subproject == "" {
			subproject = "."
		}
		rows = append(rows, []string{
			subproject,
			ValueOrDash(manifest.Path),
			ValueOrDash(manifest.PackageManager.Name()),
			fmt.Sprintf("%d", len(manifest.Dependencies)),
		})
	}
	return markdownTable([]string{"Subproject", "Manifest", "Manager", "Packages"}, rows)
}

func scanInventoryMarkdown(payload output.ScanResponse) []string {
	dependencies := scanDependencies(payload.Manifests)
	if len(dependencies) == 0 {
		return []string{"No packages detected."}
	}
	rows := make([][]string, 0, len(dependencies))
	for _, dep := range dependencies {
		rows = append(rows, []string{
			ValueOrDash(scanDependencyDisplayName(dep)),
			ValueOrDash(dep.Version),
			ValueOrDash(dep.PrimaryScope()),
			ValueOrDash(licenseList(dep.Licenses)),
		})
	}
	return markdownTable([]string{"Package", "Version", "Scope", "Licenses"}, rows)
}

func scanDependencyDisplayName(dep output.ScanDependency) string {
	switch {
	case dep.Name != "" && dep.Version != "":
		return dep.Name + "@" + dep.Version
	case dep.Name != "":
		return dep.Name
	default:
		return dep.ID
	}
}

func scanFindingsMarkdown(payload output.ScanResponse) []string {
	if len(payload.Findings) == 0 {
		return []string{"No policy findings."}
	}
	rows := make([][]string, 0, len(payload.Findings))
	for _, finding := range sortDiffAuditFindings(payload.Findings) {
		pkg := markdownPackageDisplayName(finding.Package)
		if pkg == "" {
			pkg = "-"
		}
		title := finding.Title
		if title == "" {
			title = finding.ID
		}
		row := []string{
			strings.ToUpper(ValueOrDash(string(finding.Severity))),
			valueOrDash(finding.ID),
			pkg,
		}
		if payload.Metadata.ReachabilityEnabled {
			row = append(row, valueOrDash(formatReachabilityCell(finding.Reachability)))
		}
		row = append(row,
			valueOrDash(fixedVersionSummary(finding.FixedIn, finding.FixedVersions)),
			valueOrDash(exploitabilitySummary(finding.KEVExploited, finding.KnownExploited, finding.RiskScore)),
			valueOrDash(finding.Source),
			title,
		)
		rows = append(rows, row)
	}
	header := []string{"Severity", "ID", "Package"}
	if payload.Metadata.ReachabilityEnabled {
		header = append(header, "Reachability")
	}
	header = append(header, "Fixed In", "Exploitability", "Source", "Title")
	return markdownTable(header, rows)
}

func scanPackageCount(manifests []output.ScanManifest) int {
	total := 0
	for _, manifest := range manifests {
		total += len(manifest.Dependencies)
	}
	return total
}

func scanDependencies(manifests []output.ScanManifest) []output.ScanDependency {
	dependencies := make([]output.ScanDependency, 0, scanPackageCount(manifests))
	for _, manifest := range manifests {
		dependencies = append(dependencies, manifest.Dependencies...)
	}
	sort.Slice(dependencies, func(i, j int) bool {
		if dependencies[i].Name != dependencies[j].Name {
			return dependencies[i].Name < dependencies[j].Name
		}
		if dependencies[i].Version != dependencies[j].Version {
			return dependencies[i].Version < dependencies[j].Version
		}
		return dependencies[i].ID < dependencies[j].ID
	})
	return dependencies
}

func scanAuditSummaryMarkdown(summary *output.AuditSummary) string {
	if summary == nil || summary.Total == 0 {
		return "none"
	}
	return formatAuditSummary(summary, true)
}

func scanReachabilitySummaryMarkdown(packages []output.ScanPackageEntry) string {
	var reachable, unreachable, unknown, notApplicable, total int
	for _, pkg := range packages {
		for _, vuln := range pkg.Vulnerabilities {
			if vuln.Reachability == nil {
				continue
			}
			total++
			switch vuln.Reachability.Status {
			case "reachable":
				reachable++
			case "unreachable":
				unreachable++
			case "not_applicable":
				notApplicable++
			default:
				unknown++
			}
		}
	}
	if total == 0 {
		return "enabled (no analyzer ran on any vulnerability)"
	}
	parts := make([]string, 0, 4)
	if reachable > 0 {
		parts = append(parts, fmt.Sprintf("%d reachable", reachable))
	}
	if unreachable > 0 {
		parts = append(parts, fmt.Sprintf("%d unreachable", unreachable))
	}
	if unknown > 0 {
		parts = append(parts, fmt.Sprintf("%d unknown", unknown))
	}
	if notApplicable > 0 {
		parts = append(parts, fmt.Sprintf("%d not_applicable", notApplicable))
	}
	return fmt.Sprintf("%d analyzed (%s)", total, strings.Join(parts, ", "))
}
