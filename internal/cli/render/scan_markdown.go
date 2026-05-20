package render

import (
	"fmt"
	"io"
	"sort"

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
	return []string{
		fmt.Sprintf("- Manifests: %d", len(payload.Manifests)),
		fmt.Sprintf("- Packages: %d", scanPackageCount(payload.Manifests)),
		fmt.Sprintf("- Policy findings: %s", scanAuditSummaryMarkdown(payload.AuditSummary)),
	}
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
			ValueOrDash(manifest.PackageManager),
			fmt.Sprintf("%d", len(manifest.Packages)),
		})
	}
	return markdownTable([]string{"Subproject", "Manifest", "Manager", "Packages"}, rows)
}

func scanInventoryMarkdown(payload output.ScanResponse) []string {
	packages := scanPackages(payload.Manifests)
	if len(packages) == 0 {
		return []string{"No packages detected."}
	}
	rows := make([][]string, 0, len(packages))
	for _, pkg := range packages {
		rows = append(rows, []string{
			ValueOrDash(markdownPackageDisplayName(pkg.PackageRef)),
			ValueOrDash(pkg.Version),
			ValueOrDash(pkg.Scope),
			ValueOrDash(licenseList(pkg.Licenses)),
		})
	}
	return markdownTable([]string{"Package", "Version", "Scope", "Licenses"}, rows)
}

func scanFindingsMarkdown(payload output.ScanResponse) []string {
	if len(payload.Findings) == 0 {
		return []string{"No policy findings."}
	}
	lines := make([]string, 0, len(payload.Findings))
	for _, finding := range sortDiffAuditFindings(payload.Findings) {
		pkg := markdownPackageDisplayName(finding.Package)
		if pkg == "" {
			pkg = "-"
		}
		title := finding.Title
		if title == "" {
			title = finding.ID
		}
		lines = append(lines, fmt.Sprintf(
			"- [%s] `%s`: %s",
			markdownInline(ValueOrDash(finding.Severity)),
			markdownInline(pkg),
			markdownText(title),
		))
	}
	return lines
}

func scanPackageCount(manifests []output.ScanManifest) int {
	total := 0
	for _, manifest := range manifests {
		total += len(manifest.Packages)
	}
	return total
}

func scanPackages(manifests []output.ScanManifest) []output.ScanPackage {
	packages := make([]output.ScanPackage, 0, scanPackageCount(manifests))
	for _, manifest := range manifests {
		packages = append(packages, manifest.Packages...)
	}
	sort.Slice(packages, func(i, j int) bool {
		if packages[i].Name != packages[j].Name {
			return packages[i].Name < packages[j].Name
		}
		if packages[i].Version != packages[j].Version {
			return packages[i].Version < packages[j].Version
		}
		return packages[i].ID < packages[j].ID
	})
	return packages
}

func scanAuditSummaryMarkdown(summary *output.AuditSummary) string {
	if summary == nil || summary.Total == 0 {
		return "none"
	}
	return formatAuditSummary(summary, true)
}
