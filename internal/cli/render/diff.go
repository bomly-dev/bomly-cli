package render

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/output"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// DiffManifestStatusOrder returns the sort rank for a diff manifest status
// (removed, added, changed, unchanged). Lower wins; unknown sorts last.
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
	if _, err := fmt.Fprintf(w, "Dependency diff %s -> %s\n", payload.Comparison.Base, payload.Comparison.Head); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(
		w,
		"Manifest changes: %d added, %d changed, %d unchanged, and %d removed\n",
		payload.Summary.AddedManifestCount,
		payload.Summary.ChangedManifestCount,
		payload.Summary.UnchangedManifestCount,
		payload.Summary.RemovedManifestCount,
	); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(
		w,
		"Package changes: %d added, %d updated, and %d removed\n",
		payload.Summary.AddedPackageCount,
		payload.Summary.ChangedPackageCount,
		payload.Summary.RemovedPackageCount,
	); err != nil {
		return err
	}
	if payload.Audit != nil {
		for _, line := range diffAuditTextSections(*payload.Audit) {
			if _, err := fmt.Fprintln(w, line); err != nil {
				return err
			}
		}
	}
	for _, line := range diffTextSections(payload.Results.Manifests) {
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return nil
}

func diffAuditTextSections(audit output.DiffAudit) []string {
	lines := []string{
		"",
		"Policy Outcome",
		fmt.Sprintf("  Current findings: %s.", diffAuditFindingsSummary(audit.AuditSummary)),
		fmt.Sprintf(
			"  Change summary: %d introduced, %d persisted, and %d resolved findings.",
			len(audit.Introduced),
			len(audit.Persisted),
			len(audit.Resolved),
		),
	}

	if len(audit.Introduced) == 0 && len(audit.Persisted) == 0 && len(audit.Resolved) == 0 {
		return append(lines, "  No policy differences were identified between the base and head dependency sets.")
	}

	appendSection := func(title string, findings []output.AuditFinding, color string) {
		if len(findings) == 0 {
			return
		}
		lines = append(lines, "")
		lines = append(lines, title)
		for _, finding := range sortDiffAuditFindings(findings) {
			line := fmt.Sprintf("  - [%s] %s", strings.ToUpper(ValueOrDash(finding.Severity)), ValueOrDash(finding.ID))
			pkgLabel := DiffPackageDisplayName(finding.Package)
			if pkgLabel != "" {
				line += " " + pkgLabel
			}
			if strings.TrimSpace(finding.Source) != "" {
				line += fmt.Sprintf(" (%s)", finding.Source)
			}
			if strings.TrimSpace(finding.Title) != "" && finding.Title != finding.ID {
				line += fmt.Sprintf(": %s", finding.Title)
			}
			if color != "" {
				line = Wrap(line, color)
			}
			lines = append(lines, line)
		}
	}

	appendSection("Introduced Findings", audit.Introduced, Red)
	appendSection("Persisted Findings", audit.Persisted, "")
	appendSection("Resolved Findings", audit.Resolved, Green)

	return lines
}

func diffAuditFindingsSummary(summary *output.AuditSummary) string {
	if summary == nil || summary.Total == 0 {
		return "no active findings were reported"
	}
	return formatAuditSummary(summary, true)
}

func sortDiffAuditFindings(findings []output.AuditFinding) []output.AuditFinding {
	sorted := make([]output.AuditFinding, len(findings))
	copy(sorted, findings)
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

func diffTextSections(manifests []output.DiffManifestResult) []string {
	lines := make([]string, 0, len(manifests)*8)
	titleCaser := cases.Title(language.English)
	appendSection := func(title string, values []string, indent string) {
		if len(values) == 0 {
			return
		}
		lines = append(lines, indent+title)
		for _, value := range values {
			lines = append(lines, indent+"- "+value)
		}
	}

	for _, manifest := range manifests {
		lines = append(lines, "")
		statusLine := fmt.Sprintf("%s manifest %s", titleCaser.String(manifest.Status), DiffManifestDisplayLabel(manifest))
		switch manifest.Status {
		case "added":
			statusLine = Wrap(statusLine, Green)
		case "removed":
			statusLine = Wrap(statusLine, Red)
		}
		lines = append(lines, statusLine)

		added := make([]string, 0, len(manifest.Added))
		for _, change := range manifest.Added {
			added = append(added, Wrap(DiffPackageDisplayName(change.Package), Green))
		}
		changed := make([]string, 0, len(manifest.Changed))
		for _, change := range manifest.Changed {
			changed = append(changed, fmt.Sprintf("%s (%s -> %s)", DiffPackageDisplayName(change.After), change.Before.Version, change.After.Version))
		}
		removed := make([]string, 0, len(manifest.Removed))
		for _, change := range manifest.Removed {
			removed = append(removed, Wrap(DiffPackageDisplayName(change.Package), Red))
		}

		appendSection("Added", added, "  ")
		appendSection("Changed", changed, "  ")
		appendSection("Removed", removed, "  ")
	}
	return lines
}

// DiffPackageDisplayName returns a human-readable label for a package
// referenced by the diff API: "name@version", "name", "id", or "".
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

// DiffManifestDisplayLabel returns a human-readable label for a manifest in
// diff output, optionally suffixed with the package manager name.
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
