package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/output"
)

func renderExplainTextReport(w io.Writer, target output.ExplainTargetResponse) error {
	divider := ansiStyled(strings.Repeat("=", 72), ansiDim)
	section := ansiStyled(strings.Repeat("-", 72), ansiDim)

	if _, err := fmt.Fprintln(w, divider); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, ansiStyled("Dependency Explanation", ansiBold, ansiCyan)); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, section); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "%s %s\n", ansiStyled("Component:", ansiDim), explainPackageDisplayName(target.Dependency)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "%s %s\n", ansiStyled("Project:  ", ansiDim), valueOrDash(target.Project.Name)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "%s %s\n", ansiStyled("Detector: ", ansiDim), valueOrDash(target.Detector)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "%s %d\n", ansiStyled("Path count:", ansiDim), len(target.Paths)); err != nil {
		return err
	}

	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, ansiStyled("Dependency Paths", ansiBold)); err != nil {
		return err
	}
	for _, line := range whyTreeLinesForTarget(target.Paths, target.Dependency.ID) {
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}

	if len(target.Findings) > 0 || len(target.Dependency.Licenses) > 0 || len(target.Dependency.Vulnerabilities) > 0 {
		if _, err := fmt.Fprintln(w); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w, ansiStyled("Impact Assessment", ansiBold)); err != nil {
			return err
		}
	}

	if len(target.Dependency.Vulnerabilities) > 0 {
		if _, err := fmt.Fprintf(w, "%s %d matched\n", ansiStyled("Vulnerability enrichment:", ansiDim), len(target.Dependency.Vulnerabilities)); err != nil {
			return err
		}
		for _, vulnerability := range target.Dependency.Vulnerabilities {
			if _, err := fmt.Fprintf(w, "- %s %s (%s)\n", explainSeverityLabel(vulnerability.Severity), vulnerability.ID, valueOrDash(vulnerability.Source)); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "  %s %s\n", ansiStyled("Title:   ", ansiDim), valueOrDash(vulnerability.Title)); err != nil {
				return err
			}
		}
	}

	if len(target.Findings) > 0 {
		if len(target.Dependency.Vulnerabilities) > 0 {
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "%s %s\n", ansiStyled("Policy findings:", ansiDim), formatExplainAuditSummary(target.AuditSummary)); err != nil {
			return err
		}
		for _, finding := range target.Findings {
			if _, err := fmt.Fprintf(w, "- %s %s\n", explainSeverityLabel(finding.Severity), finding.ID); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "  %s %s\n", ansiStyled("Title:   ", ansiDim), valueOrDash(finding.Title)); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "  %s %s\n", ansiStyled("Source:  ", ansiDim), valueOrDash(finding.Source)); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "  %s %s\n", ansiStyled("Package: ", ansiDim), explainPackageDisplayName(finding.Package)); err != nil {
				return err
			}
			if len(finding.Reasons) > 0 {
				if _, err := fmt.Fprintln(w, "  "+ansiStyled("Details: ", ansiDim)+finding.Reasons[0]); err != nil {
					return err
				}
				for _, reason := range finding.Reasons[1:] {
					if _, err := fmt.Fprintln(w, "           "+reason); err != nil {
						return err
					}
				}
			}
		}
	}

	if len(target.Dependency.Licenses) > 0 {
		if len(target.Findings) > 0 {
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "%s %d detected\n", ansiStyled("Licenses:", ansiDim), len(target.Dependency.Licenses)); err != nil {
			return err
		}
		for idx, license := range target.Dependency.Licenses {
			label := license.Identifier()
			if license.Type != "" {
				label += " [" + license.Type + "]"
			}
			if _, err := fmt.Fprintf(w, "- License %d: %s\n", idx+1, valueOrDash(label)); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "  %s applicable to %s\n", ansiStyled("Scope:   ", ansiDim), explainPackageDisplayName(target.Dependency)); err != nil {
				return err
			}
		}
	}

	if _, err := fmt.Fprintln(w, divider); err != nil {
		return err
	}
	return nil
}

func formatExplainAuditSummary(summary *output.AuditSummary) string {
	if summary == nil || summary.Total == 0 {
		return "no active findings"
	}
	parts := make([]string, 0, 4)
	if summary.Critical > 0 {
		parts = append(parts, fmt.Sprintf("%d critical", summary.Critical))
	}
	if summary.High > 0 {
		parts = append(parts, fmt.Sprintf("%d high", summary.High))
	}
	if summary.Medium > 0 {
		parts = append(parts, fmt.Sprintf("%d medium", summary.Medium))
	}
	if summary.Low > 0 {
		parts = append(parts, fmt.Sprintf("%d low", summary.Low))
	}
	if len(parts) == 0 && summary.Unknown > 0 {
		parts = append(parts, fmt.Sprintf("%d unknown", summary.Unknown))
	}
	return fmt.Sprintf("%d total (%s)", summary.Total, strings.Join(parts, ", "))
}

func explainSeverityLabel(severity string) string {
	label := strings.ToUpper(valueOrDash(severity))
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return ansiStyled("["+label+"]", ansiRed, ansiBold)
	case "high":
		return ansiStyled("["+label+"]", ansiRed)
	case "medium":
		return ansiStyled("["+label+"]", ansiYellow, ansiBold)
	case "low":
		return ansiStyled("["+label+"]", ansiCyan)
	default:
		return ansiStyled("["+label+"]", ansiDim)
	}
}
