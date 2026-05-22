package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/output"
)

// Explain writes the human-readable explain report for one target dependency.
func Explain(w io.Writer, target output.ExplainTargetResponse, includeReachabilityValue ...bool) error {
	includeReachability := len(includeReachabilityValue) > 0 && includeReachabilityValue[0]
	divider := Style(strings.Repeat("=", 72), Dim)
	section := Style(strings.Repeat("-", 72), Dim)

	if _, err := fmt.Fprintln(w, divider); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, Style("Dependency Explanation", Bold, Cyan)); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, section); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "%s %s\n", Style("Component:", Dim), explainPackageDisplayName(target.Dependency)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "%s %s\n", Style("Project:  ", Dim), ValueOrDash(target.Project.Name)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "%s %s\n", Style("Detector: ", Dim), ValueOrDash(target.Detector)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "%s %d\n", Style("Path count:", Dim), len(target.Paths)); err != nil {
		return err
	}

	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, Style("Dependency Paths", Bold)); err != nil {
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
		if _, err := fmt.Fprintln(w, Style("Impact Assessment", Bold)); err != nil {
			return err
		}
	}

	if len(target.Dependency.Vulnerabilities) > 0 {
		if _, err := fmt.Fprintf(w, "%s %d matched\n", Style("Vulnerability enrichment:", Dim), len(target.Dependency.Vulnerabilities)); err != nil {
			return err
		}
		for _, vulnerability := range target.Dependency.Vulnerabilities {
			if _, err := fmt.Fprintf(w, "- %s %s (%s)\n", explainSeverityLabel(vulnerability.Severity), vulnerability.ID, ValueOrDash(vulnerability.Source)); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "  %s %s\n", Style("Title:   ", Dim), ValueOrDash(vulnerability.Title)); err != nil {
				return err
			}
			if fixed := fixedVersionSummary(vulnerability.FixedIn, vulnerability.FixedVersions); fixed != "" {
				if _, err := fmt.Fprintf(w, "  %s %s\n", Style("Fixed in:", Dim), fixed); err != nil {
					return err
				}
			}
			if exploitability := exploitabilitySummary(vulnerability.KEVExploited, vulnerability.KnownExploited, vulnerability.RiskScore); exploitability != "" {
				if _, err := fmt.Fprintf(w, "  %s %s\n", Style("Exploit: ", Dim), exploitability); err != nil {
					return err
				}
			}
			if epss := epssSummary(vulnerability.EPSS); epss != "" {
				if _, err := fmt.Fprintf(w, "  %s %s\n", Style("EPSS:    ", Dim), epss); err != nil {
					return err
				}
			}
			if includeReachability {
				if _, err := fmt.Fprintf(w, "  %s %s\n", Style("Reach:   ", Dim), formatReachabilityCell(vulnerability.Reachability)); err != nil {
					return err
				}
			}
		}
	}

	if len(target.Findings) > 0 {
		if len(target.Dependency.Vulnerabilities) > 0 {
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "%s %s\n", Style("Policy findings:", Dim), formatExplainAuditSummary(target.AuditSummary)); err != nil {
			return err
		}
		for _, finding := range target.Findings {
			if _, err := fmt.Fprintf(w, "- %s %s\n", explainSeverityLabel(finding.Severity), finding.ID); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "  %s %s\n", Style("Title:   ", Dim), ValueOrDash(finding.Title)); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "  %s %s\n", Style("Source:  ", Dim), ValueOrDash(finding.Source)); err != nil {
				return err
			}
			if fixed := fixedVersionSummary(finding.FixedIn, finding.FixedVersions); fixed != "" {
				if _, err := fmt.Fprintf(w, "  %s %s\n", Style("Fixed in:", Dim), fixed); err != nil {
					return err
				}
			}
			if exploitability := exploitabilitySummary(finding.KEVExploited, finding.KnownExploited, finding.RiskScore); exploitability != "" {
				if _, err := fmt.Fprintf(w, "  %s %s\n", Style("Exploit: ", Dim), exploitability); err != nil {
					return err
				}
			}
			if includeReachability {
				if _, err := fmt.Fprintf(w, "  %s %s\n", Style("Reach:   ", Dim), formatReachabilityCell(finding.Reachability)); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprintf(w, "  %s %s\n", Style("Package: ", Dim), explainPackageDisplayName(finding.Package)); err != nil {
				return err
			}
			if len(finding.Reasons) > 0 {
				if _, err := fmt.Fprintln(w, "  "+Style("Details: ", Dim)+finding.Reasons[0]); err != nil {
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
		if _, err := fmt.Fprintf(w, "%s %d detected\n", Style("Licenses:", Dim), len(target.Dependency.Licenses)); err != nil {
			return err
		}
		for idx, license := range target.Dependency.Licenses {
			label := license.Identifier()
			if license.Type != "" {
				label += " [" + license.Type + "]"
			}
			if _, err := fmt.Fprintf(w, "- License %d: %s\n", idx+1, ValueOrDash(label)); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "  %s applicable to %s\n", Style("Scope:   ", Dim), explainPackageDisplayName(target.Dependency)); err != nil {
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
	label := strings.ToUpper(ValueOrDash(severity))
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return Style("["+label+"]", Red, Bold)
	case "high":
		return Style("["+label+"]", Red)
	case "medium":
		return Style("["+label+"]", Yellow, Bold)
	case "low":
		return Style("["+label+"]", Cyan)
	default:
		return Style("["+label+"]", Dim)
	}
}
