package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/output"
)

// Explain writes the compact human-readable explain report for one target dependency.
func Explain(w io.Writer, target output.ExplainTargetResponse, includeReachabilityValue ...bool) error {
	includeReachability := len(includeReachabilityValue) > 0 && includeReachabilityValue[0]
	_ = includeReachability

	// Key-value header block
	ecosystem := ecosystemFromPURL(target.Dependency.Purl)
	pkgLabel := explainPackageDisplayName(target.Dependency)
	scope := ValueOrDash(target.Dependency.Scope)
	directLabel := "no"
	for _, path := range target.Paths {
		if len(path.Packages) == 2 {
			directLabel = "yes"
			break
		}
	}

	// Bold keys: pad the key text to a fixed visible width BEFORE styling so
	// ANSI bytes don't affect the value column alignment.
	const kvKeyWidth = 10
	boldKey := func(k string) string {
		return Style(fmt.Sprintf("%-*s", kvKeyWidth, k), Bold)
	}
	if _, err := fmt.Fprintf(w, "%s %s\n", boldKey("ecosystem"), ecosystem); err != nil {
		return fmt.Errorf("write explain ecosystem: %w", err)
	}
	if pm := strings.TrimSpace(target.PackageManager.Name()); pm != "" {
		if _, err := fmt.Fprintf(w, "%s %s\n", boldKey("manager"), pm); err != nil {
			return fmt.Errorf("write explain manager: %w", err)
		}
	}
	if _, err := fmt.Fprintf(w, "%s %s\n", boldKey("package"), pkgLabel); err != nil {
		return fmt.Errorf("write explain package: %w", err)
	}
	if _, err := fmt.Fprintf(w, "%s %s\n", boldKey("scope"), scope); err != nil {
		return fmt.Errorf("write explain scope: %w", err)
	}
	if _, err := fmt.Fprintf(w, "%s %s\n", boldKey("direct"), directLabel); err != nil {
		return fmt.Errorf("write explain direct: %w", err)
	}

	// Licenses section — shown before the tree so the reader has context before
	// following the dependency chain.
	if len(target.Dependency.Licenses) > 0 {
		if _, err := fmt.Fprintln(w, Style("licenses", Bold)); err != nil {
			return fmt.Errorf("write explain licenses header: %w", err)
		}
		for _, license := range target.Dependency.Licenses {
			label := license.Identifier()
			if label == "" {
				continue
			}
			if license.Type != "" {
				label += " [" + string(license.Type) + "]"
			}
			if _, err := fmt.Fprintln(w, "  "+label); err != nil {
				return fmt.Errorf("write explain license entry: %w", err)
			}
		}
	}

	// Dependency tree
	if len(target.Paths) > 0 {
		if _, err := fmt.Fprintln(w, Style("introduced by:", Bold)); err != nil {
			return fmt.Errorf("write explain introduced-by header: %w", err)
		}
		for _, line := range whyTreeLinesForTarget(target.Paths, target.Dependency.ID) {
			if _, err := fmt.Fprintln(w, "  "+line); err != nil {
				return fmt.Errorf("write explain tree line: %w", err)
			}
		}
	}

	// Vulnerabilities section — shown after the tree so the reader sees the dep
	// chain before the security findings.
	if len(target.Dependency.Vulnerabilities) > 0 {
		if _, err := fmt.Fprintln(w, Style("vulnerabilities", Bold)); err != nil {
			return fmt.Errorf("write explain vulnerabilities header: %w", err)
		}
		maxIDWidth := 0
		for _, vuln := range target.Dependency.Vulnerabilities {
			if l := len(vuln.ID); l > maxIDWidth {
				maxIDWidth = l
			}
		}
		for _, vuln := range target.Dependency.Vulnerabilities {
			title := strings.TrimSpace(vuln.Title)
			if len(title) > 50 {
				title = title[:47] + "..."
			}
			line := fmt.Sprintf("  %-*s  %s  %s", maxIDWidth, vuln.ID, severityLabelFixed(string(vuln.Severity)), title)
			if _, err := fmt.Fprintln(w, strings.TrimRight(line, " ")); err != nil {
				return fmt.Errorf("write explain vulnerability entry: %w", err)
			}
		}
	}

	return nil
}

// ecosystemFromPURL extracts the package type (e.g. "npm", "go") from a PURL
// of the form "pkg:TYPE/...". Returns "-" when the PURL is absent or malformed.
func ecosystemFromPURL(purl string) string {
	const prefix = "pkg:"
	if !strings.HasPrefix(purl, prefix) {
		return "-"
	}
	rest := strings.TrimPrefix(purl, prefix)
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		return "-"
	}
	return parts[0]
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

// severityLabelFixed is like explainSeverityLabel but pads the visible text to
// a fixed width (that of "[CRITICAL]") before applying ANSI styling. This keeps
// tabular findings rows aligned even when ANSI escape sequences vary in length
// across severity levels — the invisible bytes are added after the padding, so
// all cells occupy the same number of visible terminal columns.
func severityLabelFixed(severity string) string {
	const width = 10 // len("[CRITICAL]")
	label := fmt.Sprintf("%-*s", width, "["+strings.ToUpper(ValueOrDash(severity))+"]")
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return Style(label, Red, Bold)
	case "high":
		return Style(label, Red)
	case "medium":
		return Style(label, Yellow, Bold)
	case "low":
		return Style(label, Cyan)
	default:
		return Style(label, Dim)
	}
}
