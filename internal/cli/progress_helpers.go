package cli

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/scan"
	model "github.com/bomly-dev/bomly-cli/sdk"
)

// warningProgressChildren converts pipeline warnings into ⚠ children using
// the warning source as Label and the message as Detail.
func warningProgressChildren(warnings []scan.PipelineWarning) []progressChild {
	children := make([]progressChild, 0, len(warnings))
	for _, w := range warnings {
		label := w.Source
		if label == "" {
			label = "unknown"
		}
		detail := strings.ReplaceAll(w.Message, "\n", " ")
		children = append(children, progressChild{
			Icon:   progressWarningMark,
			Label:  label,
			Detail: detail,
		})
	}
	return children
}

// subprojectProgressChildren returns one child per resolved subproject showing
// the relative path and ecosystem.
func subprojectProgressChildren(results []model.DetectionResult) []progressChild {
	children := make([]progressChild, 0, len(results))
	for _, r := range results {
		label := r.SubprojectInfo.RelativePath
		if label == "" || label == "." {
			label = filepath.Base(r.SubprojectInfo.ExecutionTarget.Location)
			if label == "" || label == "." {
				label = "root"
			}
		}
		detail := string(r.SubprojectInfo.Ecosystem)
		if detail != "" {
			label += " (" + detail + ")"
		}
		children = append(children, progressChild{Label: label})
	}
	return children
}

// detectorProgressChildren groups results by detector name, sums the total
// package count per detector, and returns children with ✔ icon.
func detectorProgressChildren(results []model.DetectionResult) []progressChild {
	type detectorInfo struct {
		name     string
		packages int
	}
	index := make(map[string]*detectorInfo)
	order := make([]string, 0)
	for _, r := range results {
		key := r.DetectorName
		info, exists := index[key]
		if !exists {
			info = &detectorInfo{name: r.DetectorName}
			index[key] = info
			order = append(order, key)
		}
		if r.Graphs != nil {
			for _, entry := range r.Graphs.Entries {
				if entry.Graph != nil {
					info.packages += entry.Graph.Size()
				}
			}
		}
	}
	children := make([]progressChild, 0, len(order))
	for _, key := range order {
		info := index[key]
		children = append(children, progressChild{
			Icon:   progressCheckMark,
			Label:  humanizeDetectorName(info.name),
			Detail: fmt.Sprintf("[%d packages]", info.packages),
		})
	}
	return children
}

// licenseProgressChildren counts packages with license data grouped by source type and
// returns children with ✔ icon and [N licenses] detail.
func licenseProgressChildren(results []model.DetectionResult) []progressChild {
	type sourceInfo struct {
		name     string
		packages map[string]struct{}
	}
	index := make(map[string]*sourceInfo)
	order := make([]string, 0)
	for _, r := range results {
		if r.Graphs == nil {
			continue
		}
		for _, entry := range r.Graphs.Entries {
			if entry.Graph == nil {
				continue
			}
			for _, pkg := range entry.Graph.Packages() {
				if pkg == nil {
					continue
				}
				for _, lic := range pkg.Licenses {
					key := lic.Type
					if key == "" {
						continue
					}
					info, exists := index[key]
					if !exists {
						info = &sourceInfo{name: key, packages: make(map[string]struct{})}
						index[key] = info
						order = append(order, key)
					}
					info.packages[pkg.ID] = struct{}{}
				}
			}
		}
	}
	children := make([]progressChild, 0, len(order))
	for _, key := range order {
		info := index[key]
		children = append(children, progressChild{
			Icon:   progressCheckMark,
			Label:  humanizeLicenseSource(info.name),
			Detail: fmt.Sprintf("[%d licenses]", len(info.packages)),
		})
	}
	return children
}

// auditProgressChildren groups findings by source and returns children with ✔ icon.
func auditProgressChildren(auditorRuns []string, auditorFindings map[string]int, warnings []scan.PipelineWarning) []progressChild {
	children := make([]progressChild, 0, len(auditorRuns)+len(warnings))
	for _, name := range auditorRuns {
		children = append(children, progressChild{
			Icon:   progressCheckMark,
			Label:  humanizeAuditorSource(name),
			Detail: fmt.Sprintf("[%d findings]", auditorFindings[name]),
		})
	}
	children = append(children, warningProgressChildren(warnings)...)
	return children
}

// matchProgressChildren returns ✔ children for each successful matcher run
// and ⚠ children for each warning.
func matchProgressChildren(g *model.Graph, runs []string, warnings []scan.PipelineWarning) []progressChild {
	children := make([]progressChild, 0, len(runs)+len(warnings))
	for _, name := range runs {
		children = append(children, progressChild{
			Icon:   progressCheckMark,
			Label:  humanizeMatcherName(name),
			Detail: matcherProgressDetail(g, name),
		})
	}
	children = append(children, warningProgressChildren(warnings)...)
	return children
}

func matcherProgressDetail(g *model.Graph, matcherName string) string {
	if g == nil {
		return ""
	}

	packages := 0
	vulnerabilities := 0
	for _, pkg := range g.Packages() {
		if pkg == nil {
			continue
		}
		switch matcherName {
		case depsdevCheckerName:
			if packageHasLicenseSource(pkg, "external-depsdev") {
				packages++
			}
		case clearlyDefinedCheckerName:
			if packageHasLicenseSource(pkg, "external-clearlydefined") {
				packages++
			}
		case osvMatcherName, grypeMatcherName:
			matchedPackage := false
			for _, vulnerability := range pkg.Vulnerabilities {
				if vulnerability.Source != matcherName {
					continue
				}
				vulnerabilities++
				matchedPackage = true
			}
			if matchedPackage {
				packages++
			}
		case eolCheckerName:
			if pkg.Metadata != nil {
				if _, ok := pkg.Metadata[eolMetadataKey]; ok {
					packages++
				}
			}
		}
	}

	switch matcherName {
	case depsdevCheckerName, clearlyDefinedCheckerName, eolCheckerName:
		return fmt.Sprintf("[%d matched packages]", packages)
	case osvMatcherName, grypeMatcherName:
		return fmt.Sprintf("[%d matched packages, %d vulnerabilities]", packages, vulnerabilities)
	default:
		if vulnerabilities > 0 {
			return fmt.Sprintf("[%d matched packages, %d vulnerabilities]", packages, vulnerabilities)
		}
		if packages > 0 {
			return fmt.Sprintf("[%d matched packages]", packages)
		}
		return ""
	}
}

func packageHasLicenseSource(pkg *model.Package, sourceType string) bool {
	if pkg == nil {
		return false
	}
	for _, license := range pkg.Licenses {
		if license.Type == sourceType {
			return true
		}
	}
	return false
}

// humanizeDetectorName converts a detector name like "maven-detector" to "Maven Detector".
func humanizeDetectorName(name string) string {
	name = strings.TrimSuffix(name, "-detector")
	parts := strings.Split(name, "-")
	for i, part := range parts {
		if isAcronym(part) {
			parts[i] = strings.ToUpper(part)
		} else if len(part) > 0 {
			parts[i] = strings.ToUpper(part[:1]) + part[1:]
		}
	}
	return strings.Join(parts, " ") + " Detector"
}

// humanizeLicenseSource converts a license source type to a display name.
func humanizeLicenseSource(sourceType string) string {
	switch sourceType {
	case "external-depsdev":
		return "deps.dev"
	case "external-clearlydefined":
		return "ClearlyDefined"
	default:
		return sourceType
	}
}

// humanizeAuditorSource converts an auditor source name to a display name.
func humanizeAuditorSource(source string) string {
	switch strings.ToLower(source) {
	case "severity-policy":
		return "Severity Policy Auditor"
	case "grype":
		return "Grype Auditor"
	case "osv":
		return "OSV Auditor"
	default:
		if isAcronym(source) {
			return strings.ToUpper(source) + " Auditor"
		}
		if len(source) > 0 {
			return strings.ToUpper(source[:1]) + source[1:] + " Auditor"
		}
		return "Auditor"
	}
}

// humanizeMatcherName converts a matcher name like "depsdev-license-checker" to "deps.dev".
func humanizeMatcherName(name string) string {
	switch name {
	case "depsdev-license-checker":
		return "deps.dev"
	case "clearlydefined-license-checker":
		return "ClearlyDefined"
	default:
		name = strings.TrimSuffix(name, "-license-checker")
		parts := strings.Split(name, "-")
		for i, part := range parts {
			if isAcronym(part) {
				parts[i] = strings.ToUpper(part)
			} else if len(part) > 0 {
				parts[i] = strings.ToUpper(part[:1]) + part[1:]
			}
		}
		return strings.Join(parts, " ")
	}
}

func isAcronym(s string) bool {
	switch strings.ToLower(s) {
	case "npm", "pnpm", "osv", "sbom", "uv":
		return true
	default:
		return false
	}
}
