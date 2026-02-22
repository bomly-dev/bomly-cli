package model

import (
	"fmt"
	"sort"
	"strings"
)

// RenderSupportMatrixMarkdown renders the canonical markdown support matrix document.
func RenderSupportMatrixMarkdown() string {
	var builder strings.Builder
	builder.WriteString("# Support Matrix\n\n")
	builder.WriteString("This document lists the ecosystems and package managers Bomly can identify today.\n\n")
	builder.WriteString("It is generated from the canonical support registry in `internal/registry/support.go`.\n\n")
	builder.WriteString("Bomly groups support into two implementation paths:\n\n")
	builder.WriteString("- Native detectors implemented directly in Bomly.\n")
	builder.WriteString("- Third-party-backed detection powered by Syft support metadata.\n\n")
	builder.WriteString("## Native Detectors\n\n")
	builder.WriteString("| Ecosystem | Package managers | Detector |\n")
	builder.WriteString("| --- | --- | --- |\n")
	for _, entry := range groupedEntries(NativeDetector) {
		builder.WriteString(fmt.Sprintf("| `%s` | %s | %s |\n", entry.ecosystem, wrapCodeList(entry.managers), nativeDetectorLabel(entry.ecosystem)))
	}
	builder.WriteString("\n## Third-Party Support\n\n")
	builder.WriteString("The entries below show Syft-backed ecosystem coverage plus representative files Bomly uses during planning and discovery.\n\n")
	builder.WriteString("Source: https://oss.anchore.com/docs/capabilities/all-packages/\n\n")
	builder.WriteString("| Ecosystem | Package managers | Representative file evidence |\n")
	builder.WriteString("| --- | --- | --- |\n")
	for _, entry := range groupedEntries(ThirdPartyDetector) {
		builder.WriteString(fmt.Sprintf("| `%s` | %s | %s |\n", entry.ecosystem, wrapCodeList(entry.managers), wrapCodeList(entry.patterns)))
	}
	builder.WriteString("\n## Notes\n\n")
	builder.WriteString("- Bomly does not expose every Syft cataloger as a package manager.\n")
	builder.WriteString("- Some OS image and binary catalogers are intentionally omitted when they do not map cleanly to Bomly's ecosystem and package-manager model.\n")
	builder.WriteString("- The `maven` ecosystem is a shared umbrella for both Maven and Gradle.\n")
	builder.WriteString("\n## Syft Container OS Support\n\n")
	builder.WriteString("These OS families are listed separately because they describe container base-image detection rather than language-specific package managers.\n\n")
	builder.WriteString("Source: https://oss.anchore.com/docs/capabilities/all-os/\n\n")
	builder.WriteString("| OS family | Syft provider | Version source |\n")
	builder.WriteString("| --- | --- | --- |\n")
	for _, item := range operatingSystemRegistry {
		label := item.Name
		if len(item.Aliases) > 0 {
			label = fmt.Sprintf("%s (%s)", item.Name, strings.Join(item.Aliases, ", "))
		}
		builder.WriteString(fmt.Sprintf("| `%s` | `%s` | `%s` |\n", label, item.Provider, item.VersionSource))
	}
	return builder.String()
}

func groupedEntries(detectorType DetectorType) []groupedSupportEntry {
	indexByEcosystem := make(map[Ecosystem]int)
	result := make([]groupedSupportEntry, 0, len(ecosystemRegistry))
	for _, entry := range SupportEntriesForDetectorType(detectorType) {
		idx, ok := indexByEcosystem[entry.Ecosystem]
		if !ok {
			idx = len(result)
			indexByEcosystem[entry.Ecosystem] = idx
			result = append(result, groupedSupportEntry{
				ecosystem: entry.Ecosystem,
				managers:  []string{},
				patterns:  []string{},
			})
		}
		result[idx].managers = appendUniqueString(result[idx].managers, entry.Manager.Name())
		for _, pattern := range entry.EvidencePatterns {
			result[idx].patterns = appendUniqueString(result[idx].patterns, pattern)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].ecosystem < result[j].ecosystem
	})
	return result
}

func appendUniqueString(values []string, value string) []string {
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func wrapCodeList(values []string) string {
	if len(values) == 0 {
		return ""
	}
	items := make([]string, 0, len(values))
	for _, value := range values {
		items = append(items, "`"+value+"`")
	}
	return strings.Join(items, ", ")
}

func nativeDetectorLabel(ecosystem Ecosystem) string {
	switch ecosystem {
	case EcosystemNPM:
		return "Native Node detectors"
	case EcosystemMaven:
		return "Native Maven and Gradle detectors"
	case EcosystemGo:
		return "Native Go detector"
	case EcosystemPython:
		return "Native Python detectors"
	case EcosystemSBOM:
		return "Native SBOM detector"
	default:
		return "Native detector"
	}
}
