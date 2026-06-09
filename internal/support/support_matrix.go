package support

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/registry"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// RenderSupportMatrixMarkdown renders the canonical markdown support matrix document.
func RenderSupportMatrixMarkdown() string {
	var builder strings.Builder
	builder.WriteString("# Support Matrix\n\n")
	builder.WriteString("This document lists the ecosystems and package managers Bomly can identify today.\n\n")
	builder.WriteString("It is generated from the canonical support registry in `internal/registry/support.go`.\n\n")
	builder.WriteString("Bomly groups support into two implementation paths:\n\n")
	builder.WriteString("- Core detectors implemented directly in Bomly.\n")
	builder.WriteString("- Bundled detectors based on third-party tools that are distributed with Bomly and maintained by the Bomly team.\n\n")
	builder.WriteString("## Core Detectors\n\n")
	builder.WriteString("Primary detector files are the preferred inputs for Bomly-owned resolution. Fallback detector files are inputs for the next built-in Bomly detector in the same chain; Syft-only backstops are omitted here and listed under Bundled detectors support.\n\n")
	builder.WriteString("Some primary detectors execute the ecosystem build tool to recover richer dependency edges than a committed lockfile or manifest can provide. When the tool is not installed or the build-tool command fails, Bomly falls back to the next detector in the chain. For reproducible validation of those richer graphs, make sure the relevant tools are on `PATH` before running smoke tests or the local benchmark.\n\n")
	builder.WriteString("| Ecosystem | Package managers | Primary detector files | Fallback detector files | Detector |\n")
	builder.WriteString("| --- | --- | --- | --- | --- |\n")
	for _, entry := range groupedNativeEntries() {
		_, _ = fmt.Fprintf(&builder, "| `%s` | %s | %s | %s | %s |\n", entry.ecosystem, codeList(entry.managers), codeListOrDash(entry.primaryPatterns), codeListOrDash(entry.fallbackPatterns), nativeDetectorLabel(entry.ecosystem))
	}
	builder.WriteString("\n## Bundled Detectors\n\n")
	builder.WriteString("The entries below show Syft-backed ecosystem coverage plus representative files Bomly uses during planning and discovery.\n\n")
	builder.WriteString("Source: https://oss.anchore.com/docs/capabilities/all-packages/\n\n")
	builder.WriteString("| Ecosystem | Package managers | Representative file evidence |\n")
	builder.WriteString("| --- | --- | --- |\n")
	for _, entry := range groupedMultipleTechniqueEntries() {
		_, _ = fmt.Fprintf(&builder, "| `%s` | %s | %s |\n", entry.ecosystem, codeList(entry.managers), codeList(entry.patterns))
	}
	builder.WriteString("\n## Notes\n\n")
	builder.WriteString("- Bomly does not expose every Syft cataloger as a package manager.\n")
	builder.WriteString("- Some OS image and binary catalogers are intentionally omitted when they do not map cleanly to Bomly's ecosystem and package-manager model.\n")
	builder.WriteString("- Build-tool-backed detectors currently include Pub (`dart`), SwiftPM (`swift`), and SBT (`sbt`) for richer transitive graph resolution when those tools are available.\n")
	builder.WriteString("\n## Syft Container OS Support\n\n")
	builder.WriteString("These OS families are listed separately because they describe container base-image detection rather than language-specific package managers.\n\n")
	builder.WriteString("Source: https://oss.anchore.com/docs/capabilities/all-os/\n\n")
	builder.WriteString("| OS family | Syft provider | Version source |\n")
	builder.WriteString("| --- | --- | --- |\n")
	for _, item := range registry.SupportedOperatingSystems() {
		label := item.Name
		if len(item.Aliases) > 0 {
			label = fmt.Sprintf("%s (%s)", item.Name, strings.Join(item.Aliases, ", "))
		}
		_, _ = fmt.Fprintf(&builder, "| `%s` | `%s` | `%s` |\n", label, item.Provider, item.VersionSource)
	}
	return builder.String()
}

// WriteSupportMatrix writes the generated support matrix markdown to disk.
func WriteSupportMatrix(outputPath string) error {
	if err := os.WriteFile(outputPath, []byte(RenderSupportMatrixMarkdown()), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", outputPath, err)
	}
	return nil
}

type groupedEntry struct {
	ecosystem        sdk.Ecosystem
	managers         []string
	patterns         []string
	primaryPatterns  []string
	fallbackPatterns []string
}

// groupedNativeEntries reports the first Bomly-owned detector in each built-in
// package-manager chain and, when present, the next Bomly-owned fallback.
func groupedNativeEntries() []groupedEntry {
	indexByEcosystem := make(map[sdk.Ecosystem]int)
	result := make([]groupedEntry, 0)
	for _, entry := range registry.SupportEntries() {
		primary, fallback := firstBuiltInDetectorPair(entry.Detectors)
		if primary == "" {
			continue
		}
		idx, ok := indexByEcosystem[entry.Ecosystem]
		if !ok {
			idx = len(result)
			indexByEcosystem[entry.Ecosystem] = idx
			result = append(result, groupedEntry{ecosystem: entry.Ecosystem})
		}
		result[idx].managers = appendUnique(result[idx].managers, entry.Manager.Name())
		for _, pattern := range entry.EvidencePatternsByDetector[primary] {
			result[idx].primaryPatterns = appendUnique(result[idx].primaryPatterns, pattern)
		}
		for _, pattern := range entry.EvidencePatternsByDetector[fallback] {
			result[idx].fallbackPatterns = appendUnique(result[idx].fallbackPatterns, pattern)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].ecosystem < result[j].ecosystem
	})
	return result
}

func firstBuiltInDetectorPair(detectors []string) (string, string) {
	primary := ""
	for _, detector := range detectors {
		if registry.DetectorOriginForName(detector) == sdk.CoreOrigin {
			if primary == "" {
				primary = detector
				continue
			}
			return primary, detector
		}
	}
	return primary, ""
}

func groupedMultipleTechniqueEntries() []groupedEntry {
	indexByEcosystem := make(map[sdk.Ecosystem]int)
	result := make([]groupedEntry, 0)
	for _, entry := range registry.SupportEntriesForTechnique(sdk.MultipleTechnique) {
		idx, ok := indexByEcosystem[entry.Ecosystem]
		if !ok {
			idx = len(result)
			indexByEcosystem[entry.Ecosystem] = idx
			result = append(result, groupedEntry{ecosystem: entry.Ecosystem})
		}
		result[idx].managers = appendUnique(result[idx].managers, entry.Manager.Name())
		for _, pattern := range entry.EvidencePatterns {
			result[idx].patterns = appendUnique(result[idx].patterns, pattern)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].ecosystem < result[j].ecosystem
	})
	return result
}

func appendUnique(values []string, value string) []string {
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

func codeList(values []string) string {
	if len(values) == 0 {
		return ""
	}
	items := make([]string, 0, len(values))
	for _, v := range values {
		items = append(items, "`"+v+"`")
	}
	return strings.Join(items, ", ")
}

func codeListOrDash(values []string) string {
	if len(values) == 0 {
		return "-"
	}
	return codeList(values)
}

func nativeDetectorLabel(ecosystem sdk.Ecosystem) string {
	switch ecosystem {
	case sdk.EcosystemNPM:
		return "Native Node detectors"
	case sdk.EcosystemMaven:
		return "Native Maven and Gradle detectors"
	case sdk.EcosystemGo:
		return "Native Go detector"
	case sdk.EcosystemPython:
		return "Native Python detectors"
	case sdk.EcosystemSBOM:
		return "Native SBOM detector"
	default:
		return "Native detector"
	}
}
