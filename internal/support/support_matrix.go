package support

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/registry"
	model "github.com/bomly-dev/bomly-cli/sdk"
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
	for _, entry := range groupedNativeEntries() {
		builder.WriteString(fmt.Sprintf("| `%s` | %s | %s |\n", entry.ecosystem, codeList(entry.managers), nativeDetectorLabel(entry.ecosystem)))
	}
	builder.WriteString("\n## Third-Party Support\n\n")
	builder.WriteString("The entries below show Syft-backed ecosystem coverage plus representative files Bomly uses during planning and discovery.\n\n")
	builder.WriteString("Source: https://oss.anchore.com/docs/capabilities/all-packages/\n\n")
	builder.WriteString("| Ecosystem | Package managers | Representative file evidence |\n")
	builder.WriteString("| --- | --- | --- |\n")
	for _, entry := range groupedSupportEntries(model.ThirdPartyComponent) {
		builder.WriteString(fmt.Sprintf("| `%s` | %s | %s |\n", entry.ecosystem, codeList(entry.managers), codeList(entry.patterns)))
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
	for _, item := range registry.SupportedOperatingSystems() {
		label := item.Name
		if len(item.Aliases) > 0 {
			label = fmt.Sprintf("%s (%s)", item.Name, strings.Join(item.Aliases, ", "))
		}
		builder.WriteString(fmt.Sprintf("| `%s` | `%s` | `%s` |\n", label, item.Provider, item.VersionSource))
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
	ecosystem model.Ecosystem
	managers  []string
	patterns  []string
}

// groupedNativeEntries merges NativeComponent and LockfileParserComponent entries
// so that lockfile-based detectors appear together with native detectors in the
// support matrix (they are first-class built-in detectors from the user perspective).
func groupedNativeEntries() []groupedEntry {
	indexByEcosystem := make(map[model.Ecosystem]int)
	result := make([]groupedEntry, 0)
	for _, componentType := range []model.ComponentType{model.NativeComponent, model.LockfileParserComponent} {
		for _, entry := range registry.SupportEntriesForDetectorType(componentType) {
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
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].ecosystem < result[j].ecosystem
	})
	return result
}

func groupedSupportEntries(detectorType model.ComponentType) []groupedEntry {
	indexByEcosystem := make(map[model.Ecosystem]int)
	result := make([]groupedEntry, 0)
	for _, entry := range registry.SupportEntriesForDetectorType(detectorType) {
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

func nativeDetectorLabel(ecosystem model.Ecosystem) string {
	switch ecosystem {
	case model.EcosystemNPM:
		return "Native Node detectors"
	case model.EcosystemMaven:
		return "Native Maven and Gradle detectors"
	case model.EcosystemGo:
		return "Native Go detector"
	case model.EcosystemPython:
		return "Native Python detectors"
	case model.EcosystemSBOM:
		return "Native SBOM detector"
	default:
		return "Native detector"
	}
}
