package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/registry"
	"github.com/bomly-dev/bomly-cli/internal/scan"
	"github.com/bomly-dev/bomly-cli/internal/selector"
	model "github.com/bomly-dev/bomly-cli/sdk"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func bindDynamicFlagOptions(cmd *cobra.Command) error {
	ecosystems := availableEcosystemOptions()
	detectors := availableDetectorOptions()
	auditors := availableAuditorOptions(zap.NewNop())
	matchers := availableMatcherOptions()

	if err := cmd.RegisterFlagCompletionFunc("ecosystems", csvCompletionFunc(ecosystems)); err != nil {
		return err
	}
	if err := cmd.RegisterFlagCompletionFunc("detectors", csvCompletionFunc(detectors)); err != nil {
		return err
	}
	if err := cmd.RegisterFlagCompletionFunc("auditors", csvCompletionFunc(auditors)); err != nil {
		return err
	}
	if err := cmd.RegisterFlagCompletionFunc("matchers", csvCompletionFunc(matchers)); err != nil {
		return err
	}

	return nil
}

func availableEcosystemOptions() []string {
	seen := map[string]struct{}{}
	options := make([]string, 0)
	reg := scan.NewRegistry(scan.RegistryConfigs{}, *zap.NewNop())
	reg.Build()
	for _, descriptor := range reg.DetectorDescriptors() {
		for _, ecosystem := range descriptor.SupportedEcosystems {
			value := strings.TrimSpace(string(ecosystem))
			if value == "" {
				continue
			}
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			options = append(options, value)
		}
	}
	sort.Strings(options)
	return options
}

func availableDetectorOptions() []string {
	reg := scan.NewRegistry(scan.RegistryConfigs{}, *zap.NewNop())
	reg.Build()
	rows := buildDetectorOptionRows(reg)
	seen := map[string]struct{}{}
	options := make([]string, 0, len(rows)*2)
	for _, row := range rows {
		if row.Name != "" {
			if _, ok := seen[row.Name]; !ok {
				seen[row.Name] = struct{}{}
				options = append(options, row.Name)
			}
		}
		for _, alias := range row.Aliases {
			if alias == "" {
				continue
			}
			if _, ok := seen[alias]; ok {
				continue
			}
			seen[alias] = struct{}{}
			options = append(options, alias)
		}
	}
	sort.Strings(options)
	return options
}

// availableAuditorOptions returns auditor names for shell completion.
func availableAuditorOptions(logger *zap.Logger) []string {
	seen := map[string]struct{}{}
	options := make([]string, 0)
	reg := scan.NewRegistry(scan.RegistryConfigs{}, *logger)
	reg.Build()
	for _, descriptor := range reg.AuditorDescriptors() {
		name := descriptor.Name
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		options = append(options, name)
	}
	sort.Strings(options)
	return options
}

// availableMatcherOptions returns matcher names for shell completion.
func availableMatcherOptions() []string {
	seen := map[string]struct{}{}
	options := make([]string, 0)
	reg := scan.NewRegistry(scan.RegistryConfigs{}, *zap.NewNop())
	reg.Build()
	for _, descriptor := range reg.MatcherDescriptors() {
		name := descriptor.Name
		if name == "" {
			continue
		}
		// Internal names replaced by user-facing aliases below.
		if name == clearlyDefinedCheckerName || name == depsdevCheckerName || name == eolCheckerName {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		options = append(options, name)
	}
	// Emit user-facing aliases only.
	for _, alias := range []string{clearlyDefinedCheckerAlias, depsdevCheckerAlias, eolCheckerAlias} {
		if alias == "" {
			continue
		}
		if _, ok := seen[alias]; ok {
			continue
		}
		seen[alias] = struct{}{}
		options = append(options, alias)
	}
	sort.Strings(options)
	return options
}

func availableContainerOSOptions() []string {
	seen := map[string]struct{}{}
	options := make([]string, 0)
	for _, item := range registry.SupportedOperatingSystems() {
		for _, value := range append([]string{item.Name}, item.Aliases...) {
			normalized := strings.TrimSpace(strings.ToLower(value))
			if normalized == "" {
				continue
			}
			if _, ok := seen[normalized]; ok {
				continue
			}
			seen[normalized] = struct{}{}
			options = append(options, normalized)
		}
	}
	sort.Strings(options)
	return options
}

func csvCompletionFunc(options []string) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		prefix := ""
		current := toComplete
		if idx := strings.LastIndex(toComplete, ","); idx >= 0 {
			prefix = toComplete[:idx+1]
			current = toComplete[idx+1:]
		}

		used := map[string]struct{}{}
		for _, part := range strings.Split(toComplete, ",") {
			value := strings.TrimSpace(part)
			if value == "" {
				continue
			}
			used[strings.TrimLeft(value, "+-")] = struct{}{}
		}

		matches := make([]string, 0, len(options))
		normalizedCurrent := strings.TrimSpace(current)
		sign := ""
		if strings.HasPrefix(normalizedCurrent, "+") || strings.HasPrefix(normalizedCurrent, "-") {
			sign = normalizedCurrent[:1]
			normalizedCurrent = strings.TrimSpace(normalizedCurrent[1:])
		}
		for _, option := range options {
			if _, ok := used[option]; ok && option != normalizedCurrent {
				continue
			}
			if normalizedCurrent != "" && !strings.HasPrefix(option, normalizedCurrent) {
				continue
			}
			matches = append(matches, prefix+sign+option)
		}
		return matches, cobra.ShellCompDirectiveNoFileComp
	}
}

func optionValuesHelpSection(cmd *cobra.Command) string {
	if cmd == nil {
		return ""
	}

	flags := cmd.Flags()
	if flags.Lookup("ecosystems") == nil &&
		flags.Lookup("detectors") == nil {
		return ""
	}

	return "\n\nExplore available detectors, matchers, and auditors with `bomly plugin list`."
}

func formatHelpList(label string, values []string) string {
	const width = 100
	if len(values) == 0 {
		return fmt.Sprintf("%s: none\n", label)
	}

	var builder strings.Builder
	builder.WriteString(label)
	builder.WriteString(":\n")

	line := "    "
	for i, value := range values {
		item := value
		if i < len(values)-1 {
			item += ","
		}
		if len(line)+len(item)+1 > width {
			builder.WriteString(strings.TrimRight(line, " "))
			builder.WriteString("\n")
			line = "    " + item + " "
			continue
		}
		line += item + " "
	}
	builder.WriteString(strings.TrimRight(line, " "))
	builder.WriteString("\n")
	return builder.String()
}

// ecosystemGroupRow is an internal grouping used when building detector table rows.
type ecosystemGroupRow struct {
	Ecosystem       string
	PackageManagers []string
	Detectors       []string
}

// buildBundledDetectorRows returns rows for the bundled detector table.
// Each row contains [Ecosystem, Package Managers, Detectors].
func buildBundledDetectorRows(reg *scan.Registry) [][]string {
	if reg == nil {
		return nil
	}
	detectorOrigins := make(map[string]model.DetectorOrigin, len(reg.DetectorDescriptors()))
	for _, desc := range reg.DetectorDescriptors() {
		detectorOrigins[desc.Name] = desc.Origin
	}
	rowMap := make(map[string]*ecosystemGroupRow)
	for _, support := range registry.SupportEntries() {
		eco := strings.TrimSpace(string(support.Ecosystem))
		if eco == "" {
			continue
		}
		var bundledDets []string
		for _, det := range support.Detectors {
			t := detectorOrigins[det]
			if t == model.CoreOrigin {
				bundledDets = append(bundledDets, det)
			}
		}
		if len(bundledDets) == 0 {
			continue
		}
		row := rowMap[eco]
		if row == nil {
			row = &ecosystemGroupRow{Ecosystem: eco}
			rowMap[eco] = row
		}
		manager := strings.TrimSpace(support.Manager.Name())
		if manager != "" {
			row.PackageManagers = selector.AppendUnique(row.PackageManagers, manager)
		}
		for _, det := range bundledDets {
			row.Detectors = selector.AppendUnique(row.Detectors, detectorEntryLabel(det))
		}
	}
	ecos := make([]string, 0, len(rowMap))
	for eco := range rowMap {
		ecos = append(ecos, eco)
	}
	sort.Strings(ecos)
	out := make([][]string, 0, len(ecos))
	for _, eco := range ecos {
		row := rowMap[eco]
		sort.Strings(row.PackageManagers)
		sort.Strings(row.Detectors)
		managers := strings.Join(row.PackageManagers, ", ")
		if managers == "" {
			managers = "-"
		}
		dets := strings.Join(row.Detectors, ", ")
		if dets == "" {
			dets = "-"
		}
		out = append(out, []string{eco, managers, dets})
	}
	return out
}

// buildExternalDetectorRows returns rows for the external detector table.
// Each row contains [Detector, Ecosystems].
func buildExternalDetectorRows(reg *scan.Registry) [][]string {
	if reg == nil {
		return nil
	}
	type entry struct {
		label string
		ecos  []string
	}
	byDet := make(map[string]*entry)
	for _, desc := range reg.DetectorDescriptors() {
		if desc.Origin != model.ExternalOrigin {
			continue
		}
		label := detectorEntryLabel(strings.TrimSpace(desc.Name))
		e := byDet[label]
		if e == nil {
			e = &entry{label: label}
			byDet[label] = e
		}
		for _, eco := range desc.SupportedEcosystems {
			ecoStr := strings.TrimSpace(string(eco))
			if ecoStr != "" {
				e.ecos = selector.AppendUnique(e.ecos, ecoStr)
			}
		}
	}
	labels := make([]string, 0, len(byDet))
	for label := range byDet {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	out := make([][]string, 0, len(labels))
	for _, label := range labels {
		e := byDet[label]
		sort.Strings(e.ecos)
		ecoList := strings.Join(e.ecos, ", ")
		if ecoList == "" {
			ecoList = "-"
		}
		out = append(out, []string{label, ecoList})
	}
	return out
}

// buildContainerOSRows returns rows for the container OS support table.
// Each row contains [OS, Aliases, Detector].
func buildContainerOSRows() [][]string {
	items := registry.SupportedOperatingSystems()
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	const detector = "syft-detector (syft)"
	out := make([][]string, 0, len(items))
	for _, item := range items {
		aliases := "-"
		if len(item.Aliases) > 0 {
			aliases = strings.Join(item.Aliases, ", ")
		}
		out = append(out, []string{item.Name, aliases, detector})
	}
	return out
}

// detectorEntryLabel returns "name (alias)" when a short alias exists, else just "name".
func detectorEntryLabel(name string) string {
	if alias := detectorShortAlias(name); alias != "" {
		return fmt.Sprintf("%s (%s)", name, alias)
	}
	return name
}

// formatTable renders a table with auto-sized columns and no borders.
// All columns except the last are right-padded to their measured max width.
// The last column wraps at ", " boundaries if it exceeds the remaining line budget.
func formatTable(label string, headers []string, rows [][]string) string {
	if len(rows) == 0 {
		return fmt.Sprintf("%s: none\n", label)
	}
	const indent = "  "
	const colSep = "  "
	const maxLineWidth = 100

	n := len(headers)
	widths := make([]int, n)
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i := 0; i < n-1 && i < len(row); i++ {
			if len(row[i]) > widths[i] {
				widths[i] = len(row[i])
			}
		}
	}

	// Compute prefix width (indent + all non-last columns + separators)
	prefixWidth := len(indent)
	for i := 0; i < n-1; i++ {
		prefixWidth += widths[i] + len(colSep)
	}
	lastColBudget := maxLineWidth - prefixWidth
	if lastColBudget < 20 {
		lastColBudget = 20
	}
	continuation := strings.Repeat(" ", prefixWidth)

	var b strings.Builder
	b.WriteString(label + ":\n")

	// Header row
	b.WriteString(indent)
	for i, h := range headers {
		if i < n-1 {
			fmt.Fprintf(&b, "%-*s%s", widths[i], h, colSep)
		} else {
			b.WriteString(h)
		}
	}
	b.WriteString("\n")

	// Separator row
	b.WriteString(indent)
	for i := range headers {
		dash := strings.Repeat("-", widths[i])
		if i < n-1 {
			fmt.Fprintf(&b, "%-*s%s", widths[i], dash, colSep)
		} else {
			b.WriteString(dash)
		}
	}
	b.WriteString("\n")

	// Data rows
	for _, row := range rows {
		b.WriteString(indent)
		for i := 0; i < n-1 && i < len(row); i++ {
			fmt.Fprintf(&b, "%-*s%s", widths[i], row[i], colSep)
		}
		lastCell := "-"
		if len(row) >= n {
			lastCell = row[n-1]
		}
		writeTableCell(&b, lastCell, lastColBudget, continuation)
	}

	return b.String()
}

// writeTableCell writes a cell value to b, wrapping at ", " if it exceeds budget.
func writeTableCell(b *strings.Builder, content string, budget int, continuation string) {
	if len(content) <= budget {
		b.WriteString(content)
		b.WriteString("\n")
		return
	}
	parts := strings.Split(content, ", ")
	line := ""
	newLine := false
	for _, part := range parts {
		if line == "" {
			line = part
		} else if len(line)+2+len(part) <= budget {
			line += ", " + part
		} else {
			if newLine {
				b.WriteString(continuation)
			}
			b.WriteString(line + ",\n")
			newLine = true
			line = part
		}
	}
	if line != "" {
		if newLine {
			b.WriteString(continuation)
		}
		b.WriteString(line + "\n")
	}
}
