package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/bomly/bomly-cli/internal/registry"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func bindDynamicFlagOptions(cmd *cobra.Command) error {
	ecosystems := availableEcosystemOptions()
	detectors := availableDetectorOptions()
	auditors := availableAuditorOptions(zap.NewNop())

	if err := cmd.RegisterFlagCompletionFunc("ecosystems", csvCompletionFunc(ecosystems)); err != nil {
		return err
	}
	if err := cmd.RegisterFlagCompletionFunc("exclude-ecosystems", csvCompletionFunc(ecosystems)); err != nil {
		return err
	}
	if err := cmd.RegisterFlagCompletionFunc("detectors", csvCompletionFunc(detectors)); err != nil {
		return err
	}
	if err := cmd.RegisterFlagCompletionFunc("exclude-detectors", csvCompletionFunc(detectors)); err != nil {
		return err
	}
	if err := cmd.RegisterFlagCompletionFunc("auditors", csvCompletionFunc(auditors)); err != nil {
		return err
	}
	if err := cmd.RegisterFlagCompletionFunc("exclude-auditors", csvCompletionFunc(auditors)); err != nil {
		return err
	}

	return nil
}

func availableEcosystemOptions() []string {
	seen := map[string]struct{}{}
	options := make([]string, 0)
	for _, descriptor := range registry.BuildScanRegistry(zap.NewNop(), registry.Config{}).DetectorDescriptors() {
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
	seen := map[string]struct{}{}
	options := make([]string, 0)
	for _, descriptor := range registry.BuildScanRegistry(zap.NewNop(), registry.Config{}).DetectorDescriptors() {
		if descriptor.Name == "" {
			continue
		}
		if _, ok := seen[descriptor.Name]; ok {
			continue
		}
		seen[descriptor.Name] = struct{}{}
		options = append(options, descriptor.Name)
	}
	sort.Strings(options)
	return options
}

// availableAuditorOptions returns auditor names for shell completion.
func availableAuditorOptions(logger *zap.Logger) []string {
	seen := map[string]struct{}{}
	options := make([]string, 0)
	for _, descriptor := range registry.BuildScanRegistry(logger, registry.Config{}).AuditorDescriptors() {
		if descriptor.Name == "" {
			continue
		}
		if _, ok := seen[descriptor.Name]; ok {
			continue
		}
		seen[descriptor.Name] = struct{}{}
		options = append(options, descriptor.Name)
	}
	sort.Strings(options)
	return options
}

// availableMatcherOptions returns matcher names for shell completion.
func availableMatcherOptions() []string {
	seen := map[string]struct{}{}
	options := make([]string, 0)
	for _, descriptor := range registry.BuildScanRegistry(zap.NewNop(), registry.Config{}).MatcherDescriptors() {
		if descriptor.Name == "" {
			continue
		}
		if _, ok := seen[descriptor.Name]; ok {
			continue
		}
		seen[descriptor.Name] = struct{}{}
		options = append(options, descriptor.Name)
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
			used[value] = struct{}{}
		}

		matches := make([]string, 0, len(options))
		normalizedCurrent := strings.TrimSpace(current)
		for _, option := range options {
			if _, ok := used[option]; ok && option != normalizedCurrent {
				continue
			}
			if normalizedCurrent != "" && !strings.HasPrefix(option, normalizedCurrent) {
				continue
			}
			matches = append(matches, prefix+option)
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
		flags.Lookup("exclude-ecosystems") == nil &&
		flags.Lookup("detectors") == nil &&
		flags.Lookup("exclude-detectors") == nil {
		return ""
	}

	var builder strings.Builder
	builder.WriteString("\n\nAvailable Options:\n")
	builder.WriteString(formatHelpList("  Detectors", availableDetectorOptions()))
	builder.WriteString("\n")
	builder.WriteString(formatHelpList("  Ecosystems", availableEcosystemOptions()))
	builder.WriteString("\n")
	builder.WriteString(formatHelpList("  Auditors", availableAuditorOptions(zap.NewNop())))
	builder.WriteString("\n")
	builder.WriteString(formatHelpList("  Matchers", availableMatcherOptions()))
	builder.WriteString("\n")
	builder.WriteString(formatHelpList("  Container OS", availableContainerOSOptions()))
	return builder.String()
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
