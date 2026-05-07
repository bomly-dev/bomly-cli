package opts

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	err2 "github.com/bomly-dev/bomly-cli/internal/cli/exit"
	"github.com/bomly-dev/bomly-cli/internal/engine"
	"github.com/bomly-dev/bomly-cli/internal/registry"
	"github.com/bomly-dev/bomly-cli/internal/selector"
	model "github.com/bomly-dev/bomly-cli/sdk"
)

type detectorOptionRow struct {
	Name            string
	Aliases         []string
	Ecosystems      []string
	PackageManagers []string
}

const (
	OSVMatcherName             = "osv"
	GrypeMatcherName           = "grype"
	SeverityPolicyAuditorName  = "severity-policy"
	ClearlyDefinedCheckerName  = "clearlydefined-license-checker"
	clearlyDefinedCheckerAlias = "clearlydefined"
	DepsdevCheckerName         = "depsdev-license-checker"
	depsdevCheckerAlias        = "deps.dev"
	EOLCheckerName             = "eol-checker"
	eolCheckerAlias            = "eol"
	EOLMetadataKey             = "endoflife.date"

	osvMatcherName            = OSVMatcherName
	grypeMatcherName          = GrypeMatcherName
	clearlyDefinedCheckerName = ClearlyDefinedCheckerName
	depsdevCheckerName        = DepsdevCheckerName
	eolCheckerName            = EOLCheckerName
	eolMetadataKey            = EOLMetadataKey
)

func buildDetectorOptionRows(reg *engine.Registry) []detectorOptionRow {
	if reg == nil {
		return nil
	}
	rows := make(map[string]*detectorOptionRow)
	for _, descriptor := range reg.DetectorDescriptors() {
		name := strings.TrimSpace(descriptor.Name)
		if name == "" {
			continue
		}
		row := &detectorOptionRow{Name: name}
		if alias := detectorShortAlias(name); alias != "" {
			row.Aliases = []string{alias}
		}
		for _, ecosystem := range descriptor.SupportedEcosystems {
			value := strings.TrimSpace(string(ecosystem))
			if value != "" {
				row.Ecosystems = selector.AppendUnique(row.Ecosystems, value)
			}
		}
		rows[name] = row
	}

	for _, support := range registry.SupportEntries() {
		managerName := strings.TrimSpace(support.Manager.Name())
		ecosystemName := strings.TrimSpace(string(support.Ecosystem))
		for _, detectorName := range support.Detectors {
			row, ok := rows[detectorName]
			if !ok {
				continue
			}
			if managerName != "" {
				row.PackageManagers = selector.AppendUnique(row.PackageManagers, managerName)
			}
			if ecosystemName != "" {
				row.Ecosystems = selector.AppendUnique(row.Ecosystems, ecosystemName)
			}
		}
	}

	out := make([]detectorOptionRow, 0, len(rows))
	for _, row := range rows {
		sort.Strings(row.Aliases)
		sort.Strings(row.Ecosystems)
		sort.Strings(row.PackageManagers)
		out = append(out, *row)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func buildDetectorSelectorCatalog(reg *engine.Registry) selector.Catalog {
	rows := buildDetectorOptionRows(reg)
	aliasToName := make(map[string]string, len(rows)*2)
	available := make([]string, 0, len(rows))
	simplified := make([]string, 0, len(rows))

	for _, row := range rows {
		available = append(available, row.Name)
		aliasToName[row.Name] = row.Name
		if len(row.Aliases) > 0 {
			simplified = append(simplified, fmt.Sprintf("%s (%s)", row.Aliases[0], row.Name))
		} else {
			simplified = append(simplified, row.Name)
		}
		for _, alias := range row.Aliases {
			aliasToName[alias] = row.Name
		}
	}
	sort.Strings(available)
	sort.Strings(simplified)
	return selector.Catalog{
		Kind:        "detector",
		Available:   available,
		AliasToName: aliasToName,
		Items:       simplified,
	}
}

func buildEcosystemSelectorCatalog() selector.Catalog {
	ecosystems := registry.SupportedEcosystems()
	aliasMap := registry.EcosystemAliasMap()
	available := make([]string, 0, len(ecosystems))
	for _, e := range ecosystems {
		available = append(available, string(e))
	}
	sort.Strings(available)
	aliasToName := make(map[string]string, len(aliasMap))
	for k, v := range aliasMap {
		aliasToName[k] = v
	}
	simplified := append([]string(nil), available...)
	return selector.Catalog{
		Kind:        "ecosystem",
		Available:   available,
		AliasToName: aliasToName,
		Items:       simplified,
	}
}

func resolveEcosystemFilter(raw string) (model.EcosystemFilter, error) {
	catalog := buildEcosystemSelectorCatalog()
	defaults := append([]string(nil), catalog.Available...)
	includeNames, excludeNames, err := resolveSelector(raw, defaults, catalog, true)
	if err != nil {
		return model.EcosystemFilter{}, err
	}
	include, err := ecosystemStringSliceToValues(includeNames)
	if err != nil {
		return model.EcosystemFilter{}, err
	}
	exclude, err := ecosystemStringSliceToValues(excludeNames)
	if err != nil {
		return model.EcosystemFilter{}, err
	}
	return model.EcosystemFilter{Include: include, Exclude: exclude}, nil
}

func ecosystemStringSliceToValues(items []string) ([]model.Ecosystem, error) {
	if len(items) == 0 {
		return nil, nil
	}
	values := make([]model.Ecosystem, 0, len(items))
	seen := make(map[model.Ecosystem]struct{}, len(items))
	for _, name := range items {
		eco, err := model.ParseEcosystem(name)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[eco]; ok {
			continue
		}
		seen[eco] = struct{}{}
		values = append(values, eco)
	}
	return values, nil
}

func buildAuditorSelectorCatalog(reg *engine.Registry) selector.Catalog {
	available := make([]string, 0)
	aliasToName := make(map[string]string)
	for _, descriptor := range reg.AuditorDescriptors() {
		name := strings.TrimSpace(descriptor.Name)
		if name == "" {
			continue
		}
		available = append(available, name)
		aliasToName[name] = name
	}
	simplified := make([]string, 0, len(available))
	for _, name := range available {
		simplified = append(simplified, name)
	}
	sort.Strings(available)
	sort.Strings(simplified)
	return selector.Catalog{Kind: "auditor", Available: available, AliasToName: aliasToName, Items: simplified}
}

func buildMatcherSelectorCatalog(reg *engine.Registry) selector.Catalog {
	available := make([]string, 0)
	aliasToName := make(map[string]string)
	for _, descriptor := range reg.MatcherDescriptors() {
		name := strings.TrimSpace(descriptor.Name)
		if name == "" {
			continue
		}
		available = append(available, name)
		aliasToName[name] = name
	}
	// User-facing aliases (shown in help/completions).
	aliasToName[clearlyDefinedCheckerAlias] = clearlyDefinedCheckerName
	aliasToName[depsdevCheckerAlias] = depsdevCheckerName
	aliasToName[eolCheckerAlias] = eolCheckerName
	aliasToName["osv"] = osvMatcherName
	aliasToName["grype"] = grypeMatcherName
	// Full internal names accepted silently for backward compat but not shown in help.
	aliasToName[clearlyDefinedCheckerName] = clearlyDefinedCheckerName
	aliasToName[depsdevCheckerName] = depsdevCheckerName
	aliasToName[eolCheckerName] = eolCheckerName
	aliasToName[osvMatcherName] = osvMatcherName
	aliasToName[grypeMatcherName] = grypeMatcherName

	simplified := make([]string, 0, len(available))
	for _, name := range available {
		switch name {
		case clearlyDefinedCheckerName:
			simplified = append(simplified, fmt.Sprintf("%s (%s)", clearlyDefinedCheckerAlias, clearlyDefinedCheckerName))
		case depsdevCheckerName:
			simplified = append(simplified, fmt.Sprintf("%s (%s)", depsdevCheckerAlias, depsdevCheckerName))
		case eolCheckerName:
			simplified = append(simplified, fmt.Sprintf("%s (%s)", eolCheckerAlias, eolCheckerName))
		case osvMatcherName:
			simplified = append(simplified, osvMatcherName)
		case grypeMatcherName:
			simplified = append(simplified, grypeMatcherName)
		default:
			simplified = append(simplified, name)
		}
	}
	sort.Strings(available)
	sort.Strings(simplified)
	return selector.Catalog{Kind: "matcher", Available: available, AliasToName: aliasToName, Items: simplified}
}

func detectorShortAlias(name string) string {
	trimmed := strings.TrimSpace(strings.ToLower(name))
	if strings.HasSuffix(trimmed, "-detector") {
		return strings.TrimSuffix(trimmed, "-detector")
	}
	return ""
}

// resolveSelector wraps selector.Resolve and translates the typed unknown-selector
// error into the CLI's invalidInputError so cobra surfaces a help hint.
func resolveSelector(raw string, defaults []string, catalog selector.Catalog, implicitAllWhenEmpty bool) ([]string, []string, error) {
	include, exclude, err := selector.Resolve(raw, defaults, catalog, implicitAllWhenEmpty)
	if err == nil {
		return include, exclude, nil
	}
	var unknown *selector.UnknownSelectorError
	if errors.As(err, &unknown) {
		return nil, nil, err2.InvalidInputError(
			"unknown %s selector(s): %s\navailable %ss: %s\nrun `bomly scan --help` for full selector details",
			unknown.Kind,
			strings.Join(unknown.Unknown, ", "),
			unknown.Kind,
			strings.Join(unknown.Items, ", "),
		)
	}
	return nil, nil, err
}

func resolveDetectorFilter(raw string, reg *engine.Registry) (model.DetectorFilter, error) {
	catalog := buildDetectorSelectorCatalog(reg)
	defaultSet := defaultEnabledDetectorNames(reg)
	include, exclude, err := resolveSelector(raw, defaultSet, catalog, true)
	if err != nil {
		return model.DetectorFilter{}, err
	}
	return model.DetectorFilter{Include: include, Exclude: exclude}, nil
}

func ResolveAuditorFilter(raw string, reg *engine.Registry) (model.AuditorFilter, error) {
	if strings.TrimSpace(raw) == "" {
		return model.AuditorFilter{}, nil
	}
	catalog := buildAuditorSelectorCatalog(reg)
	defaultSet := defaultEnabledAuditorNames(reg)
	include, exclude, err := resolveSelector(raw, defaultSet, catalog, false)
	if err != nil {
		return model.AuditorFilter{}, err
	}
	return model.AuditorFilter{Include: include, Exclude: exclude}, nil
}

func ResolveMatcherFilter(raw string, reg *engine.Registry) (model.MatcherFilter, error) {
	if strings.TrimSpace(raw) == "" {
		return model.MatcherFilter{}, nil
	}
	catalog := buildMatcherSelectorCatalog(reg)
	defaultSet := defaultEnabledMatcherNames(reg)
	include, exclude, err := resolveSelector(raw, defaultSet, catalog, false)
	if err != nil {
		return model.MatcherFilter{}, err
	}
	return model.MatcherFilter{Include: include, Exclude: exclude}, nil
}

func resolveMatcherFilter(raw string, reg *engine.Registry) (model.MatcherFilter, error) {
	return ResolveMatcherFilter(raw, reg)
}

func filterAllowsName(include, exclude []string, name string) bool {
	if len(include) > 0 && !selector.Contains(include, name) {
		return false
	}
	if selector.Contains(exclude, name) {
		return false
	}
	return true
}

func selectedDetectorNames(filter model.DetectorFilter, reg *engine.Registry) []string {
	names := make([]string, 0)
	for _, descriptor := range reg.DetectorDescriptors() {
		if descriptor.Name == "" {
			continue
		}
		if !filterAllowsName(filter.Include, filter.Exclude, descriptor.Name) {
			continue
		}
		names = append(names, descriptor.Name)
	}
	sort.Strings(names)
	return names
}

func defaultEnabledDetectorNames(reg *engine.Registry) []string {
	if reg == nil {
		return nil
	}
	names := make([]string, 0)
	for _, descriptor := range reg.DetectorDescriptors() {
		if descriptor.Name == "" || !descriptor.Enabled {
			continue
		}
		names = append(names, descriptor.Name)
	}
	sort.Strings(names)
	return names
}

func defaultEnabledAuditorNames(reg *engine.Registry) []string {
	if reg == nil {
		return nil
	}
	names := make([]string, 0)
	for _, descriptor := range reg.AuditorDescriptors() {
		if descriptor.Name == "" || !descriptor.Enabled {
			continue
		}
		names = append(names, descriptor.Name)
	}
	sort.Strings(names)
	return names
}

func defaultEnabledMatcherNames(reg *engine.Registry) []string {
	if reg == nil {
		return nil
	}
	names := make([]string, 0)
	for _, descriptor := range reg.MatcherDescriptors() {
		if descriptor.Name == "" || !descriptor.Enabled {
			continue
		}
		names = append(names, descriptor.Name)
	}
	sort.Strings(names)
	return names
}
