package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/registry"
	"github.com/bomly-dev/bomly-cli/internal/scan"
	model "github.com/bomly-dev/bomly-cli/sdk"
)

type selectorCatalog struct {
	kind            string
	available       []string
	aliasToName     map[string]string
	simplifiedItems []string
}

type detectorOptionRow struct {
	Name            string
	Aliases         []string
	Ecosystems      []string
	PackageManagers []string
}

func buildDetectorOptionRows(reg *scan.Registry) []detectorOptionRow {
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
				row.Ecosystems = appendUnique(row.Ecosystems, value)
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
				row.PackageManagers = appendUnique(row.PackageManagers, managerName)
			}
			if ecosystemName != "" {
				row.Ecosystems = appendUnique(row.Ecosystems, ecosystemName)
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

func buildDetectorSelectorCatalog(reg *scan.Registry) selectorCatalog {
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
	return selectorCatalog{
		kind:            "detector",
		available:       available,
		aliasToName:     aliasToName,
		simplifiedItems: simplified,
	}
}

func buildEcosystemSelectorCatalog() selectorCatalog {
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
	return selectorCatalog{
		kind:            "ecosystem",
		available:       available,
		aliasToName:     aliasToName,
		simplifiedItems: simplified,
	}
}

func resolveEcosystemFilter(raw string) (model.EcosystemFilter, error) {
	catalog := buildEcosystemSelectorCatalog()
	defaults := append([]string(nil), catalog.available...)
	includeNames, excludeNames, err := resolveSelectorExpression(raw, defaults, catalog, true)
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

func buildAuditorSelectorCatalog(reg *scan.Registry) selectorCatalog {
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
	return selectorCatalog{kind: "auditor", available: available, aliasToName: aliasToName, simplifiedItems: simplified}
}

func buildMatcherSelectorCatalog(reg *scan.Registry) selectorCatalog {
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
	return selectorCatalog{kind: "matcher", available: available, aliasToName: aliasToName, simplifiedItems: simplified}
}

func detectorShortAlias(name string) string {
	trimmed := strings.TrimSpace(strings.ToLower(name))
	if strings.HasSuffix(trimmed, "-detector") {
		return strings.TrimSuffix(trimmed, "-detector")
	}
	return ""
}

func resolveSelectorExpression(raw string, defaults []string, catalog selectorCatalog, implicitAllWhenEmpty bool) ([]string, []string, error) {
	selectors := parseCSV(raw)
	if len(selectors) == 0 {
		if implicitAllWhenEmpty {
			return nil, nil, nil
		}
		exclude := differenceSorted(catalog.available, defaults)
		if len(exclude) == 0 {
			return nil, nil, nil
		}
		return nil, exclude, nil
	}

	hasOps := false
	for _, selector := range selectors {
		if strings.HasPrefix(selector, "+") || strings.HasPrefix(selector, "-") {
			hasOps = true
			break
		}
	}

	selected := make(map[string]struct{})
	if hasOps {
		for _, name := range defaults {
			selected[name] = struct{}{}
		}
	}

	unknown := make([]string, 0)
	for _, selector := range selectors {
		op := byte(0)
		token := selector
		if strings.HasPrefix(token, "+") || strings.HasPrefix(token, "-") {
			op = token[0]
			token = strings.TrimSpace(token[1:])
		}
		if token == "" {
			unknown = append(unknown, selector)
			continue
		}
		resolved, ok := catalog.aliasToName[token]
		if !ok {
			unknown = append(unknown, token)
			continue
		}
		if hasOps {
			switch op {
			case '-':
				delete(selected, resolved)
			default:
				selected[resolved] = struct{}{}
			}
			continue
		}
		selected[resolved] = struct{}{}
	}

	if len(unknown) > 0 {
		sort.Strings(unknown)
		return nil, nil, invalidInputf(
			"unknown %s selector(s): %s\navailable %ss: %s\nrun `bomly scan --help` for full selector details",
			catalog.kind,
			strings.Join(unknown, ", "),
			catalog.kind,
			strings.Join(catalog.simplifiedItems, ", "),
		)
	}

	if len(selected) == 0 {
		exclude := append([]string(nil), catalog.available...)
		sort.Strings(exclude)
		return nil, exclude, nil
	}

	if hasOps {
		selectedNames := make([]string, 0, len(selected))
		for name := range selected {
			selectedNames = append(selectedNames, name)
		}
		exclude := differenceSorted(catalog.available, selectedNames)
		if len(exclude) == 0 {
			return nil, nil, nil
		}
		return nil, exclude, nil
	}

	include := make([]string, 0, len(selected))
	for name := range selected {
		include = append(include, name)
	}
	sort.Strings(include)
	return include, nil, nil
}

func differenceSorted(all []string, keep []string) []string {
	kept := make(map[string]struct{}, len(keep))
	for _, name := range keep {
		kept[name] = struct{}{}
	}
	out := make([]string, 0, len(all))
	for _, name := range all {
		if _, ok := kept[name]; ok {
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func resolveDetectorFilter(raw string, reg *scan.Registry) (model.DetectorFilter, error) {
	catalog := buildDetectorSelectorCatalog(reg)
	defaultSet := defaultEnabledDetectorNames(reg)
	include, exclude, err := resolveSelectorExpression(raw, defaultSet, catalog, true)
	if err != nil {
		return model.DetectorFilter{}, err
	}
	return model.DetectorFilter{Include: include, Exclude: exclude}, nil
}

func resolveAuditorFilter(raw string, reg *scan.Registry) (model.AuditorFilter, error) {
	if strings.TrimSpace(raw) == "" {
		return model.AuditorFilter{}, nil
	}
	catalog := buildAuditorSelectorCatalog(reg)
	defaultSet := defaultEnabledAuditorNames(reg)
	include, exclude, err := resolveSelectorExpression(raw, defaultSet, catalog, false)
	if err != nil {
		return model.AuditorFilter{}, err
	}
	return model.AuditorFilter{Include: include, Exclude: exclude}, nil
}

func resolveMatcherFilter(raw string, reg *scan.Registry) (model.MatcherFilter, error) {
	if strings.TrimSpace(raw) == "" {
		return model.MatcherFilter{}, nil
	}
	catalog := buildMatcherSelectorCatalog(reg)
	defaultSet := defaultEnabledMatcherNames(reg)
	include, exclude, err := resolveSelectorExpression(raw, defaultSet, catalog, false)
	if err != nil {
		return model.MatcherFilter{}, err
	}
	return model.MatcherFilter{Include: include, Exclude: exclude}, nil
}

func filterAllowsName(include, exclude []string, name string) bool {
	if len(include) > 0 && !containsStringValue(include, name) {
		return false
	}
	if containsStringValue(exclude, name) {
		return false
	}
	return true
}

func selectedDetectorNames(filter model.DetectorFilter, reg *scan.Registry) []string {
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

func defaultEnabledDetectorNames(reg *scan.Registry) []string {
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

func defaultEnabledAuditorNames(reg *scan.Registry) []string {
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

func defaultEnabledMatcherNames(reg *scan.Registry) []string {
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
