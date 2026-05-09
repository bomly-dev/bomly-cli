// Package opts resolves +/- selector expressions used by the CLI to filter
// detectors, auditors, matchers, and ecosystems. The resolver is generic: callers
// build a catalog of available items (with optional aliases) and pass a default set
// plus a raw expression — the resolver returns the include and exclude lists.
package opts

import (
	"fmt"
	"sort"
	"strings"
)

// catalog enumerates the available items for one selector domain (detector,
// auditor, matcher, ecosystem) plus any user-facing aliases that resolve to a
// canonical name. Kind is the noun used in error messages ("detector"). Items
// are the user-facing labels shown in error hints — typically with the alias
// in parentheses where one exists.
type catalog struct {
	Kind        string
	Available   []string
	AliasToName map[string]string
	Items       []string
}

// unknownSelectorError is returned when one or more selector tokens do not
// match any available name or alias in the catalog. The Kind, Unknown, and
// Items fields let callers format a domain-specific help message.
type unknownSelectorError struct {
	Kind    string
	Unknown []string
	Items   []string
}

func (e *unknownSelectorError) Error() string {
	return fmt.Sprintf(
		"unknown %s selector(s): %s\navailable %ss: %s",
		e.Kind,
		strings.Join(e.Unknown, ", "),
		e.Kind,
		strings.Join(e.Items, ", "),
	)
}

// resolve parses a comma-separated selector expression against the catalog and
// returns the include and exclude lists.
//
// Behavior:
//   - Empty raw expression with implicitAllWhenEmpty=true → include nil, exclude nil.
//   - Empty raw expression with implicitAllWhenEmpty=false → exclude everything not in defaults.
//   - Tokens with +/- prefix are operators applied against defaults.
//   - Plain tokens (no operator) replace the default set entirely.
//   - Unknown tokens return *unknownSelectorError.
func resolve(raw string, defaults []string, catalog catalog, implicitAllWhenEmpty bool) ([]string, []string, error) {
	selectors := parseCSV(raw)
	if len(selectors) == 0 {
		if implicitAllWhenEmpty {
			return nil, nil, nil
		}
		exclude := differenceSorted(catalog.Available, defaults)
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
		resolved, ok := catalog.AliasToName[token]
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
		return nil, nil, &unknownSelectorError{
			Kind:    catalog.Kind,
			Unknown: unknown,
			Items:   catalog.Items,
		}
	}

	if len(selected) == 0 {
		exclude := append([]string(nil), catalog.Available...)
		sort.Strings(exclude)
		return nil, exclude, nil
	}

	if hasOps {
		selectedNames := make([]string, 0, len(selected))
		for name := range selected {
			selectedNames = append(selectedNames, name)
		}
		exclude := differenceSorted(catalog.Available, selectedNames)
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

// parseCSV splits a comma-separated string into trimmed, non-empty tokens.
func parseCSV(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// appendUnique appends value to values if not already present.
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

// contains reports whether value is in values.
func contains(values []string, value string) bool {
	for _, existing := range values {
		if existing == value {
			return true
		}
	}
	return false
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
