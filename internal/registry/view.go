package registry

import (
	"slices"

	"github.com/bomly-dev/bomly-sdk/plugin"
)

// DefaultEnabled reports whether the registry selects the named component of
// kind when the user's selector does not mention it.
func (r *Registry) DefaultEnabled(kind plugin.PluginKind, name string) bool {
	return r.isDefaultEnabled(kind, name)
}

// SelectedAuditors returns every auditor filter selects, before ecosystem
// and package-manager matching narrows the set for one request. A component
// audit selects by the queried package's ecosystem, which planning cannot
// know in advance, so planning has to see all of them.
func (r *Registry) SelectedAuditors(filter plugin.AuditorFilter) []plugin.Auditor {
	selected := make([]plugin.Auditor, 0, len(r.auditors))
	for _, auditor := range r.auditors {
		if r.auditorSelected(filter, auditor.Descriptor()) {
			selected = append(selected, auditor)
		}
	}
	return selected
}

// Without returns a view of the registry that leaves out the named
// components of one kind and shares every other registration. Runtime
// preflight uses it to hold a component back from a stage without touching
// the selection filters the component itself is sent.
//
// The view owns no component lifetime: closing it ends nothing, because the
// registry it came from still owns every component it constructed.
func (r *Registry) Without(kind plugin.PluginKind, names []string) *Registry {
	if r == nil || len(names) == 0 {
		return r
	}
	view := *r
	view.scopes = nil
	switch kind {
	case plugin.PluginKindDetector:
		view.detectors = withoutNamed(r.detectors, names, func(d plugin.Detector) string { return d.Descriptor().Name })
	case plugin.PluginKindMatcher:
		view.matchers = withoutNamed(r.matchers, names, func(m plugin.Matcher) string { return m.Descriptor().Name })
	case plugin.PluginKindAnalyzer:
		view.analyzers = withoutNamed(r.analyzers, names, func(a plugin.Analyzer) string { return a.Descriptor().Name })
	case plugin.PluginKindAuditor:
		view.auditors = withoutNamed(r.auditors, names, func(a plugin.Auditor) string { return a.Descriptor().Name })
	}
	return &view
}

func withoutNamed[T any](items []T, names []string, name func(T) string) []T {
	kept := make([]T, 0, len(items))
	for _, item := range items {
		if !slices.Contains(names, name(item)) {
			kept = append(kept, item)
		}
	}
	return kept
}
