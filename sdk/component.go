package sdk

import "strings"

// ComponentDescriptor describes the common identity and selection fields shared
// by detectors, matchers, auditors, and analyzers.
type ComponentDescriptor struct {
	Name                string           `json:"name"`
	DisplayName         string           `json:"displayName,omitempty"`
	Aliases             []string         `json:"aliases,omitempty"`
	Tags                []string         `json:"tags,omitempty"`
	SupportedEcosystems []Ecosystem      `json:"supportedEcosystems,omitempty"`
	SupportedManagers   []PackageManager `json:"supportedManagers,omitempty"`
}

// Label returns the user-facing component label, falling back to Name.
func (d ComponentDescriptor) Label() string {
	if value := strings.TrimSpace(d.DisplayName); value != "" {
		return value
	}
	return strings.TrimSpace(d.Name)
}

func componentLabel(name, displayName string) string {
	if value := strings.TrimSpace(displayName); value != "" {
		return value
	}
	return strings.TrimSpace(name)
}

// Label returns the user-facing detector label, falling back to Name.
func (d DetectorDescriptor) Label() string { return componentLabel(d.Name, d.DisplayName) }

// Label returns the user-facing matcher label, falling back to Name.
func (d MatcherDescriptor) Label() string { return componentLabel(d.Name, d.DisplayName) }

// Label returns the user-facing auditor label, falling back to Name.
func (d AuditorDescriptor) Label() string { return componentLabel(d.Name, d.DisplayName) }

// Label returns the user-facing analyzer label, falling back to Name.
func (d AnalyzerDescriptor) Label() string { return componentLabel(d.Name, d.DisplayName) }
