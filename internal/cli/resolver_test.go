package cli

import (
	"testing"

	"github.com/bomly/bomly-cli/internal/scan"
)

func TestDefaultAuditorFilterDefaultsToPolicyAuditor(t *testing.T) {
	filter := defaultAuditorFilter("")

	if len(filter.Include) != 0 || len(filter.Exclude) != 0 {
		t.Fatalf("expected default auditor filter to allow default policy auditors without overrides: %#v", filter)
	}
}

func TestDefaultAuditorFilterEnablesPolicyAuditorWhenRequested(t *testing.T) {
	filter := defaultAuditorFilter("severity-policy")

	if !containsStringValue(filter.Include, severityPolicyAuditorName) {
		t.Fatalf("expected severity-policy to be explicitly included: %#v", filter)
	}
}

func TestDefaultMatcherFilterDisablesClearlyDefinedByDefault(t *testing.T) {
	filter := defaultMatcherFilter("")

	if !containsStringValue(filter.Exclude, clearlyDefinedCheckerName) {
		t.Fatalf("expected ClearlyDefined to be excluded by default: %#v", filter)
	}
	if !containsStringValue(filter.Exclude, eolCheckerName) {
		t.Fatalf("expected EOL matcher to be excluded by default: %#v", filter)
	}
}

func TestDefaultMatcherFilterEnablesClearlyDefinedAlias(t *testing.T) {
	filter := defaultMatcherFilter("clearlydefined")

	if containsStringValue(filter.Exclude, clearlyDefinedCheckerName) {
		t.Fatalf("expected ClearlyDefined not to be excluded when explicitly requested: %#v", filter)
	}
}

func TestDefaultMatcherFilterEnablesEOLWhenRequested(t *testing.T) {
	filter := defaultMatcherFilter("eol")

	if !containsStringValue(filter.Include, eolCheckerName) {
		t.Fatalf("expected EOL matcher to be explicitly included: %#v", filter)
	}
	if containsStringValue(filter.Exclude, eolCheckerName) {
		t.Fatalf("expected EOL matcher not to be excluded when explicitly requested: %#v", filter)
	}
}

func TestDefaultAuditorFilterFromFilterPreservesCallerSelection(t *testing.T) {
	filter := defaultAuditorFilterFromFilter(scan.AuditorFilter{
		Include: []string{severityPolicyAuditorName},
		Exclude: []string{},
	})

	if !containsStringValue(filter.Include, severityPolicyAuditorName) {
		t.Fatalf("expected policy auditor selection to be preserved: %#v", filter)
	}
}
