package cli

import (
	"testing"

	"github.com/bomly/bomly-cli/internal/scan"
)

func TestDefaultAuditorFilterDisablesOSVByDefault(t *testing.T) {
	filter := defaultAuditorFilter("", "")

	if containsStringValue(filter.Include, osvAuditorName) {
		t.Fatalf("expected osv to remain out of the include list by default: %#v", filter)
	}
	if !containsStringValue(filter.Exclude, osvAuditorName) {
		t.Fatalf("expected osv to be excluded by default: %#v", filter)
	}
}

func TestDefaultAuditorFilterEnablesOSVWhenRequested(t *testing.T) {
	filter := defaultAuditorFilter("osv", "")

	if !containsStringValue(filter.Include, osvAuditorName) {
		t.Fatalf("expected osv to be explicitly included: %#v", filter)
	}
	if containsStringValue(filter.Exclude, osvAuditorName) {
		t.Fatalf("expected osv not to be excluded when requested: %#v", filter)
	}
}

func TestDefaultMatcherFilterDisablesClearlyDefinedByDefault(t *testing.T) {
	filter := defaultMatcherFilter("", "")

	if !containsStringValue(filter.Exclude, clearlyDefinedCheckerName) {
		t.Fatalf("expected ClearlyDefined to be excluded by default: %#v", filter)
	}
}

func TestDefaultMatcherFilterEnablesClearlyDefinedAlias(t *testing.T) {
	filter := defaultMatcherFilter("clearlydefined", "")

	if containsStringValue(filter.Exclude, clearlyDefinedCheckerName) {
		t.Fatalf("expected ClearlyDefined not to be excluded when explicitly requested: %#v", filter)
	}
}

func TestDefaultAuditorFilterFromFilterAppliesDefaultOSVExclusion(t *testing.T) {
	filter := defaultAuditorFilterFromFilter(scan.AuditorFilter{
		Include: []string{"grype"},
		Exclude: []string{},
	})

	if !containsStringValue(filter.Exclude, osvAuditorName) {
		t.Fatalf("expected osv exclusion to be applied to caller-provided filters: %#v", filter)
	}
}
