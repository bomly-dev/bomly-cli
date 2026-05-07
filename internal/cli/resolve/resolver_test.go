package resolve

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/cli/opts"
	"github.com/bomly-dev/bomly-cli/internal/selector"
	model "github.com/bomly-dev/bomly-cli/sdk"
)

func TestDefaultAuditorFilterDefaultsToPolicyAuditor(t *testing.T) {
	filter := defaultAuditorFilter("")

	if len(filter.Include) != 0 || len(filter.Exclude) != 0 {
		t.Fatalf("expected default auditor filter to allow default policy auditors without overrides: %#v", filter)
	}
}

func TestDefaultAuditorFilterEnablesPolicyAuditorWhenRequested(t *testing.T) {
	filter := defaultAuditorFilter("severity-policy")

	if !selector.Contains(filter.Include, opts.SeverityPolicyAuditorName) {
		t.Fatalf("expected severity-policy to be explicitly included: %#v", filter)
	}
}

func TestDefaultMatcherFilterDisablesClearlyDefinedByDefault(t *testing.T) {
	filter := defaultMatcherFilter("")

	if len(filter.Include) != 0 || len(filter.Exclude) != 0 {
		t.Fatalf("expected default matcher filter to defer to descriptor defaults: %#v", filter)
	}
}

func TestDefaultMatcherFilterEnablesClearlyDefinedAlias(t *testing.T) {
	filter := defaultMatcherFilter("clearlydefined")

	if selector.Contains(filter.Exclude, opts.ClearlyDefinedCheckerName) {
		t.Fatalf("expected ClearlyDefined not to be excluded when explicitly requested: %#v", filter)
	}
}

func TestDefaultMatcherFilterEnablesEOLWhenRequested(t *testing.T) {
	filter := defaultMatcherFilter("eol")

	if !selector.Contains(filter.Include, opts.EOLCheckerName) {
		t.Fatalf("expected EOL matcher to be explicitly included: %#v", filter)
	}
	if selector.Contains(filter.Exclude, opts.EOLCheckerName) {
		t.Fatalf("expected EOL matcher not to be excluded when explicitly requested: %#v", filter)
	}
}

func TestDefaultAuditorFilterFromFilterPreservesCallerSelection(t *testing.T) {
	filter := defaultAuditorFilterFromFilter(model.AuditorFilter{
		Include: []string{opts.SeverityPolicyAuditorName},
		Exclude: []string{},
	})

	if !selector.Contains(filter.Include, opts.SeverityPolicyAuditorName) {
		t.Fatalf("expected policy auditor selection to be preserved: %#v", filter)
	}
}
