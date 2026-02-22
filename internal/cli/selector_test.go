package cli

import (
	"strings"
	"testing"

	"github.com/bomly/bomly-cli/internal/registry"
	"go.uber.org/zap"
)

func TestResolveDetectorFilter_AliasAndExplicitSet(t *testing.T) {
	reg := registry.BuildScanRegistry(zap.NewNop(), registry.Config{})
	filter, err := resolveDetectorFilter("npm", reg)
	if err != nil {
		t.Fatalf("resolveDetectorFilter() error = %v", err)
	}
	if len(filter.Include) != 1 || filter.Include[0] != "npm-detector" {
		t.Fatalf("expected npm-detector include, got %#v", filter)
	}
}

func TestResolveDetectorFilter_DefaultMinusToken(t *testing.T) {
	reg := registry.BuildScanRegistry(zap.NewNop(), registry.Config{})
	filter, err := resolveDetectorFilter("-npm", reg)
	if err != nil {
		t.Fatalf("resolveDetectorFilter() error = %v", err)
	}
	if len(filter.Exclude) == 0 || !containsStringValue(filter.Exclude, "npm-detector") {
		t.Fatalf("expected npm-detector in exclusion list, got %#v", filter)
	}
}

func TestResolveDetectorFilter_UnknownShowsHelpHint(t *testing.T) {
	reg := registry.BuildScanRegistry(zap.NewNop(), registry.Config{})
	_, err := resolveDetectorFilter("not-a-detector", reg)
	if err == nil {
		t.Fatal("expected error")
	}
	message := err.Error()
	if !strings.Contains(message, "unknown detector selector") {
		t.Fatalf("expected unknown selector message, got %q", message)
	}
	if !strings.Contains(message, "run `bomly scan --help`") {
		t.Fatalf("expected help hint in message, got %q", message)
	}
}

func TestResolveAuditorFilter_DefaultLeavesAuditorSelectionToRegistryDefaults(t *testing.T) {
	reg := registry.BuildScanRegistry(zap.NewNop(), registry.Config{})
	filter, err := resolveAuditorFilter("", reg)
	if err != nil {
		t.Fatalf("resolveAuditorFilter() error = %v", err)
	}
	if len(filter.Include) != 0 || len(filter.Exclude) != 0 {
		t.Fatalf("expected empty filter for registry-driven auditor defaults, got %#v", filter)
	}
}

func TestResolveMatcherFilter_PlusSyntaxAddsClearlyDefined(t *testing.T) {
	reg := registry.BuildScanRegistry(zap.NewNop(), registry.Config{})
	filter, err := resolveMatcherFilter("+clearlydefined", reg)
	if err != nil {
		t.Fatalf("resolveMatcherFilter() error = %v", err)
	}
	if containsStringValue(filter.Exclude, clearlyDefinedCheckerName) {
		t.Fatalf("expected clearlydefined matcher not to be excluded, got %#v", filter)
	}
}

func TestResolveEcosystemFilter_PlainList(t *testing.T) {
	include, exclude, err := resolveEcosystemFilter("npm,python")
	if err != nil {
		t.Fatalf("resolveEcosystemFilter() error = %v", err)
	}
	if len(include) != 2 {
		t.Fatalf("expected 2 included ecosystems, got %v", include)
	}
	if _, ok := include["npm"]; !ok {
		t.Fatalf("expected npm in include, got %v", include)
	}
	if _, ok := include["python"]; !ok {
		t.Fatalf("expected python in include, got %v", include)
	}
	if len(exclude) != 0 {
		t.Fatalf("expected empty exclude, got %v", exclude)
	}
}

func TestResolveEcosystemFilter_MinusSyntax(t *testing.T) {
	include, exclude, err := resolveEcosystemFilter("-npm")
	if err != nil {
		t.Fatalf("resolveEcosystemFilter() error = %v", err)
	}
	if len(include) != 0 {
		t.Fatalf("expected empty include for ops-mode, got %v", include)
	}
	if _, ok := exclude["npm"]; !ok {
		t.Fatalf("expected npm in exclude, got %v", exclude)
	}
}

func TestResolveEcosystemFilter_GradleAlias(t *testing.T) {
	// "gradle" is an alias for the "maven" ecosystem in the registry.
	include, _, err := resolveEcosystemFilter("gradle")
	if err != nil {
		t.Fatalf("resolveEcosystemFilter() error = %v", err)
	}
	if len(include) != 1 {
		t.Fatalf("expected 1 included ecosystem, got %v", include)
	}
	if _, ok := include["maven"]; !ok {
		t.Fatalf("expected gradle alias to resolve to maven, got %v", include)
	}
}

func TestResolveEcosystemFilter_EmptyMeansAll(t *testing.T) {
	include, exclude, err := resolveEcosystemFilter("")
	if err != nil {
		t.Fatalf("resolveEcosystemFilter() error = %v", err)
	}
	if len(include) != 0 {
		t.Fatalf("expected nil include for empty (all ecosystems), got %v", include)
	}
	if len(exclude) != 0 {
		t.Fatalf("expected nil exclude for empty, got %v", exclude)
	}
}

func TestResolveEcosystemFilter_UnknownReturnsError(t *testing.T) {
	_, _, err := resolveEcosystemFilter("not-an-ecosystem")
	if err == nil {
		t.Fatal("expected error for unknown ecosystem")
	}
	if !strings.Contains(err.Error(), "unknown ecosystem selector") {
		t.Fatalf("expected unknown ecosystem selector message, got %q", err.Error())
	}
}
