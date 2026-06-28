package opts

import (
	"context"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/engine"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

func TestResolveDetectorFilter_AliasAndExplicitSet(t *testing.T) {
	reg := engine.NewRegistry(engine.RegistryConfigs{}, *zap.NewNop())
	reg.RegisterDetector(fakeDetector{descriptor: sdk.DetectorDescriptor{
		Name:    "example-detector",
		Aliases: []string{"example"},
	}})
	filter, err := resolveDetectorFilter("example", reg)
	if err != nil {
		t.Fatalf("resolveDetectorFilter() error = %v", err)
	}
	if len(filter.Include) != 1 || filter.Include[0] != "example-detector" {
		t.Fatalf("expected example-detector include, got %#v", filter)
	}
}

func TestResolveDetectorFilter_DefaultMinusToken(t *testing.T) {
	reg := engine.NewRegistry(engine.RegistryConfigs{}, *zap.NewNop())
	reg.RegisterDetector(fakeDetector{descriptor: sdk.DetectorDescriptor{
		Name:    "example-detector",
		Aliases: []string{"example"},
	}})
	filter, err := resolveDetectorFilter("-example", reg)
	if err != nil {
		t.Fatalf("resolveDetectorFilter() error = %v", err)
	}
	if len(filter.Exclude) == 0 || !contains(filter.Exclude, "example-detector") {
		t.Fatalf("expected example-detector in exclusion list, got %#v", filter)
	}
}

func TestResolveDetectorFilter_UnknownShowsHelpHint(t *testing.T) {
	reg := engine.NewRegistry(engine.RegistryConfigs{}, *zap.NewNop())
	reg.Build()
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
	reg := engine.NewRegistry(engine.RegistryConfigs{}, *zap.NewNop())
	reg.Build()
	filter, err := ResolveAuditorFilter("", reg)
	if err != nil {
		t.Fatalf("resolveAuditorFilter() error = %v", err)
	}
	if len(filter.Include) != 0 || len(filter.Exclude) != 0 {
		t.Fatalf("expected empty filter for registry-driven auditor defaults, got %#v", filter)
	}
}

func TestResolveMatcherFilter_DefaultLeavesMatcherSelectionToRegistryDefaults(t *testing.T) {
	reg := engine.NewRegistry(engine.RegistryConfigs{}, *zap.NewNop())
	reg.Build()
	filter, err := resolveMatcherFilter("", reg)
	if err != nil {
		t.Fatalf("resolveMatcherFilter() error = %v", err)
	}
	if len(filter.Include) != 0 || len(filter.Exclude) != 0 {
		t.Fatalf("expected empty filter for registry-driven matcher defaults, got %#v", filter)
	}
}

func TestResolveMatcherFilter_UsesDescriptorAliases(t *testing.T) {
	reg := engine.NewRegistry(engine.RegistryConfigs{}, *zap.NewNop())
	reg.RegisterMatcher(fakeMatcher{descriptor: sdk.MatcherDescriptor{
		Name:    "example-license-matcher",
		Aliases: []string{"example-license"},
	}})
	filter, err := resolveMatcherFilter("+example-license", reg)
	if err != nil {
		t.Fatalf("resolveMatcherFilter() error = %v", err)
	}
	if contains(filter.Exclude, "example-license-matcher") {
		t.Fatalf("expected aliased matcher not to be excluded, got %#v", filter)
	}
}

func TestResolveAuditorFilter_UsesDescriptorAliases(t *testing.T) {
	reg := engine.NewRegistry(engine.RegistryConfigs{}, *zap.NewNop())
	reg.RegisterAuditor(fakeAuditor{descriptor: sdk.AuditorDescriptor{
		Name:    "example-auditor",
		Aliases: []string{"example-audit"},
	}})
	filter, err := ResolveAuditorFilter("+example-audit", reg)
	if err != nil {
		t.Fatalf("ResolveAuditorFilter() error = %v", err)
	}
	if contains(filter.Exclude, "example-auditor") {
		t.Fatalf("expected aliased auditor not to be excluded, got %#v", filter)
	}
}

func TestResolveAnalyzerFilter_UsesDescriptorAliases(t *testing.T) {
	reg := engine.NewRegistry(engine.RegistryConfigs{}, *zap.NewNop())
	reg.RegisterAnalyzer(fakeAnalyzer{descriptor: sdk.AnalyzerDescriptor{
		Name:    "example-analyzer",
		Aliases: []string{"example-reach"},
	}})
	filter, err := ResolveAnalyzerFilter("+example-reach", reg)
	if err != nil {
		t.Fatalf("ResolveAnalyzerFilter() error = %v", err)
	}
	if contains(filter.Exclude, "example-analyzer") {
		t.Fatalf("expected aliased analyzer not to be excluded, got %#v", filter)
	}
}

func TestResolveEcosystemFilter_PlainList(t *testing.T) {
	filter, err := resolveEcosystemFilter("npm,python")
	if err != nil {
		t.Fatalf("resolveEcosystemFilter() error = %v", err)
	}
	if len(filter.Include) != 2 {
		t.Fatalf("expected 2 included ecosystems, got %v", filter.Include)
	}
	if !containsEcosystem(filter.Include, sdk.EcosystemNPM) {
		t.Fatalf("expected npm in include, got %v", filter.Include)
	}
	if !containsEcosystem(filter.Include, sdk.EcosystemPython) {
		t.Fatalf("expected python in include, got %v", filter.Include)
	}
	if len(filter.Exclude) != 0 {
		t.Fatalf("expected empty exclude, got %v", filter.Exclude)
	}
}

func TestResolveEcosystemFilter_MinusSyntax(t *testing.T) {
	filter, err := resolveEcosystemFilter("-npm")
	if err != nil {
		t.Fatalf("resolveEcosystemFilter() error = %v", err)
	}
	if len(filter.Include) != 0 {
		t.Fatalf("expected empty include for ops-mode, got %v", filter.Include)
	}
	if !containsEcosystem(filter.Exclude, sdk.EcosystemNPM) {
		t.Fatalf("expected npm in exclude, got %v", filter.Exclude)
	}
}

func TestResolveEcosystemFilter_GradleAlias(t *testing.T) {
	// "gradle" is an alias for the "maven" ecosystem in the registry.
	filter, err := resolveEcosystemFilter("gradle")
	if err != nil {
		t.Fatalf("resolveEcosystemFilter() error = %v", err)
	}
	if len(filter.Include) != 1 {
		t.Fatalf("expected 1 included ecosystem, got %v", filter.Include)
	}
	if !containsEcosystem(filter.Include, sdk.EcosystemMaven) {
		t.Fatalf("expected gradle alias to resolve to maven, got %v", filter.Include)
	}
}

func TestResolveEcosystemFilter_EmptyMeansAll(t *testing.T) {
	filter, err := resolveEcosystemFilter("")
	if err != nil {
		t.Fatalf("resolveEcosystemFilter() error = %v", err)
	}
	if len(filter.Include) != 0 {
		t.Fatalf("expected nil include for empty (all ecosystems), got %v", filter.Include)
	}
	if len(filter.Exclude) != 0 {
		t.Fatalf("expected nil exclude for empty, got %v", filter.Exclude)
	}
}

func TestResolveEcosystemFilter_UnknownReturnsError(t *testing.T) {
	_, err := resolveEcosystemFilter("not-an-ecosystem")
	if err == nil {
		t.Fatal("expected error for unknown ecosystem")
	}
	if !strings.Contains(err.Error(), "unknown ecosystem selector") {
		t.Fatalf("expected unknown ecosystem selector message, got %q", err.Error())
	}
}

func containsEcosystem(values []sdk.Ecosystem, target sdk.Ecosystem) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

type fakeMatcher struct {
	descriptor sdk.MatcherDescriptor
}

func (f fakeMatcher) Descriptor() sdk.MatcherDescriptor {
	return f.descriptor
}

func (f fakeMatcher) Ready(context.Context, sdk.MatchRequest) error {
	return nil
}

func (f fakeMatcher) Applicable(context.Context, sdk.MatchRequest) (bool, error) {
	return true, nil
}

func (f fakeMatcher) Match(_ context.Context, req sdk.MatchRequest) (sdk.MatchResult, error) {
	return sdk.MatchResult{Registry: req.Registry}, nil
}

type fakeDetector struct {
	descriptor sdk.DetectorDescriptor
}

func (f fakeDetector) Descriptor() sdk.DetectorDescriptor {
	return f.descriptor
}

func (f fakeDetector) PackageManagerSupport() []sdk.PackageManagerSupport {
	return nil
}

func (f fakeDetector) Ready(context.Context, sdk.DetectionRequest) error {
	return nil
}

func (f fakeDetector) Applicable(context.Context, sdk.DetectionRequest) (bool, error) {
	return true, nil
}

func (f fakeDetector) ResolveGraph(context.Context, sdk.DetectionRequest) (sdk.DetectionResult, error) {
	return sdk.DetectionResult{}, nil
}

type fakeAuditor struct {
	descriptor sdk.AuditorDescriptor
}

func (f fakeAuditor) Descriptor() sdk.AuditorDescriptor {
	return f.descriptor
}

func (f fakeAuditor) Ready(context.Context, sdk.AuditRequest) error {
	return nil
}

func (f fakeAuditor) Applicable(context.Context, sdk.AuditRequest) (bool, error) {
	return true, nil
}

func (f fakeAuditor) Audit(context.Context, sdk.AuditRequest) (sdk.AuditResult, error) {
	return sdk.AuditResult{}, nil
}

type fakeAnalyzer struct {
	descriptor sdk.AnalyzerDescriptor
}

func (f fakeAnalyzer) Descriptor() sdk.AnalyzerDescriptor {
	return f.descriptor
}

func (f fakeAnalyzer) Ready(context.Context, sdk.AnalyzeRequest) error {
	return nil
}

func (f fakeAnalyzer) Applicable(context.Context, sdk.AnalyzeRequest) (bool, error) {
	return true, nil
}

func (f fakeAnalyzer) Analyze(context.Context, sdk.AnalyzeRequest) (sdk.AnalyzeResult, error) {
	return sdk.AnalyzeResult{}, nil
}
