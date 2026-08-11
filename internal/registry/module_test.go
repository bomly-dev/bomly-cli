package registry

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/composition"
	"github.com/bomly-dev/bomly-cli/internal/config"
	"github.com/bomly-dev/bomly-sdk"
	"go.uber.org/zap"
)

type moduleTestMatcher struct {
	name     string
	host     sdk.HostContext
	decoded  map[string]any
	hostInfo sdk.RuntimeInfo
}

func (m *moduleTestMatcher) Descriptor() sdk.MatcherDescriptor {
	return sdk.MatcherDescriptor{Name: m.name}
}

func (m *moduleTestMatcher) Ready(context.Context, sdk.MatchRequest) error { return nil }

func (m *moduleTestMatcher) Applicable(context.Context, sdk.MatchRequest) (bool, error) {
	return true, nil
}

func (m *moduleTestMatcher) Match(context.Context, sdk.MatchRequest) (sdk.MatchResult, error) {
	return sdk.MatchResult{}, nil
}

func TestRegisterModuleMatcher(t *testing.T) {
	configs := Configs{PluginConfigs: config.PluginConfigs{
		Matchers: map[string]map[string]any{
			"module-matcher": {"endpoint": "https://example.test"},
		},
	}}
	registry := NewRegistry(configs, *zap.NewNop())

	constructed := &moduleTestMatcher{name: "module-matcher"}
	module := sdk.Module{Kind: sdk.PluginKindMatcher, Matcher: &sdk.MatcherModule{
		Descriptor: sdk.MatcherDescriptor{Name: "module-matcher"},
		New: func(_ context.Context, host sdk.HostContext) (sdk.Matcher, error) {
			constructed.host = host
			constructed.hostInfo = host.Runtime()
			var cfg map[string]any
			if err := host.DecodeConfig(&cfg); err != nil {
				return nil, err
			}
			constructed.decoded = cfg
			if host.Logger() == nil {
				return nil, errors.New("nil logger from host context")
			}
			return constructed, nil
		},
	}}

	if err := registry.RegisterModule(module, ComponentOptions{DefaultEnabled: false, Origin: sdk.CoreOrigin}); err != nil {
		t.Fatalf("RegisterModule() error = %v", err)
	}
	if constructed.hostInfo.Execution != sdk.ExecutionEmbedded {
		t.Fatalf("expected embedded execution mode, got %q", constructed.hostInfo.Execution)
	}
	if constructed.decoded["endpoint"] != "https://example.test" {
		t.Fatalf("expected kind-scoped config block to decode, got %#v", constructed.decoded)
	}
	if got := registry.ComponentOrigin(sdk.PluginKindMatcher, "module-matcher"); got != sdk.CoreOrigin {
		t.Fatalf("expected core origin, got %q", got)
	}
	if registry.isDefaultEnabled(sdk.PluginKindMatcher, "module-matcher") {
		t.Fatal("expected module-matcher to be registered default-disabled")
	}
	if len(registry.AllMatchers()) != 1 {
		t.Fatalf("expected exactly one matcher, got %d", len(registry.AllMatchers()))
	}
}

func TestRegisterModuleConstructionErrorPropagates(t *testing.T) {
	registry := NewRegistry(Configs{}, *zap.NewNop())
	module := sdk.Module{Kind: sdk.PluginKindMatcher, Matcher: &sdk.MatcherModule{
		Descriptor: sdk.MatcherDescriptor{Name: "broken"},
		New: func(context.Context, sdk.HostContext) (sdk.Matcher, error) {
			return nil, errors.New("boom")
		},
	}}
	err := registry.RegisterModule(module, ComponentOptions{})
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected construction error, got %v", err)
	}
	if len(registry.AllMatchers()) != 0 {
		t.Fatal("expected no matcher registered after construction failure")
	}
}

func TestRegisterModuleRejectsInvalidModule(t *testing.T) {
	registry := NewRegistry(Configs{}, *zap.NewNop())
	if err := registry.RegisterModule(sdk.Module{Kind: sdk.PluginKindMatcher}, ComponentOptions{}); err == nil {
		t.Fatal("expected invalid module to be rejected")
	}
}

// TestBuildRegistersCompositionEntries asserts the composition-driven wiring
// reproduces the historical registry contents: grype and deps.dev default
// enabled, osv and scorecard registered but default disabled, and all four
// reachability analyzers default enabled.
func TestBuildRegistersCompositionEntries(t *testing.T) {
	registry := NewRegistry(Configs{}, *zap.NewNop())
	registry.Build()

	matcherNames := map[string]bool{}
	for _, descriptor := range registry.MatcherDescriptors() {
		matcherNames[descriptor.Name] = true
	}
	for _, want := range []string{"grype", "osv", "depsdev-license-matcher", "scorecard"} {
		if !matcherNames[want] {
			t.Errorf("expected matcher %q to be registered, got %v", want, matcherNames)
		}
	}
	defaultMatchers := registry.DefaultEnabledMatcherNames()
	for _, name := range defaultMatchers {
		if name == "osv" || name == "scorecard" {
			t.Errorf("expected %q to be default-disabled, defaults: %v", name, defaultMatchers)
		}
	}
	defaultSet := map[string]bool{}
	for _, name := range defaultMatchers {
		defaultSet[name] = true
	}
	if !defaultSet["grype"] || !defaultSet["depsdev-license-matcher"] {
		t.Errorf("expected grype and depsdev-license-matcher default-enabled, got %v", defaultMatchers)
	}

	analyzerNames := registry.DefaultEnabledAnalyzerNames()
	wantAnalyzers := []string{"govulncheck", "jsreach", "jvmreach", "pyreach"}
	if len(analyzerNames) != len(wantAnalyzers) {
		t.Fatalf("expected default analyzers %v, got %v", wantAnalyzers, analyzerNames)
	}
	for idx, want := range wantAnalyzers {
		if analyzerNames[idx] != want {
			t.Fatalf("expected default analyzers %v, got %v", wantAnalyzers, analyzerNames)
		}
	}
}

// TestCompositionAnalyzerEntriesStayInDocsCatalog asserts composition entry
// names remain a subset of the registry's built-in display-name catalog, so
// user-facing listings keep labeling every composed component.
func TestCompositionAnalyzerEntriesStayInDocsCatalog(t *testing.T) {
	for _, entry := range composition.Entries() {
		if entry.Kind != sdk.PluginKindAnalyzer {
			continue
		}
		if _, ok := builtInDisplayNames[entry.Name]; !ok {
			t.Errorf("composition analyzer %q has no display-name catalog entry", entry.Name)
		}
		if _, ok := builtInAnalyzerAliases[entry.Name]; !ok {
			t.Errorf("composition analyzer %q has no alias catalog entry", entry.Name)
		}
	}
}
