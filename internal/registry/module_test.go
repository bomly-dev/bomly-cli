package registry

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/composition"
	"github.com/bomly-dev/bomly-cli/internal/config"
	"go.uber.org/zap"

	"github.com/bomly-dev/bomly-sdk/plugin"
)

type moduleTestMatcher struct {
	name     string
	host     plugin.HostContext
	decoded  map[string]any
	hostInfo plugin.RuntimeInfo
}

func (m *moduleTestMatcher) Descriptor() plugin.MatcherDescriptor {
	return plugin.MatcherDescriptor{Name: m.name}
}

func (m *moduleTestMatcher) Ready(context.Context, plugin.MatchRequest) error { return nil }

func (m *moduleTestMatcher) Applicable(context.Context, plugin.MatchRequest) (bool, error) {
	return true, nil
}

func (m *moduleTestMatcher) Match(context.Context, plugin.MatchRequest) (plugin.MatchResult, error) {
	return plugin.MatchResult{}, nil
}

func TestRegisterModuleMatcher(t *testing.T) {
	configs := Configs{
		CoreVersion: "1.2.3",
		PluginConfigs: config.PluginConfigs{
			Matchers: map[string]map[string]any{
				"module-matcher": {"endpoint": "https://example.test"},
			},
		},
	}
	registry := NewRegistry(configs, *zap.NewNop())

	constructed := &moduleTestMatcher{name: "module-matcher"}
	module := plugin.Module{Kind: plugin.PluginKindMatcher, Matcher: &plugin.MatcherModule{
		Descriptor: plugin.MatcherDescriptor{Name: "module-matcher"},
		New: func(_ context.Context, host plugin.HostContext) (plugin.Matcher, error) {
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

	if err := registry.RegisterModule(module, ComponentOptions{DefaultEnabled: false, Origin: plugin.CoreOrigin}); err != nil {
		t.Fatalf("RegisterModule() error = %v", err)
	}
	if constructed.hostInfo.Execution != plugin.ExecutionEmbedded {
		t.Fatalf("expected embedded execution mode, got %q", constructed.hostInfo.Execution)
	}
	if constructed.hostInfo.CoreVersion != "1.2.3" {
		t.Fatalf("expected host runtime core version %q, got %q", "1.2.3", constructed.hostInfo.CoreVersion)
	}
	if constructed.decoded["endpoint"] != "https://example.test" {
		t.Fatalf("expected kind-scoped config block to decode, got %#v", constructed.decoded)
	}
	if got := registry.ComponentOrigin(plugin.PluginKindMatcher, "module-matcher"); got != plugin.CoreOrigin {
		t.Fatalf("expected core origin, got %q", got)
	}
	if registry.isDefaultEnabled(plugin.PluginKindMatcher, "module-matcher") {
		t.Fatal("expected module-matcher to be registered default-disabled")
	}
	if len(registry.AllMatchers()) != 1 {
		t.Fatalf("expected exactly one matcher, got %d", len(registry.AllMatchers()))
	}
}

func TestRegisterModuleConstructionErrorPropagates(t *testing.T) {
	registry := NewRegistry(Configs{}, *zap.NewNop())
	module := plugin.Module{Kind: plugin.PluginKindMatcher, Matcher: &plugin.MatcherModule{
		Descriptor: plugin.MatcherDescriptor{Name: "broken"},
		New: func(context.Context, plugin.HostContext) (plugin.Matcher, error) {
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
	if err := registry.RegisterModule(plugin.Module{Kind: plugin.PluginKindMatcher}, ComponentOptions{}); err == nil {
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
		if entry.Kind != plugin.PluginKindAnalyzer {
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

// lifecycleModule is a matcher module whose constructor records its context
// and registers cleanups that append to a shared trace, and optionally fails
// after registering them.
func lifecycleModule(name string, trace *[]string, constructed *context.Context, failAfterRegister bool) plugin.Module {
	return plugin.Module{Kind: plugin.PluginKindMatcher, Matcher: &plugin.MatcherModule{
		Descriptor: plugin.MatcherDescriptor{Name: name},
		New: func(ctx context.Context, host plugin.HostContext) (plugin.Matcher, error) {
			if constructed != nil {
				*constructed = ctx
			}
			host.OnCleanup(func() error { *trace = append(*trace, name+":first"); return nil })
			host.OnCleanup(func() error { *trace = append(*trace, name+":second"); return nil })
			if failAfterRegister {
				return nil, errors.New("config invalid")
			}
			return &moduleTestMatcher{name: name}, nil
		},
	}}
}

// TestRegistryComponentLifetimeIsTheCommands holds the embedded half of
// cli#415: a constructor's context is the command's, cleanups run newest
// first and at most once when the registry closes -- including those a
// failed constructor registered before failing -- and a cleanup error names
// its component without stopping the rest.
func TestRegistryComponentLifetimeIsTheCommands(t *testing.T) {
	command, cancel := context.WithCancel(context.Background())
	registry := NewRegistry(Configs{}, *zap.NewNop())
	registry.lifetime = command

	var trace []string
	var constructed context.Context
	if err := registry.RegisterModule(lifecycleModule("alpha", &trace, &constructed, false), ComponentOptions{}); err != nil {
		t.Fatalf("RegisterModule(alpha): %v", err)
	}
	if err := registry.RegisterModule(lifecycleModule("broken", &trace, nil, true), ComponentOptions{}); err == nil {
		t.Fatal("RegisterModule(broken) succeeded")
	}
	failing := plugin.Module{Kind: plugin.PluginKindMatcher, Matcher: &plugin.MatcherModule{
		Descriptor: plugin.MatcherDescriptor{Name: "leaky"},
		New: func(_ context.Context, host plugin.HostContext) (plugin.Matcher, error) {
			host.OnCleanup(func() error { return errors.New("socket already closed") })
			return &moduleTestMatcher{name: "leaky"}, nil
		},
	}}
	if err := registry.RegisterModule(failing, ComponentOptions{}); err != nil {
		t.Fatalf("RegisterModule(leaky): %v", err)
	}

	if constructed.Err() != nil {
		t.Fatal("the constructor's context is already done")
	}
	cancel()
	if constructed.Err() == nil {
		t.Error("cancelling the command did not reach the constructor's context")
	}
	if len(trace) != 0 {
		t.Fatalf("cancellation ran cleanups; only Close may: %v", trace)
	}

	err := registry.Close()
	if want := []string{"broken:second", "broken:first", "alpha:second", "alpha:first"}; !slices.Equal(trace, want) {
		t.Errorf("cleanup order = %v, want %v", trace, want)
	}
	if err == nil || !strings.Contains(err.Error(), "matcher leaky: cleanup: socket already closed") {
		t.Errorf("Close error = %v, want the leaky component's failure by name", err)
	}
	again := registry.Close()
	if len(trace) != 4 {
		t.Errorf("a second Close ran cleanups again: %v", trace)
	}
	if again == nil || again.Error() != err.Error() {
		t.Errorf("a second Close = %v, want the first Close's %v", again, err)
	}
}
