package composition

import (
	"context"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-sdk"
	"go.uber.org/zap"
)

// fakeHost is a minimal sdk.HostContext for construction tests.
type fakeHost struct{}

func (fakeHost) Logger() *zap.Logger { return zap.NewNop() }
func (fakeHost) HTTPClient() *sdk.HTTPClientProvider {
	provider, _ := sdk.NewHTTPClientProvider(sdk.HTTPClientConfig{})
	return provider
}
func (fakeHost) Runtime() sdk.RuntimeInfo { return sdk.RuntimeInfo{Execution: sdk.ExecutionEmbedded} }
func (fakeHost) DecodeConfig(any) error   { return nil }

func TestEntriesShapeAndDefaults(t *testing.T) {
	wantDefaults := map[string]struct {
		kind           sdk.PluginKind
		defaultEnabled bool
	}{
		"grype":                   {sdk.PluginKindMatcher, true},
		"osv":                     {sdk.PluginKindMatcher, false},
		"depsdev-license-matcher": {sdk.PluginKindMatcher, true},
		"scorecard":               {sdk.PluginKindMatcher, false},
		"govulncheck":             {sdk.PluginKindAnalyzer, true},
		"jsreach":                 {sdk.PluginKindAnalyzer, true},
		"pyreach":                 {sdk.PluginKindAnalyzer, true},
		"jvmreach":                {sdk.PluginKindAnalyzer, true},
	}

	entries := Entries()
	if len(entries) != len(wantDefaults) {
		t.Fatalf("expected %d composition entries, got %d", len(wantDefaults), len(entries))
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		want, ok := wantDefaults[entry.Name]
		if !ok {
			t.Errorf("unexpected composition entry %q", entry.Name)
			continue
		}
		if seen[entry.Name] {
			t.Errorf("duplicate composition entry %q", entry.Name)
		}
		seen[entry.Name] = true
		if entry.Kind != want.kind {
			t.Errorf("entry %q: kind %q, want %q", entry.Name, entry.Kind, want.kind)
		}
		if entry.DefaultEnabled != want.defaultEnabled {
			t.Errorf("entry %q: default-enabled %v, want %v", entry.Name, entry.DefaultEnabled, want.defaultEnabled)
		}
		if entry.Implementation != ImplementationNative {
			t.Errorf("entry %q: implementation %q, want native", entry.Name, entry.Implementation)
		}
		if entry.Module == nil {
			t.Errorf("entry %q: nil module builder", entry.Name)
		}
	}
}

func TestEntriesModulesValidateAndConstruct(t *testing.T) {
	deps := Deps{Logger: zap.NewNop()}
	for _, entry := range Entries() {
		module := entry.Module(deps)
		if err := sdk.ValidateModule(module); err != nil {
			t.Errorf("entry %q: module invalid: %v", entry.Name, err)
			continue
		}
		if module.Kind != entry.Kind {
			t.Errorf("entry %q: module kind %q != entry kind %q", entry.Name, module.Kind, entry.Kind)
		}
		switch module.Kind {
		case sdk.PluginKindMatcher:
			if module.Matcher.Descriptor.Name != entry.Name {
				t.Errorf("entry %q: module descriptor name %q", entry.Name, module.Matcher.Descriptor.Name)
			}
			matcher, err := module.Matcher.New(context.Background(), fakeHost{})
			if err != nil {
				t.Errorf("entry %q: construct: %v", entry.Name, err)
				continue
			}
			if got := matcher.Descriptor().Name; got != entry.Name {
				t.Errorf("entry %q: constructed matcher is named %q", entry.Name, got)
			}
		case sdk.PluginKindAnalyzer:
			if module.Analyzer.Descriptor.Name != entry.Name {
				t.Errorf("entry %q: module descriptor name %q", entry.Name, module.Analyzer.Descriptor.Name)
			}
			analyzer, err := module.Analyzer.New(context.Background(), fakeHost{})
			if err != nil {
				t.Errorf("entry %q: construct: %v", entry.Name, err)
				continue
			}
			if got := analyzer.Descriptor().Name; got != entry.Name {
				t.Errorf("entry %q: constructed analyzer is named %q", entry.Name, got)
			}
		}
	}
}

func TestOriginRejectsNativeOutsideEmbeddedExecution(t *testing.T) {
	entry := Entry{Name: "grype", Implementation: ImplementationNative}
	if origin, err := entry.Origin(sdk.ExecutionEmbedded); err != nil || origin != sdk.CoreOrigin {
		t.Fatalf("native+embedded must yield CoreOrigin, got %q / %v", origin, err)
	}
	for _, execution := range []sdk.ExecutionMode{sdk.ExecutionManaged, sdk.ExecutionMode("remote"), ""} {
		if _, err := entry.Origin(execution); err == nil || !strings.Contains(err.Error(), "must run embedded") {
			t.Errorf("native+%q must be rejected, got %v", execution, err)
		}
	}

	plugin := Entry{Name: "acme", Implementation: ImplementationPlugin}
	if origin, err := plugin.Origin(sdk.ExecutionManaged); err != nil || origin != sdk.ExternalOrigin {
		t.Fatalf("plugin entries must yield ExternalOrigin, got %q / %v", origin, err)
	}

	bespoke := Entry{Name: "x", Implementation: "bespoke"}
	if _, err := bespoke.Origin(sdk.ExecutionEmbedded); err == nil {
		t.Fatal("unknown implementation must be rejected")
	}
}
