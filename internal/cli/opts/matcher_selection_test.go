package opts

import (
	"context"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/engine"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	sdkplugin "github.com/bomly-dev/bomly-sdk/plugin"
)

type selectionMatcher struct{ name string }

func (m selectionMatcher) Descriptor() sdkplugin.MatcherDescriptor {
	return sdkplugin.MatcherDescriptor{Name: m.name}
}
func (selectionMatcher) Ready(context.Context, sdkplugin.MatchRequest) error { return nil }
func (selectionMatcher) Applicable(context.Context, sdkplugin.MatchRequest) (bool, error) {
	return true, nil
}
func (selectionMatcher) Match(context.Context, sdkplugin.MatchRequest) (sdkplugin.MatchResult, error) {
	return sdkplugin.MatchResult{}, nil
}

func TestLogMatcherSelectionNamesSelectedAndLeftOutMatchers(t *testing.T) {
	all := engine.NewRegistry(engine.RegistryConfigs{}, *zap.NewNop())
	for _, name := range []string{"grype", "osv", "scorecard"} {
		all.RegisterMatcher(selectionMatcher{name: name})
	}
	selected := engine.NewRegistry(engine.RegistryConfigs{}, *zap.NewNop())
	selected.RegisterMatcher(selectionMatcher{name: "osv"})
	selected.RegisterMatcher(selectionMatcher{name: "grype"})

	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	logMatcherSelection(logger, false, all, selected)
	if logs.Len() != 0 {
		t.Fatalf("expected no log without --enrich, got %d entries", logs.Len())
	}

	logMatcherSelection(logger, true, all, selected)
	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("expected one selection log, got %d", len(entries))
	}
	fields := entries[0].ContextMap()
	if got, want := fields["selected"], []any{"grype", "osv"}; !equalStrings(got, want) {
		t.Errorf("selected = %v, want %v", got, want)
	}
	if got, want := fields["not_selected"], []any{"scorecard"}; !equalStrings(got, want) {
		t.Errorf("not_selected = %v, want %v", got, want)
	}
}

func equalStrings(got any, want []any) bool {
	values, ok := got.([]any)
	if !ok || len(values) != len(want) {
		return false
	}
	for i := range values {
		if values[i] != want[i] {
			return false
		}
	}
	return true
}
