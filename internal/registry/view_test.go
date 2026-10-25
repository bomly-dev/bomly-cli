package registry

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/bomly-dev/bomly-sdk/plugin"
)

func TestWithoutLeavesOutOnlyTheNamedComponentsOfOneKind(t *testing.T) {
	registry := NewRegistry(Configs{}, *zap.NewNop())
	registry.RegisterMatcher(&moduleTestMatcher{name: "kept"})
	registry.RegisterMatcher(&moduleTestMatcher{name: "held-back"})
	registry.RegisterMatcherWithOptions(&moduleTestMatcher{name: "opt-in"}, ComponentOptions{DefaultEnabled: false})

	view := registry.Without(plugin.PluginKindMatcher, []string{"held-back"})
	var names []string
	for _, matcher := range view.Matchers(plugin.MatchRequest{}) {
		names = append(names, matcher.Descriptor().Name)
	}
	if len(names) != 1 || names[0] != "kept" {
		t.Fatalf("view matchers = %v, want [kept]", names)
	}
	if got := len(registry.Matchers(plugin.MatchRequest{})); got != 2 {
		t.Fatalf("the view must not change the registry it came from, which now selects %d matchers", got)
	}
	if !view.DefaultEnabled(plugin.PluginKindMatcher, "kept") || view.DefaultEnabled(plugin.PluginKindMatcher, "opt-in") {
		t.Fatal("the view must keep the registry's default selection")
	}
	if same := registry.Without(plugin.PluginKindMatcher, nil); same != registry {
		t.Fatal("holding nothing back must return the registry itself")
	}
}

func TestWithoutViewOwnsNoComponentLifetime(t *testing.T) {
	registry := NewRegistry(Configs{}, *zap.NewNop())
	ended := 0
	err := registry.RegisterModule(plugin.Module{Kind: plugin.PluginKindMatcher, Matcher: &plugin.MatcherModule{
		Descriptor: plugin.MatcherDescriptor{Name: "scoped"},
		New: func(_ context.Context, host plugin.HostContext) (plugin.Matcher, error) {
			host.OnCleanup(func() error { ended++; return nil })
			return &moduleTestMatcher{name: "scoped"}, nil
		},
	}}, ComponentOptions{DefaultEnabled: true})
	if err != nil {
		t.Fatalf("RegisterModule: %v", err)
	}
	if err := registry.Without(plugin.PluginKindMatcher, []string{"scoped"}).Close(); err != nil || ended != 0 {
		t.Fatalf("closing a view must end nothing: err=%v ended=%d", err, ended)
	}
	if err := registry.Close(); err != nil || ended != 1 {
		t.Fatalf("the registry still owns the component: err=%v ended=%d", err, ended)
	}
}
