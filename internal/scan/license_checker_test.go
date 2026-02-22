package scan

import (
	"context"
	"testing"

	"github.com/bomly/bomly-cli/internal/model"
)

type fakeMatcher struct {
	name     string
	priority int
	run      func(*model.Graph)
}

func (f fakeMatcher) Descriptor() MatcherDescriptor {
	return MatcherDescriptor{
		Name:           f.name,
		Priority:       f.priority,
		SupportedModes: []TargetMode{TargetModeFullGraph, TargetModeComponent},
	}
}

func (f fakeMatcher) Match(_ context.Context, req MatchRequest) (MatchResult, error) {
	if f.run != nil {
		f.run(req.Graph)
	}
	return MatchResult{Graph: req.Graph, Target: req.Target}, nil
}

func TestRegistryMatchers_SortsByPriority(t *testing.T) {
	registry := NewRegistry()
	registry.RegisterMatcher(fakeMatcher{name: "fallback", priority: 90})
	registry.RegisterMatcher(fakeMatcher{name: "primary", priority: 100})

	matchers := registry.Matchers(MatchRequest{Mode: TargetModeFullGraph})
	if len(matchers) != 2 {
		t.Fatalf("expected 2 matchers, got %d", len(matchers))
	}
	if got := matchers[0].Descriptor().Name; got != "primary" {
		t.Fatalf("expected primary matcher first, got %q", got)
	}
	if got := matchers[1].Descriptor().Name; got != "fallback" {
		t.Fatalf("expected fallback matcher second, got %q", got)
	}
}

func TestEngineMatch_RunsMultipleMatchersWithoutOverwritingExistingLicenses(t *testing.T) {
	registry := NewRegistry()
	registry.RegisterMatcher(fakeMatcher{
		name:     "first",
		priority: 100,
		run: func(g *model.Graph) {
			pkg, _ := g.Package("react@18.2.0")
			if pkg != nil && len(pkg.Licenses) == 0 {
				pkg.Licenses = []model.PackageLicense{{SPDXExpression: "MIT"}}
			}
		},
	})
	registry.RegisterMatcher(fakeMatcher{
		name:     "second",
		priority: 90,
		run: func(g *model.Graph) {
			pkg, _ := g.Package("react@18.2.0")
			if pkg != nil && len(pkg.Licenses) == 0 {
				pkg.Licenses = []model.PackageLicense{{SPDXExpression: "Apache-2.0"}}
			}
		},
	})
	engine := NewEngine(registry)

	g := model.New()
	pkg := model.NewPackage(model.Package{Ecosystem: "npm", Name: "react", Version: "18.2.0"})
	if err := g.AddPackage(pkg); err != nil {
		t.Fatalf("add package: %v", err)
	}

	result, err := engine.Match(context.Background(), MatchRequest{
		Mode:  TargetModeFullGraph,
		Graph: g,
	})
	if err != nil {
		t.Fatalf("Match() error = %v", err)
	}
	if result.Graph != g {
		t.Fatalf("expected graph to be returned unchanged by pointer")
	}
	values := pkg.LicenseValues()
	if len(values) != 1 || values[0] != "MIT" {
		t.Fatalf("expected first matcher to fill the gap and second to preserve it, got %#v", values)
	}
}
