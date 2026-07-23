package engine

import (
	"context"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

type fakeMatcher struct {
	name string
	run  func(reg *sdk.PackageRegistry)
}

func (f fakeMatcher) Descriptor() MatcherDescriptor {
	return MatcherDescriptor{
		Name: f.name,
	}
}

func (f fakeMatcher) Match(_ context.Context, req MatchRequest) (sdk.MatchResult, error) {
	if f.run != nil {
		f.run(req.Registry)
	}
	return sdk.MatchResult{Registry: req.Registry}, nil
}

func TestRegistryMatchers_PreservesRegistrationOrder(t *testing.T) {
	registry := newTestRegistry()
	registry.registerMatcher(fakeMatcher{name: "fallback"})
	registry.registerMatcher(fakeMatcher{name: "primary"})

	matchers := registry.Matchers(MatchRequest{})
	if len(matchers) != 2 {
		t.Fatalf("expected 2 matchers, got %d", len(matchers))
	}
	if got := matchers[0].Descriptor().Name; got != "fallback" {
		t.Fatalf("expected first registered matcher first, got %q", got)
	}
	if got := matchers[1].Descriptor().Name; got != "primary" {
		t.Fatalf("expected second registered matcher second, got %q", got)
	}
}

func TestRegistryMatchers_UsesEnabledDefaultsButAllowsExplicitInclude(t *testing.T) {
	registry := newTestRegistry()
	registry.registerMatcher(fakeMatcher{name: "default-on"})
	registry.RegisterMatcherWithOptions(fakeMatcher{name: "default-off"}, ComponentOptions{DefaultEnabled: false})

	matchers := registry.Matchers(MatchRequest{})
	if len(matchers) != 1 || matchers[0].Descriptor().Name != "default-on" {
		t.Fatalf("expected only enabled-by-default matcher, got %#v", matchers)
	}

	matchers = registry.Matchers(MatchRequest{
		MatcherFilter: sdk.MatcherFilter{Include: []string{"default-off"}},
	})
	if len(matchers) != 1 || matchers[0].Descriptor().Name != "default-off" {
		t.Fatalf("expected explicit include to override disabled default, got %#v", matchers)
	}
}

func TestEngineMatch_RunsMultipleMatchersWithoutOverwritingExistingLicenses(t *testing.T) {
	registry := newTestRegistry()
	const purl = "pkg:npm/react@18.2.0"

	registry.registerMatcher(fakeMatcher{
		name: "first",
		run: func(reg *sdk.PackageRegistry) {
			pkg := reg.Ensure(purl)
			if len(pkg.Licenses) == 0 {
				pkg.Licenses = []sdk.PackageLicense{{SPDXExpression: "MIT"}}
			}
		},
	})
	registry.registerMatcher(fakeMatcher{
		name: "second",
		run: func(reg *sdk.PackageRegistry) {
			pkg := reg.Ensure(purl)
			if len(pkg.Licenses) == 0 {
				pkg.Licenses = []sdk.PackageLicense{{SPDXExpression: "Apache-2.0"}}
			}
		},
	})
	engine := NewEngine(registry)

	g := sdk.New()
	reg := sdk.NewPackageRegistry()

	result, err := engine.Match(context.Background(), MatchRequest{
		Graph:    g,
		Registry: reg,
	})
	if err != nil {
		t.Fatalf("Match() error = %v", err)
	}
	if result.Registry == nil {
		t.Fatalf("expected registry to be returned by match result")
	}
	pkg, ok := result.Registry.Get(purl)
	if !ok {
		t.Fatalf("expected react package to be in registry")
	}
	values := pkg.LicenseValues()
	if len(values) != 1 || values[0] != "MIT" {
		t.Fatalf("expected first matcher to fill the gap and second to preserve it, got %#v", values)
	}
}

func TestEngineMatchConsolidatesAliasEquivalentVulnerabilitiesAcrossMatchers(t *testing.T) {
	registry := newTestRegistry()
	const purl = "pkg:golang/golang.org/x/text@v0.3.5"

	registry.registerMatcher(fakeMatcher{
		name: "first",
		run: func(reg *sdk.PackageRegistry) {
			reg.Ensure(purl).Vulnerabilities = append(reg.Ensure(purl).Vulnerabilities, sdk.Vulnerability{
				ID: "GHSA-ppp9-7jff-5vj2", Aliases: []string{"CVE-2021-38561"}, Source: "first",
			})
		},
	})
	registry.registerMatcher(fakeMatcher{
		name: "second",
		run: func(reg *sdk.PackageRegistry) {
			reg.Ensure(purl).Vulnerabilities = append(reg.Ensure(purl).Vulnerabilities, sdk.Vulnerability{
				ID: "GO-2021-0113", Aliases: []string{"CVE-2021-38561", "GHSA-ppp9-7jff-5vj2"}, Source: "second",
			})
		},
	})

	result, err := NewEngine(registry).Match(context.Background(), MatchRequest{
		Graph:    sdk.New(),
		Registry: sdk.NewPackageRegistry(),
	})
	if err != nil {
		t.Fatalf("Match() error = %v", err)
	}
	pkg, ok := result.Registry.Get(purl)
	if !ok || len(pkg.Vulnerabilities) != 1 {
		t.Fatalf("package vulnerabilities = %#v", pkg)
	}
	if result.VulnerabilitiesConsolidated != 1 {
		t.Fatalf("consolidated count = %d, want 1", result.VulnerabilitiesConsolidated)
	}
}
