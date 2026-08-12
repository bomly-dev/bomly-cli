package engine

import (
	"context"
	"testing"

	"github.com/bomly-dev/bomly-sdk"
)

// deltaMatcher is a fake matcher whose Match behavior is fully controlled by
// the test through the match func, so tests can return PackageUpdates deltas,
// full registries, or zero-value results.
type deltaMatcher struct {
	name  string
	match func(req MatchRequest) (sdk.MatchResult, error)
}

func (m deltaMatcher) Descriptor() MatcherDescriptor {
	return MatcherDescriptor{Name: m.name}
}

func (m deltaMatcher) Ready(context.Context, MatchRequest) error { return nil }

func (m deltaMatcher) Applicable(context.Context, MatchRequest) (bool, error) {
	return true, nil
}

func (m deltaMatcher) Match(_ context.Context, req MatchRequest) (sdk.MatchResult, error) {
	return m.match(req)
}

// deltaAnalyzer is the analyzer twin of deltaMatcher.
type deltaAnalyzer struct {
	name    string
	analyze func(req sdk.AnalyzeRequest) (sdk.AnalyzeResult, error)
}

func (a deltaAnalyzer) Descriptor() sdk.AnalyzerDescriptor {
	return sdk.AnalyzerDescriptor{Name: a.name}
}

func (a deltaAnalyzer) Ready(context.Context, sdk.AnalyzeRequest) error { return nil }

func (a deltaAnalyzer) Applicable(context.Context, sdk.AnalyzeRequest) (bool, error) {
	return true, nil
}

func (a deltaAnalyzer) Analyze(_ context.Context, req sdk.AnalyzeRequest) (sdk.AnalyzeResult, error) {
	return a.analyze(req)
}

func TestEngineMatch_AppliesPackageUpdateDeltas(t *testing.T) {
	const purl = "pkg:npm/react@18.2.0"
	registry := newTestRegistry()

	var sawAccept bool
	registry.registerMatcher(deltaMatcher{
		name: "delta",
		match: func(req MatchRequest) (sdk.MatchResult, error) {
			sawAccept = req.AcceptPackageUpdates
			return sdk.MatchResult{
				PackageUpdates: []*sdk.Package{{
					Coordinates: sdk.Coordinates{PURL: purl},
					Licenses:    []sdk.PackageLicense{{SPDXExpression: "MIT"}},
				}},
				MatcherStats: sdk.MatcherStats{Licenses: 1},
			}, nil
		},
	})

	var secondSawUpdate bool
	registry.registerMatcher(deltaMatcher{
		name: "observer",
		match: func(req MatchRequest) (sdk.MatchResult, error) {
			if pkg, ok := req.Registry.Get(purl); ok && len(pkg.Licenses) == 1 {
				secondSawUpdate = true
			}
			// Zero-value result: the effective registry must be preserved.
			return sdk.MatchResult{}, nil
		},
	})

	result, err := NewEngine(registry).Match(context.Background(), MatchRequest{
		Graph:    sdk.New(),
		Registry: sdk.NewPackageRegistry(),
	})
	if err != nil {
		t.Fatalf("Match() error = %v", err)
	}
	if !sawAccept {
		t.Fatal("expected the engine to set AcceptPackageUpdates on matcher requests")
	}
	if !secondSawUpdate {
		t.Fatal("expected the second matcher to observe the delta-updated registry")
	}
	if result.Registry == nil {
		t.Fatal("expected a registry on the aggregated result")
	}
	pkg, ok := result.Registry.Get(purl)
	if !ok {
		t.Fatalf("expected delta package %q in the final registry", purl)
	}
	if values := pkg.LicenseValues(); len(values) != 1 || values[0] != "MIT" {
		t.Fatalf("expected delta enrichment to land, got %#v", values)
	}
	if len(result.MatcherStats) != 2 {
		t.Fatalf("expected stats from both matchers, got %#v", result.MatcherStats)
	}
}

func TestEngineMatch_ReturnedRegistryWinsOverPackageUpdates(t *testing.T) {
	const kept = "pkg:npm/kept@1.0.0"
	const ignored = "pkg:npm/ignored@1.0.0"
	registry := newTestRegistry()

	full := sdk.NewPackageRegistry()
	full.Ensure(kept)
	registry.registerMatcher(deltaMatcher{
		name: "both",
		match: func(MatchRequest) (sdk.MatchResult, error) {
			// Returning both mirrors nothing a well-behaved component should
			// do, but the adapter semantics are explicit: Registry wins.
			return sdk.MatchResult{
				Registry:       full,
				PackageUpdates: []*sdk.Package{{Coordinates: sdk.Coordinates{PURL: ignored}}},
			}, nil
		},
	})

	result, err := NewEngine(registry).Match(context.Background(), MatchRequest{
		Graph:    sdk.New(),
		Registry: sdk.NewPackageRegistry(),
	})
	if err != nil {
		t.Fatalf("Match() error = %v", err)
	}
	if result.Registry != full {
		t.Fatal("expected the returned registry to win over deltas")
	}
	if _, ok := result.Registry.Get(ignored); ok {
		t.Fatal("expected PackageUpdates to be ignored when a registry is returned")
	}
	if _, ok := result.Registry.Get(kept); !ok {
		t.Fatal("expected returned registry contents to be preserved")
	}
}

func TestEngineAnalyze_AppliesPackageUpdateDeltas(t *testing.T) {
	const purl = "pkg:golang/example.com/mod@v1.0.0"
	registry := newTestRegistry()

	var sawAccept bool
	registry.RegisterAnalyzer(deltaAnalyzer{
		name: "delta",
		analyze: func(req sdk.AnalyzeRequest) (sdk.AnalyzeResult, error) {
			sawAccept = req.AcceptPackageUpdates
			return sdk.AnalyzeResult{
				PackageUpdates: []*sdk.Package{{Coordinates: sdk.Coordinates{PURL: purl}}},
				AnalyzerStats: map[string]sdk.ReachabilityStats{
					"delta": {Reachable: 1},
				},
			}, nil
		},
	})

	var secondSawUpdate bool
	registry.RegisterAnalyzer(deltaAnalyzer{
		name: "observer",
		analyze: func(req sdk.AnalyzeRequest) (sdk.AnalyzeResult, error) {
			_, secondSawUpdate = req.Registry.Get(purl)
			// Zero-value result: the effective registry must be preserved.
			return sdk.AnalyzeResult{}, nil
		},
	})

	result, err := NewEngine(registry).Analyze(context.Background(), sdk.AnalyzeRequest{
		Graph:    sdk.New(),
		Registry: sdk.NewPackageRegistry(),
	})
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if !sawAccept {
		t.Fatal("expected the engine to set AcceptPackageUpdates on analyzer requests")
	}
	if !secondSawUpdate {
		t.Fatal("expected the second analyzer to observe the delta-updated registry")
	}
	if result.Registry == nil {
		t.Fatal("expected a registry on the aggregated result")
	}
	if _, ok := result.Registry.Get(purl); !ok {
		t.Fatalf("expected delta package %q in the final registry", purl)
	}
	if result.AnalyzerStats["delta"].Reachable != 1 {
		t.Fatalf("expected analyzer stats to aggregate, got %#v", result.AnalyzerStats)
	}
}

func TestEngineAnalyze_ReturnedRegistryWinsOverPackageUpdates(t *testing.T) {
	const kept = "pkg:npm/kept@1.0.0"
	const ignored = "pkg:npm/ignored@1.0.0"
	registry := newTestRegistry()

	full := sdk.NewPackageRegistry()
	full.Ensure(kept)
	registry.RegisterAnalyzer(deltaAnalyzer{
		name: "both",
		analyze: func(sdk.AnalyzeRequest) (sdk.AnalyzeResult, error) {
			return sdk.AnalyzeResult{
				Registry:       full,
				PackageUpdates: []*sdk.Package{{Coordinates: sdk.Coordinates{PURL: ignored}}},
			}, nil
		},
	})

	result, err := NewEngine(registry).Analyze(context.Background(), sdk.AnalyzeRequest{
		Graph:    sdk.New(),
		Registry: sdk.NewPackageRegistry(),
	})
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if result.Registry != full {
		t.Fatal("expected the returned registry to win over deltas")
	}
	if _, ok := result.Registry.Get(ignored); ok {
		t.Fatal("expected PackageUpdates to be ignored when a registry is returned")
	}
}
