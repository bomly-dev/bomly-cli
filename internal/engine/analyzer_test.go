package engine

import (
	"context"
	"errors"
	"testing"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

type fakeAnalyzer struct {
	descriptor plugin.AnalyzerDescriptor
	result     plugin.AnalyzeResult
	err        error
	ready      *bool
	applicable *bool
	applyErr   error
	calls      int
}

func (f *fakeAnalyzer) Descriptor() plugin.AnalyzerDescriptor { return f.descriptor }

func (f *fakeAnalyzer) Ready(context.Context, plugin.AnalyzeRequest) error {
	if f.ready != nil && !*f.ready {
		return errors.New("not ready")
	}
	return nil
}

func (f *fakeAnalyzer) Applicable(_ context.Context, _ plugin.AnalyzeRequest) (bool, error) {
	if f.applyErr != nil {
		return false, f.applyErr
	}
	if f.applicable == nil {
		return true, nil
	}
	return *f.applicable, nil
}

func (f *fakeAnalyzer) Analyze(_ context.Context, _ plugin.AnalyzeRequest) (plugin.AnalyzeResult, error) {
	f.calls++
	return f.result, f.err
}

func TestEngineAnalyzeNoAnalyzersIsNotAnError(t *testing.T) {
	engine := NewEngine(newTestRegistry())
	g := model.New()
	result, err := engine.Analyze(context.Background(), plugin.AnalyzeRequest{Graph: g})
	if err != nil {
		t.Fatalf("Analyze with no analyzers returned err: %v", err)
	}
	_ = result
	if len(result.AnalyzerRuns) != 0 {
		t.Errorf("AnalyzerRuns should be empty, got %v", result.AnalyzerRuns)
	}
}

func TestEngineAnalyzeRunsApplicableAndCollectsStats(t *testing.T) {
	reg := newTestRegistry()
	g := model.New()
	a := &fakeAnalyzer{
		descriptor: plugin.AnalyzerDescriptor{
			Name: "fake",
		},
		result: plugin.AnalyzeResult{
			AnalyzerStats: map[string]plugin.ReachabilityStats{
				"fake": {Reachable: 2, Unreachable: 1},
			},
		},
	}
	reg.RegisterAnalyzer(a)

	engine := NewEngine(reg)
	result, err := engine.Analyze(context.Background(), plugin.AnalyzeRequest{
		Graph: g,
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if a.calls != 1 {
		t.Errorf("analyzer Analyze called %d times, want 1", a.calls)
	}
	if len(result.AnalyzerRuns) != 1 || result.AnalyzerRuns[0] != "fake" {
		t.Errorf("AnalyzerRuns = %v, want [fake]", result.AnalyzerRuns)
	}
	if result.AnalyzerStats["fake"].Reachable != 2 {
		t.Errorf("stats not propagated: %+v", result.AnalyzerStats)
	}
}

func TestEngineAnalyzeAggregatesErrorsAndContinues(t *testing.T) {
	reg := newTestRegistry()
	g := model.New()
	failing := &fakeAnalyzer{
		descriptor: plugin.AnalyzerDescriptor{
			Name: "boom",
		},
		err: errors.New("boom"),
	}
	ok := &fakeAnalyzer{
		descriptor: plugin.AnalyzerDescriptor{
			Name: "ok",
		},
		result: plugin.AnalyzeResult{},
	}
	reg.RegisterAnalyzer(failing)
	reg.RegisterAnalyzer(ok)

	engine := NewEngine(reg)
	result, err := engine.Analyze(context.Background(), plugin.AnalyzeRequest{
		Graph: g,
	})
	if err == nil {
		t.Fatal("expected aggregated error from failing analyzer")
	}
	if ok.calls != 1 {
		t.Errorf("ok analyzer should have run after failing one, calls=%d", ok.calls)
	}
	if len(result.AnalyzerRuns) != 1 || result.AnalyzerRuns[0] != "ok" {
		t.Errorf("AnalyzerRuns should only include successful runs, got %v", result.AnalyzerRuns)
	}
}

func TestEngineAnalyzeRespectsLanguageFilter(t *testing.T) {
	reg := newTestRegistry()
	g := model.New()
	goOnly := &fakeAnalyzer{
		descriptor: plugin.AnalyzerDescriptor{
			Name:               "goonly",
			SupportedLanguages: []model.Language{model.LanguageGo},
		},
		result: plugin.AnalyzeResult{},
	}
	reg.RegisterAnalyzer(goOnly)

	engine := NewEngine(reg)
	result, err := engine.Analyze(context.Background(), plugin.AnalyzeRequest{
		Graph:    g,
		Language: model.LanguageJavaScript,
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if goOnly.calls != 0 {
		t.Errorf("Go-only analyzer ran for JavaScript request: calls=%d", goOnly.calls)
	}
	if len(result.AnalyzerRuns) != 0 {
		t.Errorf("AnalyzerRuns should be empty when language filter excludes all, got %v", result.AnalyzerRuns)
	}
}
