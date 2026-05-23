package cli

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/engine"
	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestReportOptionsFromPipelineResultsCombinesAnalyzerMetadata(t *testing.T) {
	options := reportOptionsFromPipelineResults(true,
		engine.PipelineResult{
			AnalyzerRuns: []string{"jsreach", "govulncheck"},
			AnalyzerStats: map[string]sdk.ReachabilityStats{
				"jsreach": {Reachable: 1, Unknown: 2},
			},
		},
		engine.PipelineResult{
			AnalyzerRuns: []string{"pyreach", "jsreach"},
			AnalyzerStats: map[string]sdk.ReachabilityStats{
				"jsreach": {Reachable: 3, Unreachable: 4},
				"pyreach": {NotApplicable: 5},
			},
		},
	)
	if !options.ReachabilityEnabled {
		t.Fatal("reachability should be enabled")
	}
	wantRuns := []string{"govulncheck", "jsreach", "pyreach"}
	for idx, want := range wantRuns {
		if idx >= len(options.AnalyzerRuns) || options.AnalyzerRuns[idx] != want {
			t.Fatalf("AnalyzerRuns = %#v, want %#v", options.AnalyzerRuns, wantRuns)
		}
	}
	if got := options.AnalyzerStats["jsreach"]; got.Reachable != 4 || got.Unreachable != 4 || got.Unknown != 2 {
		t.Fatalf("combined jsreach stats = %#v", got)
	}
	if got := options.AnalyzerStats["pyreach"]; got.NotApplicable != 5 {
		t.Fatalf("combined pyreach stats = %#v", got)
	}
}

func TestReportOptionsFromPipelineResultsDisabledOmitsAnalyzerMetadata(t *testing.T) {
	options := reportOptionsFromPipelineResults(false, engine.PipelineResult{
		AnalyzerRuns:  []string{"jsreach"},
		AnalyzerStats: map[string]sdk.ReachabilityStats{"jsreach": {Reachable: 1}},
	})
	if options.ReachabilityEnabled || len(options.AnalyzerRuns) > 0 || len(options.AnalyzerStats) > 0 {
		t.Fatalf("disabled options should be empty: %#v", options)
	}
}
