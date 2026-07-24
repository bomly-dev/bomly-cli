package cli

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/engine"
	"github.com/bomly-dev/bomly-cli/internal/output"
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

func TestExplainPackageRefPlacesRemediationOnlyOnFocusedDependency(t *testing.T) {
	const purl = "pkg:npm/example@1.0.0"
	dependency := sdk.NewDependency(sdk.Dependency{
		Coordinates: sdk.Coordinates{
			PURL:    purl,
			Name:    "example",
			Version: "1.0.0",
		},
	})
	registry := sdk.NewPackageRegistry()
	registry.Add(&sdk.Package{
		Coordinates: dependency.Coordinates,
		Remediation: &sdk.PackageRemediation{
			Status:             sdk.PackageRemediationComplete,
			RecommendedVersion: "1.2.0",
		},
	})

	focused := explainPackageRef(dependency, registry)
	if focused.Remediation == nil || focused.Remediation.RecommendedVersion != "1.2.0" {
		t.Fatalf("focused remediation = %#v", focused.Remediation)
	}
	paths := explainPathsWithStableIDs([]output.DependencyPath{{
		Packages: []output.PackageRef{
			output.PackageFromGraphPackage(dependency),
		},
	}})
	pathData, err := json.Marshal(paths)
	if err != nil {
		t.Fatalf("Marshal(paths) error = %v", err)
	}
	if strings.Contains(string(pathData), `"remediation"`) {
		t.Fatalf("path package repeated remediation: %s", pathData)
	}

	data, err := json.Marshal(output.BuildExplainResponse(
		output.ProjectDescriptor{Name: "demo"},
		"example",
		[]output.ExplainTargetResponse{{
			Dependency: focused,
			Paths:      paths,
		}},
		time.Now(),
	))
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if got := strings.Count(string(data), `"remediation"`); got != 2 {
		t.Fatalf("remediation occurrence count = %d, want flattened and target dependency only: %s", got, data)
	}
}
