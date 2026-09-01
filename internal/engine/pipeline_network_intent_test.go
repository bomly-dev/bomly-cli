package engine

import (
	"context"
	"github.com/bomly-dev/bomly-cli/internal/testnodes"
	"slices"
	"testing"

	"github.com/bomly-dev/bomly-sdk"
	"go.uber.org/zap"
)

type matcherIntentProbe struct {
	calls *[]string
}

func (m matcherIntentProbe) Descriptor() sdk.MatcherDescriptor {
	return sdk.MatcherDescriptor{Name: "network-intent-probe"}
}

func (m matcherIntentProbe) Ready(context.Context, sdk.MatchRequest) error {
	*m.calls = append(*m.calls, "ready")
	return nil
}

func (m matcherIntentProbe) Applicable(context.Context, sdk.MatchRequest) (bool, error) {
	*m.calls = append(*m.calls, "applicable")
	return true, nil
}

func (m matcherIntentProbe) Match(_ context.Context, req sdk.MatchRequest) (sdk.MatchResult, error) {
	*m.calls = append(*m.calls, "match")
	return sdk.MatchResult{Registry: req.Registry}, nil
}

func TestPipelineRequiresExplicitMatcherIntent(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*PipelineRequest)
		wantCalls []string
	}{
		{name: "plain scan"},
		{
			name: "audit only",
			configure: func(req *PipelineRequest) {
				req.AuditEnabled = true
			},
		},
		{
			name: "analysis only",
			configure: func(req *PipelineRequest) {
				req.AnalyzeReachabilityEnabled = true
			},
		},
		{
			name: "policy inputs only",
			configure: func(req *PipelineRequest) {
				req.FailOn = []sdk.FailOnConstraint{{Kind: sdk.SeverityConstraint, Value: "high"}}
				req.WarnOnly = true
			},
		},
		{
			name: "enrichment",
			configure: func(req *PipelineRequest) {
				req.EnrichEnabled = true
			},
			wantCalls: []string{"ready", "applicable", "match"},
		},
		{
			name: "explicit internal matching",
			configure: func(req *PipelineRequest) {
				req.MatchEnabled = true
			},
			wantCalls: []string{"ready", "applicable", "match"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := []string{}
			registry := newTestRegistry()
			registry.registerDetector(networkIntentDetector(t))
			registry.registerMatcher(matcherIntentProbe{calls: &calls})

			req := networkIntentPipelineRequest()
			if tt.configure != nil {
				tt.configure(&req)
			}

			if _, err := NewPipeline(registry, zap.NewNop()).Run(context.Background(), req); err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if !slices.Equal(calls, tt.wantCalls) {
				t.Fatalf("matcher calls = %v, want %v", calls, tt.wantCalls)
			}
		})
	}
}

func networkIntentDetector(t *testing.T) fakeDetector {
	t.Helper()
	graph := sdk.New()
	dependency := testnodes.DepFrom(sdk.DependencyNode{
		Coordinates: sdk.Coordinates{
			Ecosystem:      sdk.EcosystemNPM,
			PackageManager: sdk.PackageManagerNPM,
			Name:           "lodash",
			Version:        "4.17.21",
			PURL:           "pkg:npm/lodash@4.17.21",
		},
		Relationship: sdk.DependencyRelationshipDirect,
		Source:       sdk.DependencySourceRegistry,
	})
	if err := graph.AddNode(dependency); err != nil {
		t.Fatalf("add dependency: %v", err)
	}
	return fakeDetector{
		descriptor: sdk.DetectorDescriptor{
			Name:                "npm-detector",
			SupportedEcosystems: []sdk.Ecosystem{sdk.EcosystemNPM},
			SupportedManagers:   []sdk.PackageManager{sdk.PackageManagerNPM},
		},
		result: sdk.DetectionResult{Graphs: sdk.SingleGraphContainer(
			graph,
			sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"},
		)},
	}
}

func networkIntentPipelineRequest() PipelineRequest {
	target := sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: "/repo"}
	return PipelineRequest{
		ProjectPath:     "/repo",
		ExecutionTarget: target,
		Subprojects: []sdk.Subproject{{
			ExecutionTarget:         target,
			RelativePath:            ".",
			PrimaryDetector:         "npm-detector",
			DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
			Ecosystem:               sdk.EcosystemNPM,
		}},
		MatcherFilter: sdk.MatcherFilter{Include: []string{"network-intent-probe"}},
	}
}
