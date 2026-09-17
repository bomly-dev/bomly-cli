package engine

import (
	"context"
	"slices"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/testnodes"
	"go.uber.org/zap"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

type matcherIntentProbe struct {
	calls *[]string
}

func (m matcherIntentProbe) Descriptor() plugin.MatcherDescriptor {
	return plugin.MatcherDescriptor{Name: "network-intent-probe"}
}

func (m matcherIntentProbe) Ready(context.Context, plugin.MatchRequest) error {
	*m.calls = append(*m.calls, "ready")
	return nil
}

func (m matcherIntentProbe) Applicable(context.Context, plugin.MatchRequest) (bool, error) {
	*m.calls = append(*m.calls, "applicable")
	return true, nil
}

func (m matcherIntentProbe) Match(_ context.Context, req plugin.MatchRequest) (plugin.MatchResult, error) {
	*m.calls = append(*m.calls, "match")
	return plugin.MatchResult{Registry: req.Registry}, nil
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
				req.FailOn = []model.FailOnConstraint{{Kind: model.SeverityConstraint, Value: "high"}}
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
	graph := model.New()
	dependency := testnodes.DepFrom(model.DependencyNode{
		Coordinates: model.Coordinates{
			Ecosystem:      model.EcosystemNPM,
			PackageManager: model.PackageManagerNPM,
			Name:           "lodash",
			Version:        "4.17.21",
			PURL:           "pkg:npm/lodash@4.17.21",
		},
		Relationship: model.DependencyRelationshipDirect,
		Source:       model.DependencySourceRegistry,
	})
	if err := graph.AddNode(dependency); err != nil {
		t.Fatalf("add dependency: %v", err)
	}
	return fakeDetector{
		descriptor: plugin.DetectorDescriptor{
			Name:                "npm-detector",
			SupportedEcosystems: []model.Ecosystem{model.EcosystemNPM},
			SupportedManagers:   []model.PackageManager{model.PackageManagerNPM},
		},
		result: plugin.DetectionResult{Graphs: model.SingleGraphContainer(
			graph,
			model.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"},
		)},
	}
}

func networkIntentPipelineRequest() PipelineRequest {
	target := plugin.ExecutionTarget{Kind: plugin.ExecutionTargetFilesystem, Location: "/repo"}
	return PipelineRequest{
		ProjectPath:     "/repo",
		ExecutionTarget: target,
		Subprojects: []plugin.Subproject{{
			ExecutionTarget:         target,
			RelativePath:            ".",
			PrimaryDetector:         "npm-detector",
			DetectedPackageManagers: []model.PackageManager{model.PackageManagerNPM},
			Ecosystem:               model.EcosystemNPM,
		}},
		MatcherFilter: plugin.MatcherFilter{Include: []string{"network-intent-probe"}},
	}
}
