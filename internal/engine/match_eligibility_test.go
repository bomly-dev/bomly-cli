package engine

import (
	"context"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

type eligibilityCapturingMatcher struct {
	calls    int
	graph    *sdk.Graph
	registry *sdk.PackageRegistry
	target   *sdk.Dependency
}

func (m *eligibilityCapturingMatcher) Descriptor() sdk.MatcherDescriptor {
	return sdk.MatcherDescriptor{Name: "eligibility-capture"}
}

func (m *eligibilityCapturingMatcher) Ready(context.Context, sdk.MatchRequest) error { return nil }

func (m *eligibilityCapturingMatcher) Applicable(context.Context, sdk.MatchRequest) (bool, error) {
	return true, nil
}

func (m *eligibilityCapturingMatcher) Match(_ context.Context, req sdk.MatchRequest) (sdk.MatchResult, error) {
	m.calls++
	m.graph, m.registry, m.target = req.Graph, req.Registry, req.Target
	return sdk.MatchResult{Registry: req.Registry}, nil
}

type graphSizeAuditor struct{ size int }

func (a *graphSizeAuditor) Descriptor() sdk.AuditorDescriptor {
	return sdk.AuditorDescriptor{Name: "graph-size"}
}

func (a *graphSizeAuditor) Ready(context.Context, sdk.AuditRequest) error { return nil }

func (a *graphSizeAuditor) Applicable(context.Context, sdk.AuditRequest) (bool, error) {
	return true, nil
}

func (a *graphSizeAuditor) Audit(_ context.Context, req sdk.AuditRequest) (sdk.AuditResult, error) {
	if req.Graph != nil {
		a.size = req.Graph.Size()
	}
	return sdk.AuditResult{}, nil
}

func TestEngineMatchFiltersOccurrencesButPreservesGraphAndRegistry(t *testing.T) {
	graph := sdk.New()
	app := matchTestDependency("app", "1.0.0", sdk.PackageTypeApplication, sdk.DependencySourceRegistry)
	manifest := matchTestDependency("manifest", "1.0.0", sdk.PackageTypeManifest, "")
	registryRelease := matchTestDependency("registry-package", "1.0.0", "", sdk.DependencySourceRegistry)
	registryRelease.Relationship = sdk.DependencyRelationshipUnknown
	legacy := matchTestDependency("legacy-package", "1.0.0", "", "")
	legacy.Source = sdk.DependencySource("plugin-defined")
	mirror := matchTestDependency("mirror-package", "1.0.0", "", sdk.DependencySourceRegistry)
	mirror.ResolvedURL = "https://mirror.example.test/mirror-package.tgz"
	workspace := matchTestDependency("shared", "1.0.0", sdk.PackageTypeApplication, sdk.DependencySourceWorkspace)
	externalShared := matchTestDependency("shared", "2.0.0", "", sdk.DependencySourceRegistry)
	project := matchTestDependency("project-package", "1.0.0", "", sdk.DependencySourceProject)
	file := matchTestDependency("file-package", "1.0.0", "", sdk.DependencySourceFile)
	git := matchTestDependency("git-package", "1.0.0", "", sdk.DependencySourceGit)
	url := matchTestDependency("url-package", "1.0.0", "", sdk.DependencySourceURL)

	all := []*sdk.Dependency{app, manifest, registryRelease, legacy, mirror, workspace, externalShared, project, file, git, url}
	registry := sdk.NewPackageRegistry()
	for _, dependency := range all {
		if err := graph.AddNode(dependency); err != nil {
			t.Fatal(err)
		}
		registry.Add(sdk.PackageFromDependency(dependency))
	}
	for _, dependency := range all[2:] {
		if err := graph.AddEdge(app.ID, dependency.ID); err != nil {
			t.Fatal(err)
		}
	}
	if err := graph.AddEdge(registryRelease.ID, legacy.ID); err != nil {
		t.Fatal(err)
	}

	matcher := &eligibilityCapturingMatcher{}
	auditor := &graphSizeAuditor{}
	components := newTestRegistry()
	components.registerMatcher(matcher)
	components.registerAuditor(auditor)
	engine := NewEngine(components)

	result, err := engine.Match(context.Background(), sdk.MatchRequest{Graph: graph, Registry: registry})
	if err != nil {
		t.Fatalf("Match() error = %v", err)
	}
	if matcher.calls != 1 || matcher.graph == nil {
		t.Fatalf("expected matcher to receive one filtered request, calls=%d graph=%v", matcher.calls, matcher.graph)
	}
	wantEligible := map[string]bool{registryRelease.ID: true, legacy.ID: true, mirror.ID: true, externalShared.ID: true}
	if matcher.graph.Size() != len(wantEligible) {
		t.Fatalf("matcher graph size = %d, want %d: %#v", matcher.graph.Size(), len(wantEligible), matcher.graph.Nodes())
	}
	for _, dependency := range matcher.graph.Nodes() {
		if !wantEligible[dependency.ID] {
			t.Fatalf("unexpected matcher dependency %#v", dependency)
		}
	}
	children, err := matcher.graph.DirectDependencies(registryRelease.ID)
	if err != nil || len(children) != 1 || children[0].ID != legacy.ID {
		t.Fatalf("expected eligible internal edge to survive, children=%#v err=%v", children, err)
	}
	if matcher.registry != registry || result.Registry != registry || matcher.registry.Len() != registry.Len() {
		t.Fatal("expected the complete package registry to remain shared with matchers")
	}
	if graph.Size() != len(all) {
		t.Fatalf("complete graph was mutated: size=%d want=%d", graph.Size(), len(all))
	}
	if _, err := engine.Audit(context.Background(), sdk.AuditRequest{Graph: graph, Registry: registry}); err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if auditor.size != len(all) {
		t.Fatalf("auditor graph size = %d, want complete size %d", auditor.size, len(all))
	}
}

func TestEngineMatchDoesNotWidenIneligibleTarget(t *testing.T) {
	graph := sdk.New()
	workspace := matchTestDependency("workspace", "1.0.0", sdk.PackageTypeApplication, sdk.DependencySourceWorkspace)
	external := matchTestDependency("external", "1.0.0", "", sdk.DependencySourceRegistry)
	if err := graph.AddNode(workspace); err != nil {
		t.Fatal(err)
	}
	if err := graph.AddNode(external); err != nil {
		t.Fatal(err)
	}
	matcher := &eligibilityCapturingMatcher{}
	components := newTestRegistry()
	components.registerMatcher(matcher)
	engine := NewEngine(components)

	if _, err := engine.Match(context.Background(), sdk.MatchRequest{Graph: graph, Registry: sdk.NewPackageRegistry(), Target: workspace}); err != nil {
		t.Fatalf("Match() error = %v", err)
	}
	if matcher.calls != 0 {
		t.Fatalf("expected no matcher call for ineligible target, got %d", matcher.calls)
	}

	if _, err := engine.Match(context.Background(), sdk.MatchRequest{Graph: graph, Registry: sdk.NewPackageRegistry(), Target: external}); err != nil {
		t.Fatalf("Match() eligible target error = %v", err)
	}
	if matcher.calls != 1 || matcher.target == nil || matcher.target.ID != external.ID {
		t.Fatalf("expected eligible target to be preserved, calls=%d target=%#v", matcher.calls, matcher.target)
	}
}

func matchTestDependency(name, version string, typ sdk.PackageType, source sdk.DependencySource) *sdk.Dependency {
	return sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemNPM, Name: name, Version: version, Type: typ}, Source: source})
}
