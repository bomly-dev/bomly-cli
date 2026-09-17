package engine

import (
	"context"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/testnodes"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

type eligibilityCapturingMatcher struct {
	calls    int
	graph    *model.Graph
	registry *model.PackageRegistry
	target   *model.DependencyNode
}

func (m *eligibilityCapturingMatcher) Descriptor() plugin.MatcherDescriptor {
	return plugin.MatcherDescriptor{Name: "eligibility-capture"}
}

func (m *eligibilityCapturingMatcher) Ready(context.Context, plugin.MatchRequest) error { return nil }

func (m *eligibilityCapturingMatcher) Applicable(context.Context, plugin.MatchRequest) (bool, error) {
	return true, nil
}

func (m *eligibilityCapturingMatcher) Match(_ context.Context, req plugin.MatchRequest) (plugin.MatchResult, error) {
	m.calls++
	m.graph, m.registry, m.target = req.Graph, req.Registry, req.Target
	return plugin.MatchResult{Registry: req.Registry}, nil
}

type graphSizeAuditor struct{ size int }

func (a *graphSizeAuditor) Descriptor() plugin.AuditorDescriptor {
	return plugin.AuditorDescriptor{Name: "graph-size"}
}

func (a *graphSizeAuditor) Ready(context.Context, plugin.AuditRequest) error { return nil }

func (a *graphSizeAuditor) Applicable(context.Context, plugin.AuditRequest) (bool, error) {
	return true, nil
}

func (a *graphSizeAuditor) Audit(_ context.Context, req plugin.AuditRequest) (plugin.AuditResult, error) {
	if req.Graph != nil {
		a.size = req.Graph.Size()
	}
	return plugin.AuditResult{}, nil
}

func TestEngineMatchFiltersOccurrencesButPreservesGraphAndRegistry(t *testing.T) {
	graph := model.New()
	app := testnodes.ModuleFrom("package.json", model.Coordinates{
		Ecosystem: model.EcosystemNPM, Name: "app", Version: "1.0.0", Type: model.PackageTypeApplication,
	})
	// A manifest is a manifest node now; there is no dependency node typed
	// "manifest" for a matcher to consider (ADR-0041).
	manifest := testnodes.Manifest("package.json", model.ManifestKindPackageJSON)
	registryRelease := matchTestDependency("registry-package", "1.0.0", "", model.DependencySourceRegistry)
	registryRelease.Relationship = model.DependencyRelationshipUnknown
	legacy := matchTestDependency("legacy-package", "1.0.0", "", "")
	legacy.Source = model.DependencySource("plugin-defined")
	mirror := matchTestDependency("mirror-package", "1.0.0", "", model.DependencySourceRegistry)
	mirror.ResolvedURL = "https://mirror.example.test/mirror-package.tgz"
	workspace := matchTestDependency("shared", "1.0.0", model.PackageTypeApplication, model.DependencySourceWorkspace)
	externalShared := matchTestDependency("shared", "2.0.0", "", model.DependencySourceRegistry)
	project := matchTestDependency("project-package", "1.0.0", "", model.DependencySourceProject)
	file := matchTestDependency("file-package", "1.0.0", "", model.DependencySourceFile)
	git := matchTestDependency("git-package", "1.0.0", "", model.DependencySourceGit)
	url := matchTestDependency("url-package", "1.0.0", "", model.DependencySourceURL)

	all := []model.GraphNode{app, manifest, registryRelease, legacy, mirror, workspace, externalShared, project, file, git, url}
	registry := model.NewPackageRegistry()
	for _, dependency := range all {
		if err := graph.AddNode(dependency); err != nil {
			t.Fatal(err)
		}
		if dep, ok := model.AsDependencyNode(dependency); ok {
			registry.Add(model.PackageFromDependencyNode(dep))
		}
	}
	for _, dependency := range all[2:] {
		if err := graph.AddEdge(app.NodeID(), dependency.NodeID()); err != nil {
			t.Fatal(err)
		}
	}
	if err := graph.AddEdge(registryRelease.NodeID(), legacy.NodeID()); err != nil {
		t.Fatal(err)
	}

	matcher := &eligibilityCapturingMatcher{}
	auditor := &graphSizeAuditor{}
	components := newTestRegistry()
	components.registerMatcher(matcher)
	components.registerAuditor(auditor)
	engine := NewEngine(components)

	result, err := engine.Match(context.Background(), plugin.MatchRequest{Graph: graph, Registry: registry})
	if err != nil {
		t.Fatalf("Match() error = %v", err)
	}
	if matcher.calls != 1 || matcher.graph == nil {
		t.Fatalf("expected matcher to receive one filtered request, calls=%d graph=%v", matcher.calls, matcher.graph)
	}
	wantEligible := map[string]bool{registryRelease.NodeID(): true, legacy.NodeID(): true, mirror.NodeID(): true, externalShared.NodeID(): true}
	if matcher.graph.Size() != len(wantEligible) {
		t.Fatalf("matcher graph size = %d, want %d: %#v", matcher.graph.Size(), len(wantEligible), matcher.graph.DependencyNodes())
	}
	for _, dependency := range matcher.graph.DependencyNodes() {
		if !wantEligible[dependency.NodeID()] {
			t.Fatalf("unexpected matcher dependency %#v", dependency)
		}
	}
	children, err := matcher.graph.DirectDependencies(registryRelease.NodeID())
	if err != nil || len(children) != 1 || !testnodes.Is(children[0], legacy.NodeID()) {
		t.Fatalf("expected eligible internal edge to survive, children=%#v err=%v", children, err)
	}
	if matcher.registry != registry || result.Registry != registry || matcher.registry.Len() != registry.Len() {
		t.Fatal("expected the complete package registry to remain shared with matchers")
	}
	if graph.Size() != len(all) {
		t.Fatalf("complete graph was mutated: size=%d want=%d", graph.Size(), len(all))
	}
	if _, err := engine.Audit(context.Background(), plugin.AuditRequest{Graph: graph, Registry: registry}); err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if auditor.size != len(all) {
		t.Fatalf("auditor graph size = %d, want complete size %d", auditor.size, len(all))
	}
}

func TestEngineMatchDoesNotWidenIneligibleTarget(t *testing.T) {
	graph := model.New()
	workspace := matchTestDependency("workspace", "1.0.0", model.PackageTypeApplication, model.DependencySourceWorkspace)
	external := matchTestDependency("external", "1.0.0", "", model.DependencySourceRegistry)
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

	if _, err := engine.Match(context.Background(), plugin.MatchRequest{Graph: graph, Registry: model.NewPackageRegistry(), Target: workspace}); err != nil {
		t.Fatalf("Match() error = %v", err)
	}
	if matcher.calls != 0 {
		t.Fatalf("expected no matcher call for ineligible target, got %d", matcher.calls)
	}

	if _, err := engine.Match(context.Background(), plugin.MatchRequest{Graph: graph, Registry: model.NewPackageRegistry(), Target: external}); err != nil {
		t.Fatalf("Match() eligible target error = %v", err)
	}
	if matcher.calls != 1 || matcher.target == nil || !testnodes.Is(matcher.target, external.NodeID()) {
		t.Fatalf("expected eligible target to be preserved, calls=%d target=%#v", matcher.calls, matcher.target)
	}
}

func matchTestDependency(name, version string, typ model.PackageType, source model.DependencySource) *model.DependencyNode {
	return testnodes.DepFrom(model.DependencyNode{Coordinates: model.Coordinates{Ecosystem: model.EcosystemNPM, Name: name, Version: version, Type: typ}, Source: source})
}
