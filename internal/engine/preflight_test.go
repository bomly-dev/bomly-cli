package engine

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/testnodes"
	"go.uber.org/zap"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

// calls records which contract methods the pipeline reached on a component,
// so a test can prove preflight held it back before Ready.
type calls struct{ ready, applicable, action int }

type preflightMatcher struct {
	descriptor      plugin.MatcherDescriptor
	vulnerabilities bool
	calls           *calls
}

func (m preflightMatcher) Descriptor() plugin.MatcherDescriptor { return m.descriptor }
func (m preflightMatcher) Ready(context.Context, plugin.MatchRequest) error {
	m.calls.ready++
	return nil
}
func (m preflightMatcher) Applicable(context.Context, plugin.MatchRequest) (bool, error) {
	m.calls.applicable++
	return true, nil
}
func (m preflightMatcher) Match(_ context.Context, req plugin.MatchRequest) (plugin.MatchResult, error) {
	m.calls.action++
	if m.vulnerabilities {
		for _, pkg := range req.Registry.All() {
			pkg.Vulnerabilities = append(pkg.Vulnerabilities, model.Vulnerability{ID: "GHSA-test-0001"})
		}
	}
	return plugin.MatchResult{Registry: req.Registry}, nil
}

type preflightAnalyzer struct {
	descriptor plugin.AnalyzerDescriptor
	applicable bool
	calls      *calls
}

func (a preflightAnalyzer) Descriptor() plugin.AnalyzerDescriptor { return a.descriptor }
func (a preflightAnalyzer) Ready(context.Context, plugin.AnalyzeRequest) error {
	a.calls.ready++
	return nil
}
func (a preflightAnalyzer) Applicable(context.Context, plugin.AnalyzeRequest) (bool, error) {
	a.calls.applicable++
	return a.applicable, nil
}
func (a preflightAnalyzer) Analyze(_ context.Context, req plugin.AnalyzeRequest) (plugin.AnalyzeResult, error) {
	a.calls.action++
	return plugin.AnalyzeResult{Registry: req.Registry}, nil
}

type preflightAuditor struct {
	descriptor plugin.AuditorDescriptor
	calls      *calls
}

func (a preflightAuditor) Descriptor() plugin.AuditorDescriptor { return a.descriptor }
func (a preflightAuditor) Ready(context.Context, plugin.AuditRequest) error {
	a.calls.ready++
	return nil
}
func (a preflightAuditor) Applicable(context.Context, plugin.AuditRequest) (bool, error) {
	a.calls.applicable++
	return true, nil
}
func (a preflightAuditor) Audit(context.Context, plugin.AuditRequest) (plugin.AuditResult, error) {
	a.calls.action++
	return plugin.AuditResult{}, nil
}

// preflightGraph is a two-dependency graph, so dependency-graph-v1 holds.
func preflightGraph(t *testing.T) *model.Graph {
	t.Helper()
	g := model.New()
	for _, label := range []string{"app@1.0.0", "react@18.2.0"} {
		if err := g.AddNode(testnodes.Ref(strings.Split(label, "@")[0], strings.Split(label, "@")[1])); err != nil {
			t.Fatalf("add node: %v", err)
		}
	}
	if err := g.AddEdge(testnodes.ID(g, "app@1.0.0"), testnodes.ID(g, "react@18.2.0")); err != nil {
		t.Fatalf("add edge: %v", err)
	}
	return g
}

// preflightScenario builds a registry with one npm detector, plus req for a
// filesystem target. Tests swap the target or add components.
func preflightScenario(t *testing.T, graph *model.Graph) (*Registry, PipelineRequest) {
	t.Helper()
	registry := newTestRegistry()
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "npm-detector", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
		result:     ResolveGraphResult{Graphs: SingleGraphContainer(graph, model.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"})},
	})
	target := ExecutionTarget{Kind: ExecutionTargetFilesystem, Location: "/repo"}
	return registry, PipelineRequest{
		ExecutionTarget: target,
		Subprojects: []Subproject{{
			ExecutionTarget:         target,
			RelativePath:            ".",
			DetectedPackageManagers: []PackageManager{PackageManagerNPM},
			Ecosystem:               EcosystemNPM,
		}},
	}
}

// sbomTarget replaces req's target with an ingested SBOM document, planned
// the way --sbom plans it, and registers a detector for it.
func sbomTarget(registry *Registry, req *PipelineRequest, graph *model.Graph) {
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "sbom-detector", SupportedEcosystems: []Ecosystem{EcosystemSBOM}, SupportedManagers: []PackageManager{PackageManagerSBOM}},
		result:     ResolveGraphResult{Graphs: SingleGraphContainer(graph, model.ManifestMetadata{Path: "bom.cdx.json", Kind: "cyclonedx"})},
	})
	target := ExecutionTarget{Kind: ExecutionTargetFilesystem, Location: "/repo/bom.cdx.json"}
	req.ExecutionTarget = target
	req.Subprojects = []Subproject{{
		ExecutionTarget:         target,
		RelativePath:            ".",
		DetectedPackageManagers: []PackageManager{PackageManagerSBOM},
		Ecosystem:               EcosystemSBOM,
	}}
}

func requires(tokens ...plugin.Requirement) plugin.Requirements { return tokens }

func TestPreflight_LegacyComponentsRunAsBeforeOnAnyTarget(t *testing.T) {
	graph := preflightGraph(t)
	registry, req := preflightScenario(t, graph)
	sbomTarget(registry, &req, graph)
	matcher, analyzer, auditor := &calls{}, &calls{}, &calls{}
	registry.registerMatcher(preflightMatcher{descriptor: plugin.MatcherDescriptor{Name: "legacy-matcher"}, calls: matcher})
	registry.RegisterAnalyzer(preflightAnalyzer{descriptor: plugin.AnalyzerDescriptor{Name: "legacy-analyzer"}, applicable: true, calls: analyzer})
	registry.registerAuditor(preflightAuditor{descriptor: plugin.AuditorDescriptor{Name: "legacy-auditor"}, calls: auditor})
	req.EnrichEnabled, req.AnalyzeReachabilityEnabled, req.AuditEnabled = true, true, true

	result, err := NewPipeline(registry, zap.NewNop()).Run(context.Background(), req)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	for name, got := range map[string]*calls{"matcher": matcher, "analyzer": analyzer, "auditor": auditor} {
		if got.ready != 1 || got.applicable != 1 || got.action != 1 {
			t.Errorf("%s: a component that declares nothing must run exactly as before, got %+v", name, *got)
		}
	}
	if len(result.MatchWarnings)+len(result.AnalyzeWarnings)+len(result.AuditWarnings) != 0 {
		t.Errorf("legacy components must raise no preflight warning, got %v %v %v", result.MatchWarnings, result.AnalyzeWarnings, result.AuditWarnings)
	}
}

func TestPreflight_SatisfiedRequirementsStillGoThroughReadyAndApplicable(t *testing.T) {
	registry, req := preflightScenario(t, preflightGraph(t))
	matcher, reachable, notApplicable := &calls{}, &calls{}, &calls{}
	registry.registerMatcher(preflightMatcher{
		descriptor:      plugin.MatcherDescriptor{Name: "vuln-matcher", Requires: requires(plugin.RequirementDependencyGraph)},
		vulnerabilities: true,
		calls:           matcher,
	})
	every := requires(plugin.RequirementSourceTree, plugin.RequirementDependencyGraph, plugin.RequirementVulnerabilityRecords)
	registry.RegisterAnalyzer(preflightAnalyzer{descriptor: plugin.AnalyzerDescriptor{Name: "reach", Requires: every}, applicable: true, calls: reachable})
	registry.RegisterAnalyzer(preflightAnalyzer{descriptor: plugin.AnalyzerDescriptor{Name: "picky", Requires: every}, applicable: false, calls: notApplicable})
	req.EnrichEnabled, req.AnalyzeReachabilityEnabled = true, true

	result, err := NewPipeline(registry, zap.NewNop()).Run(context.Background(), req)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if matcher.action != 1 || reachable.action != 1 {
		t.Fatalf("satisfied components must run: matcher %+v, analyzer %+v", *matcher, *reachable)
	}
	// Applicable stays authoritative after preflight passes.
	if notApplicable.ready != 1 || notApplicable.applicable != 1 || notApplicable.action != 0 {
		t.Fatalf("a component that passes preflight must still be asked Applicable and obeyed, got %+v", *notApplicable)
	}
	if len(result.AnalyzeWarnings) != 0 {
		t.Fatalf("no requirement was unmet, got warnings %v", result.AnalyzeWarnings)
	}
}

func TestPreflight_DefaultSelectedComponentIsSkippedWithADiagnostic(t *testing.T) {
	cases := []struct {
		name   string
		target func(*Registry, *PipelineRequest, *model.Graph)
		want   string
	}{
		{"SBOM document", sbomTarget, "the target is an SBOM document, not a source tree"},
		{"container image", func(_ *Registry, req *PipelineRequest, _ *model.Graph) {
			req.ExecutionTarget = ExecutionTarget{Kind: ExecutionTargetContainerImage, Location: "alpine:3.20"}
		}, "the target is a container image, not a source tree"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			graph := preflightGraph(t)
			registry, req := preflightScenario(t, graph)
			tc.target(registry, &req, graph)
			analyzer := &calls{}
			registry.RegisterAnalyzer(preflightAnalyzer{descriptor: plugin.AnalyzerDescriptor{Name: "reach", Requires: requires(plugin.RequirementSourceTree)}, applicable: true, calls: analyzer})
			req.AnalyzeReachabilityEnabled = true

			result, err := NewPipeline(registry, zap.NewNop()).Run(context.Background(), req)
			if err != nil {
				t.Fatalf("a default-selected component must not fail the run, got %v", err)
			}
			if *analyzer != (calls{}) {
				t.Fatalf("preflight must hold the component back before Ready, got %+v", *analyzer)
			}
			if len(result.AnalyzeWarnings) != 1 {
				t.Fatalf("expected one diagnostic, got %v", result.AnalyzeWarnings)
			}
			warning := result.AnalyzeWarnings[0]
			if warning.Source != "reach" || !strings.Contains(warning.Message, "requires source-tree-v1") || !strings.Contains(warning.Message, tc.want) {
				t.Fatalf("diagnostic must name the component, the requirement and what is missing, got %+v", warning)
			}
		})
	}
}

func TestPreflight_ExplicitlySelectedComponentFailsBeforeAnyStage(t *testing.T) {
	graph := preflightGraph(t)
	registry, req := preflightScenario(t, graph)
	sbomTarget(registry, &req, graph)
	detected := false
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{Name: "watch", SupportedEcosystems: []Ecosystem{EcosystemSBOM}, SupportedManagers: []PackageManager{PackageManagerSBOM}},
		onResolve:  func(ResolveGraphRequest) { detected = true },
	})
	req.Subprojects[0].PlannedDetectors = []string{"watch", "sbom-detector"}
	analyzer := &calls{}
	registry.RegisterAnalyzer(preflightAnalyzer{descriptor: plugin.AnalyzerDescriptor{Name: "reach", Requires: requires(plugin.RequirementSourceTree)}, applicable: true, calls: analyzer})
	req.AnalyzeReachabilityEnabled = true
	req.AnalyzerFilter = plugin.AnalyzerFilter{Include: []string{"reach"}}

	_, err := NewPipeline(registry, zap.NewNop()).Run(context.Background(), req)
	preflight, ok := errors.AsType[*PreflightError](err)
	if !ok {
		t.Fatalf("an explicitly selected component that can never run must fail the run, got %v", err)
	}
	if detected || *analyzer != (calls{}) {
		t.Fatalf("the plan must fail before any stage runs: detected=%v analyzer=%+v", detected, *analyzer)
	}
	want := PreflightIssue{
		Kind:        plugin.PluginKindAnalyzer,
		Component:   "reach",
		Stage:       StageAnalyze,
		Requirement: plugin.RequirementSourceTree,
		Explicit:    true,
		Satisfy:     "the target is an SBOM document, not a source tree; scan a directory with --path or a Git repository with --url",
	}
	if len(preflight.Issues) != 1 || preflight.Issues[0] != want {
		t.Fatalf("issues = %+v, want [%+v]", preflight.Issues, want)
	}
}

func TestPreflight_UnknownRequirementIsNeverSatisfied(t *testing.T) {
	// A token shaped like a provider is still only an unknown token: the
	// vocabulary has no way to name a component, so a matcher with that name
	// running earlier does not satisfy it.
	for _, token := range []plugin.Requirement{"package-update-deltas-v9", "osv-matcher-v1"} {
		t.Run(string(token), func(t *testing.T) {
			registry, req := preflightScenario(t, preflightGraph(t))
			registry.registerMatcher(preflightMatcher{descriptor: plugin.MatcherDescriptor{Name: "osv-matcher"}, vulnerabilities: true, calls: &calls{}})
			auditor := &calls{}
			registry.registerAuditor(preflightAuditor{descriptor: plugin.AuditorDescriptor{Name: "future", Requires: requires(token)}, calls: auditor})
			req.EnrichEnabled, req.AuditEnabled = true, true

			result, err := NewPipeline(registry, zap.NewNop()).Run(context.Background(), req)
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if *auditor != (calls{}) {
				t.Fatalf("an unknown requirement must hold the component back, got %+v", *auditor)
			}
			if len(result.AuditWarnings) == 0 || !strings.Contains(result.AuditWarnings[0].Message, "does not know this requirement") {
				t.Fatalf("expected an unsupported-requirement diagnostic, got %v", result.AuditWarnings)
			}

			req.AuditorFilter = plugin.AuditorFilter{Include: []string{"future"}}
			_, err = NewPipeline(registry, zap.NewNop()).Run(context.Background(), req)
			if _, ok := errors.AsType[*PreflightError](err); !ok {
				t.Fatalf("an explicitly selected component with an unknown requirement must fail, got %v", err)
			}
		})
	}
}

func TestPreflight_StageDataRequirementsSkipWhateverTheSelection(t *testing.T) {
	// A requirement the plan could meet but this input did not -- no
	// vulnerability was found, no dependency was detected -- skips the
	// component even when the user named it: nothing in the command would
	// make it run on this input.
	cases := []struct {
		name   string
		enrich bool
		want   string
	}{
		{"no matcher ran", false, "no matcher ran; add --enrich"},
		{"matchers found nothing", true, "no package carries a vulnerability record"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			registry, req := preflightScenario(t, preflightGraph(t))
			registry.registerMatcher(preflightMatcher{descriptor: plugin.MatcherDescriptor{Name: "license-matcher"}, calls: &calls{}})
			analyzer := &calls{}
			registry.RegisterAnalyzer(preflightAnalyzer{descriptor: plugin.AnalyzerDescriptor{Name: "reach", Requires: requires(plugin.RequirementVulnerabilityRecords)}, applicable: true, calls: analyzer})
			req.EnrichEnabled, req.AnalyzeReachabilityEnabled = tc.enrich, true
			req.AnalyzerFilter = plugin.AnalyzerFilter{Include: []string{"reach"}}

			result, err := NewPipeline(registry, zap.NewNop()).Run(context.Background(), req)
			if err != nil {
				t.Fatalf("a data-dependent requirement must not fail the plan, got %v", err)
			}
			if *analyzer != (calls{}) {
				t.Fatalf("analyzer must be held back, got %+v", *analyzer)
			}
			if len(result.AnalyzeWarnings) != 1 || !strings.Contains(result.AnalyzeWarnings[0].Message, tc.want) {
				t.Fatalf("expected %q, got %v", tc.want, result.AnalyzeWarnings)
			}
		})
	}
}

func TestPreflight_DependencyGraphIsCheckedAgainstTheGraphTheStageReceives(t *testing.T) {
	// Only the project's own module: a graph, but no dependency in it.
	moduleOnly := model.New()
	if err := moduleOnly.AddNode(testnodes.Module("package.json", "app", "1.0.0")); err != nil {
		t.Fatalf("add module: %v", err)
	}
	registry, req := preflightScenario(t, moduleOnly)
	auditor := &calls{}
	registry.registerAuditor(preflightAuditor{descriptor: plugin.AuditorDescriptor{Name: "graph-auditor", Requires: requires(plugin.RequirementDependencyGraph)}, calls: auditor})
	req.AuditEnabled = true

	result, err := NewPipeline(registry, zap.NewNop()).Run(context.Background(), req)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if *auditor != (calls{}) {
		t.Fatalf("an auditor requiring a dependency graph must not run on a graph with no dependency, got %+v", *auditor)
	}
	if len(result.AuditWarnings) == 0 || !strings.Contains(result.AuditWarnings[0].Message, "detection found no dependencies") {
		t.Fatalf("expected a no-dependency diagnostic, got %v", result.AuditWarnings)
	}
}

func TestPreflight_DetectorsCannotRequireWhatLaterStagesProduce(t *testing.T) {
	for _, token := range []plugin.Requirement{plugin.RequirementDependencyGraph, plugin.RequirementVulnerabilityRecords} {
		t.Run(string(token), func(t *testing.T) {
			graph := preflightGraph(t)
			registry := newTestRegistry()
			resolved := false
			registry.registerDetector(fakeDetector{
				descriptor: DetectorDescriptor{Name: "needy", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}, Requires: requires(token)},
				onResolve:  func(ResolveGraphRequest) { resolved = true },
			})
			registry.registerDetector(fakeDetector{
				descriptor: DetectorDescriptor{Name: "npm-detector", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
				result:     ResolveGraphResult{Graphs: SingleGraphContainer(graph, model.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"})},
			})
			target := ExecutionTarget{Kind: ExecutionTargetFilesystem, Location: "/repo"}
			req := PipelineRequest{ExecutionTarget: target, Subprojects: []Subproject{{
				ExecutionTarget:         target,
				RelativePath:            ".",
				PlannedDetectors:        []string{"needy", "npm-detector"},
				DetectedPackageManagers: []PackageManager{PackageManagerNPM},
				Ecosystem:               EcosystemNPM,
			}}}

			result, err := NewPipeline(registry, zap.NewNop()).Run(context.Background(), req)
			if err != nil {
				t.Fatalf("a default detector must be skipped, not fail the run: %v", err)
			}
			if resolved {
				t.Fatal("preflight must hold the detector back before it resolves")
			}
			if len(result.ResolveResults) != 1 || result.ResolveResults[0].DetectorName != "npm-detector" {
				t.Fatalf("the next link of the chain must resolve the subproject, got %+v", result.ResolveResults)
			}
			var found bool
			for _, warning := range result.DetectorWarnings {
				if warning.Source == "needy" && warning.DegradesCoverage() && strings.Contains(warning.Message, "requires "+string(token)) {
					found = true
				}
			}
			if !found {
				t.Fatalf("expected a coverage-degrading detector diagnostic, got %+v", result.DetectorWarnings)
			}

			req.DetectorFilter = plugin.DetectorFilter{Include: []string{"needy", "npm-detector"}}
			if _, err := NewPipeline(registry, zap.NewNop()).Run(context.Background(), req); err == nil {
				t.Fatal("an explicitly selected detector with an impossible requirement must fail the run")
			}
		})
	}
}

func TestPreflight_EmptyRegistryPlansNothing(t *testing.T) {
	pipeline := NewPipeline(newTestRegistry(), zap.NewNop())
	req := PipelineRequest{EnrichEnabled: true, AnalyzeReachabilityEnabled: true, AuditEnabled: true}
	if err := pipeline.preflightPlan(req); err != nil {
		t.Fatalf("an empty registry has nothing to reject, got %v", err)
	}
	for _, stage := range plannedStages(req) {
		stagePipeline, issues := pipeline.preflightStage(stage, req, nil, nil)
		if stagePipeline != pipeline || len(issues) != 0 {
			t.Fatalf("stage %s: nothing to hold back, got %v", stage, issues)
		}
	}
}

func TestPreflight_HostVouchesOnlyForWhatEachStageHas(t *testing.T) {
	sourceTree := targetShape{sourceTree: true}
	cases := []struct {
		facts preflightFacts
		want  []plugin.Requirement
	}{
		{preflightFacts{stage: StageDetect, planning: true, target: sourceTree}, []plugin.Requirement{plugin.RequirementSourceTree}},
		{preflightFacts{stage: StageMatch, planning: true, target: sourceTree}, []plugin.Requirement{plugin.RequirementSourceTree, plugin.RequirementDependencyGraph}},
		{preflightFacts{stage: StageAnalyze, planning: true}, []plugin.Requirement{plugin.RequirementDependencyGraph, plugin.RequirementVulnerabilityRecords}},
		{preflightFacts{stage: StageAudit}, nil},
		{preflightFacts{stage: StageAudit, dependencyNodes: true, vulnerabilityRecords: true}, []plugin.Requirement{plugin.RequirementDependencyGraph, plugin.RequirementVulnerabilityRecords}},
		{preflightFacts{stage: StageMatch, dependencyNodes: true, vulnerabilityRecords: true}, []plugin.Requirement{plugin.RequirementDependencyGraph}},
	}
	for _, tc := range cases {
		got := tc.facts.available()
		if len(got) != len(tc.want) {
			t.Errorf("%+v: available = %v, want %v", tc.facts, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%+v: available = %v, want %v", tc.facts, got, tc.want)
			}
		}
		for _, requirement := range got {
			if !requirement.Known() {
				t.Errorf("the host must only vouch for SDK-known requirements, got %q", requirement)
			}
		}
	}
}

func TestPreflight_ExplicitSelectionFollowsTheSelectorGrammar(t *testing.T) {
	includes := func(names ...string) func(string) bool {
		return func(name string) bool { return plugin.MatcherFilter{Include: names}.Includes(name) }
	}
	cases := []struct {
		name           string
		include        []string
		exclude        []string
		defaultEnabled bool
		want           bool
	}{
		{"no selector: the default set", nil, nil, true, false},
		{"named in a plain list", []string{"osv"}, nil, true, true},
		{"another component named in a plain list", []string{"grype"}, nil, false, false},
		{"default-off component added with +name", nil, []string{"scorecard"}, false, true},
		{"default-on component repeated with +name", nil, []string{"scorecard"}, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := selectedExplicitly(tc.include, tc.exclude, includes(tc.include...), "osv", tc.defaultEnabled); got != tc.want {
				t.Fatalf("selectedExplicitly = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPreflight_OperatorSelectedDefaultOffComponentIsExplicit(t *testing.T) {
	graph := preflightGraph(t)
	registry, req := preflightScenario(t, graph)
	sbomTarget(registry, &req, graph)
	registry.RegisterMatcherWithOptions(preflightMatcher{
		descriptor: plugin.MatcherDescriptor{Name: "opt-in", Requires: requires(plugin.RequirementSourceTree)},
		calls:      &calls{},
	}, ComponentOptions{DefaultEnabled: false})
	registry.registerMatcher(preflightMatcher{descriptor: plugin.MatcherDescriptor{Name: "default-on"}, calls: &calls{}})
	req.EnrichEnabled = true
	// What "--matchers +opt-in" resolves to when one other matcher is
	// registered and left in: an exclude-only filter.
	req.MatcherFilter = plugin.MatcherFilter{Exclude: []string{"unrelated"}}

	_, err := NewPipeline(registry, zap.NewNop()).Run(context.Background(), req)
	preflight, ok := errors.AsType[*PreflightError](err)
	if !ok || len(preflight.Issues) != 1 || preflight.Issues[0].Component != "opt-in" {
		t.Fatalf("a default-off component added with +name is the user's explicit choice, got %v", err)
	}
}
