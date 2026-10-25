package engine

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/testnodes"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

type fakeDetector struct {
	descriptor  DetectorDescriptor
	result      ResolveGraphResult
	err         error
	ready       *bool
	readyReason string
	applicable  *bool
	applyErr    error
	onResolve   func(ResolveGraphRequest)
}

func (f fakeDetector) Descriptor() DetectorDescriptor { return f.descriptor }

func (f fakeDetector) PackageManagerSupport() []plugin.PackageManagerSupport {
	values := make([]plugin.PackageManagerSupport, 0, len(f.descriptor.SupportedManagers))
	for _, manager := range f.descriptor.SupportedManagers {
		values = append(values, plugin.Support(manager))
	}
	return values
}

func (f fakeDetector) ResolveGraph(_ context.Context, req ResolveGraphRequest) (ResolveGraphResult, error) {
	if f.onResolve != nil {
		f.onResolve(req)
	}
	return f.result, f.err
}

func (f fakeDetector) Ready(context.Context, ResolveGraphRequest) error {
	if f.ready != nil && !*f.ready {
		if f.readyReason != "" {
			return errors.New(f.readyReason)
		}
		return errors.New("not ready")
	}
	return nil
}

func (f fakeDetector) Applicable(_ context.Context, _ ResolveGraphRequest) (bool, error) {
	if f.applyErr != nil {
		return false, f.applyErr
	}
	if f.applicable == nil {
		return true, nil
	}
	return *f.applicable, nil
}

type fakeInstallFirstDetector struct {
	fakeDetector
	installed bool
	onInstall func(ResolveGraphRequest)
}

func (f *fakeInstallFirstDetector) Install(_ context.Context, req ResolveGraphRequest) error {
	f.installed = true
	if f.onInstall != nil {
		f.onInstall(req)
	}
	return nil
}

type fakeAuditor struct {
	descriptor   AuditorDescriptor
	result       AuditResult
	err          error
	ready        *bool
	applicable   *bool
	applyErr     error
	run          func(AuditRequest) AuditResult
	onReady      func(AuditRequest)
	onApplicable func(AuditRequest)
}

func (f fakeAuditor) Descriptor() AuditorDescriptor { return f.descriptor }

func (f fakeAuditor) Audit(_ context.Context, req AuditRequest) (AuditResult, error) {
	if f.run != nil {
		return f.run(req), f.err
	}
	return f.result, f.err
}

func (f fakeAuditor) Ready(_ context.Context, req AuditRequest) error {
	if f.onReady != nil {
		f.onReady(req)
	}
	if f.ready != nil && !*f.ready {
		return errors.New("not ready")
	}
	return nil
}

func (f fakeAuditor) Applicable(_ context.Context, req AuditRequest) (bool, error) {
	if f.onApplicable != nil {
		f.onApplicable(req)
	}
	if f.applyErr != nil {
		return false, f.applyErr
	}
	if f.applicable == nil {
		return true, nil
	}
	return *f.applicable, nil
}

func TestEngineAudit_AggregatesAuditorResults(t *testing.T) {
	registry := newTestRegistry()
	registry.registerAuditor(fakeAuditor{
		descriptor: AuditorDescriptor{Name: "a", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
		result:     AuditResult{Findings: []Finding{{ID: "1"}}},
	})
	registry.registerAuditor(fakeAuditor{
		descriptor: AuditorDescriptor{Name: "b", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
		result:     AuditResult{Findings: []Finding{{ID: "2"}}, RiskScores: []RiskScore{{Score: 50}}},
	})

	engine := NewEngine(registry)
	result, err := engine.Audit(context.Background(), AuditRequest{Ecosystem: EcosystemNPM, PackageManager: PackageManagerNPM})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if len(result.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(result.Findings))
	}
	if len(result.RiskScores) != 1 {
		t.Fatalf("expected 1 risk score, got %d", len(result.RiskScores))
	}
}

func TestEngineAudit_ReturnsPartialResultsWhenAnAuditorFails(t *testing.T) {
	registry := newTestRegistry()
	registry.registerAuditor(fakeAuditor{
		descriptor: AuditorDescriptor{Name: "working", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
		result:     AuditResult{Findings: []Finding{{ID: "1"}}},
	})
	registry.registerAuditor(fakeAuditor{
		descriptor: AuditorDescriptor{Name: "broken", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
		err:        errors.New("boom"),
	})

	engine := NewEngine(registry)
	result, err := engine.Audit(context.Background(), AuditRequest{Ecosystem: EcosystemNPM, PackageManager: PackageManagerNPM})
	if err == nil {
		t.Fatal("expected joined error")
	}
	if len(result.Findings) != 1 || result.Findings[0].ID != "1" {
		t.Fatalf("expected partial findings to be preserved, got %#v", result.Findings)
	}
}

func TestEngineAudit_ClonesDependencyDetailChangesPerAuditor(t *testing.T) {
	// Named coordinates, because a node's identity is minted from them and a
	// nameless one has no package URL to mint (ADR-0041).
	coords := model.Coordinates{Ecosystem: model.EcosystemNPM, Name: "example", Version: "1.0.0"}
	before := testnodes.DepFrom(model.DependencyNode{Coordinates: coords, Source: model.DependencySourceRegistry})
	after := testnodes.DepFrom(model.DependencyNode{Coordinates: coords, Source: model.DependencySourceGit})
	request := AuditRequest{
		Ecosystem:      EcosystemNPM,
		PackageManager: PackageManagerNPM,
		DependencyDetailChanges: []model.DependencyDetailTransition{{
			Before:        before,
			After:         after,
			ChangedFields: []model.DependencyDetailField{model.DependencyDetailSource},
		}},
	}
	assertOriginal := func(phase string, req AuditRequest) {
		t.Helper()
		if req.DependencyDetailChanges[0].After.Source != model.DependencySourceGit ||
			req.DependencyDetailChanges[0].ChangedFields[0] != model.DependencyDetailSource {
			t.Fatalf("%s observed mutated request: %#v", phase, req.DependencyDetailChanges)
		}
	}
	mutate := func(req AuditRequest) {
		req.DependencyDetailChanges[0].After.Source = model.DependencySourceURL
		req.DependencyDetailChanges[0].ChangedFields[0] = model.DependencyDetailRelationship
	}
	registry := newTestRegistry()
	registry.registerAuditor(fakeAuditor{
		descriptor: AuditorDescriptor{Name: "mutating", SupportedEcosystems: []Ecosystem{EcosystemNPM}},
		onReady:    mutate,
		onApplicable: func(req AuditRequest) {
			assertOriginal("mutating auditor Applicable", req)
			mutate(req)
		},
		run: func(req AuditRequest) AuditResult {
			assertOriginal("mutating auditor Audit", req)
			mutate(req)
			return AuditResult{}
		},
	})
	registry.registerAuditor(fakeAuditor{
		descriptor: AuditorDescriptor{Name: "observing", SupportedEcosystems: []Ecosystem{EcosystemNPM}},
		onReady: func(req AuditRequest) {
			assertOriginal("observing auditor Ready", req)
		},
		onApplicable: func(req AuditRequest) {
			assertOriginal("observing auditor Applicable", req)
		},
		run: func(req AuditRequest) AuditResult {
			assertOriginal("observing auditor Audit", req)
			return AuditResult{}
		},
	})

	if _, err := NewEngine(registry).Audit(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	assertOriginal("caller", request)
}

func TestEngineAudit_SkipsNotReadyOrNotApplicableAuditors(t *testing.T) {
	registry := newTestRegistry()
	registry.registerAuditor(fakeAuditor{
		descriptor: AuditorDescriptor{Name: "not-ready", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
		ready:      new(false),
	})
	registry.registerAuditor(fakeAuditor{
		descriptor: AuditorDescriptor{Name: "not-applicable", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
		applicable: new(false),
	})
	registry.registerAuditor(fakeAuditor{
		descriptor: AuditorDescriptor{Name: "usable", SupportedEcosystems: []Ecosystem{EcosystemNPM}, SupportedManagers: []PackageManager{PackageManagerNPM}},
		result:     AuditResult{Findings: []Finding{{ID: "1"}}},
	})

	engine := NewEngine(registry)
	result, err := engine.Audit(context.Background(), AuditRequest{Ecosystem: EcosystemNPM, PackageManager: PackageManagerNPM})
	if err == nil {
		t.Fatal("expected joined error for skipped auditors")
	}
	if len(result.Findings) != 1 || result.Findings[0].ID != "1" {
		t.Fatalf("expected applicable ready auditor result, got %#v", result.Findings)
	}
}

// --- Transactional component calls ------------------------------------------

// wireCopy round-trips v through JSON into out, which is what the managed
// transport does to every request and result.
func wireCopy(t *testing.T, v, out any) {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("encode for the wire: %v", err)
	}
	if err := json.Unmarshal(data, out); err != nil {
		t.Fatalf("decode off the wire: %v", err)
	}
}

// wireMatcher runs a matcher as a managed plugin sees the world: each request
// arrives as a copy, and the result leaves as one.
type wireMatcher struct {
	t     *testing.T
	inner plugin.Matcher
}

func (w wireMatcher) Descriptor() MatcherDescriptor { return w.inner.Descriptor() }

func (w wireMatcher) Ready(ctx context.Context, req MatchRequest) error {
	var copied MatchRequest
	wireCopy(w.t, req, &copied)
	return w.inner.Ready(ctx, copied)
}

func (w wireMatcher) Applicable(ctx context.Context, req MatchRequest) (bool, error) {
	var copied MatchRequest
	wireCopy(w.t, req, &copied)
	return w.inner.Applicable(ctx, copied)
}

func (w wireMatcher) Match(ctx context.Context, req MatchRequest) (plugin.MatchResult, error) {
	var copied MatchRequest
	wireCopy(w.t, req, &copied)
	result, err := w.inner.Match(ctx, copied)
	if err != nil {
		return plugin.MatchResult{}, err
	}
	var returned plugin.MatchResult
	wireCopy(w.t, result, &returned)
	return returned, nil
}

// wireAnalyzer is wireMatcher's analyzer twin.
type wireAnalyzer struct {
	t     *testing.T
	inner plugin.Analyzer
}

func (w wireAnalyzer) Descriptor() plugin.AnalyzerDescriptor { return w.inner.Descriptor() }

func (w wireAnalyzer) Ready(ctx context.Context, req plugin.AnalyzeRequest) error {
	var copied plugin.AnalyzeRequest
	wireCopy(w.t, req, &copied)
	return w.inner.Ready(ctx, copied)
}

func (w wireAnalyzer) Applicable(ctx context.Context, req plugin.AnalyzeRequest) (bool, error) {
	var copied plugin.AnalyzeRequest
	wireCopy(w.t, req, &copied)
	return w.inner.Applicable(ctx, copied)
}

func (w wireAnalyzer) Analyze(ctx context.Context, req plugin.AnalyzeRequest) (plugin.AnalyzeResult, error) {
	var copied plugin.AnalyzeRequest
	wireCopy(w.t, req, &copied)
	result, err := w.inner.Analyze(ctx, copied)
	if err != nil {
		return plugin.AnalyzeResult{}, err
	}
	var returned plugin.AnalyzeResult
	wireCopy(w.t, result, &returned)
	return returned, nil
}

const (
	txPURL      = "pkg:npm/tx-target@1.0.0"
	txOtherPURL = "pkg:npm/tx-other@1.0.0"
)

// txState is the canonical host state a component call must leave alone
// unless it succeeds: the registry, the graph and the target.
type txState struct {
	graph    *model.Graph
	registry *model.PackageRegistry
	target   *model.DependencyNode
}

func newTxState(t *testing.T) txState {
	t.Helper()
	graph := model.New()
	target := matchTestDependency("tx-target", "1.0.0", "", model.DependencySourceRegistry)
	target.Metadata = map[string]any{"seed": "kept"}
	other := matchTestDependency("tx-other", "1.0.0", "", model.DependencySourceRegistry)
	for _, node := range []model.GraphNode{target, other} {
		if err := graph.AddNode(node); err != nil {
			t.Fatal(err)
		}
	}
	if err := graph.AddEdge(target.NodeID(), other.NodeID()); err != nil {
		t.Fatal(err)
	}
	registry := model.NewPackageRegistry()
	registry.Add(&model.Package{
		Coordinates:     model.Coordinates{PURL: txPURL, Ecosystem: model.EcosystemNPM, Name: "tx-target", Version: "1.0.0"},
		Vulnerabilities: []model.Vulnerability{{Source: "osv", ID: "GHSA-seed-seed-seed"}},
		Metadata:        map[string]any{"seed": map[string]any{"nested": []any{"kept"}}},
	})
	registry.Add(&model.Package{Coordinates: model.Coordinates{PURL: txOtherPURL, Ecosystem: model.EcosystemNPM, Name: "tx-other", Version: "1.0.0"}})
	return txState{graph: graph, registry: registry, target: target}
}

// encoded is the state no component call may commit to: the graph and the
// target. The registry is where successful calls commit, so it is checked
// for the failure's marks instead.
func (s txState) encoded(t *testing.T) string {
	t.Helper()
	data, err := json.Marshal(map[string]any{"graph": s.graph, "target": s.target})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// mutateEverything is what a careless component does to its request: it
// rewrites a package, its nested advisories and metadata, the graph, and
// the target in place.
func mutateEverything(graph *model.Graph, registry *model.PackageRegistry, target *model.DependencyNode) {
	if pkg, ok := registry.Get(txPURL); ok {
		pkg.Matched = true
		pkg.Vulnerabilities[0].ID = "GHSA-leak-leak-leak"
		pkg.Vulnerabilities = append(pkg.Vulnerabilities, model.Vulnerability{Source: "osv", ID: "GHSA-half-done-yet"})
		pkg.Metadata["seed"].(map[string]any)["nested"] = []any{"leaked"}
	}
	registry.Ensure("pkg:npm/leaked@1.0.0")
	if graph != nil {
		graph.RemoveNode(txOtherPURL)
	}
	if target != nil {
		target.Metadata["seed"] = "leaked"
	}
}

// assertNoFailureMarks fails on any trace mutateEverything leaves in a
// registry: every one of its changes is distinguishable from committed work.
func assertNoFailureMarks(t *testing.T, registry *model.PackageRegistry) {
	t.Helper()
	if _, leaked := registry.Get("pkg:npm/leaked@1.0.0"); leaked {
		t.Error("a failed call's new package reached the registry")
	}
	pkg, _ := registry.Get(txPURL)
	if pkg.Matched {
		t.Error("a failed call's flag reached the registry")
	}
	for _, v := range pkg.Vulnerabilities {
		if v.ID == "GHSA-leak-leak-leak" || v.ID == "GHSA-half-done-yet" {
			t.Errorf("a failed call's advisory %s reached the registry", v.ID)
		}
	}
	if nested := pkg.Metadata["seed"].(map[string]any)["nested"].([]any); nested[0] != "kept" {
		t.Error("a failed call's nested metadata change reached the registry")
	}
}

// TestEngineMatchCommitsOnlySuccessfulCalls runs one pipeline through
// three matchers -- one that enriches by delta, one that mutates every
// class of request data and then fails, one that returns a full registry
// alongside deltas -- embedded and over a simulated wire, and requires the
// same canonical outcome both ways: earlier success kept, the failure
// leaving no trace, the full registry winning over its own deltas, nothing
// applied twice, and the graph and target untouched.
func TestEngineMatchCommitsOnlySuccessfulCalls(t *testing.T) {
	matchers := []plugin.Matcher{
		deltaMatcher{name: "enricher", match: func(MatchRequest) (plugin.MatchResult, error) {
			return plugin.MatchResult{PackageUpdates: []*model.Package{{
				Coordinates:     model.Coordinates{PURL: txPURL},
				Vulnerabilities: []model.Vulnerability{{Source: "osv", ID: "GHSA-from-enricher"}},
			}}}, nil
		}},
		deltaMatcher{name: "careless", match: func(req MatchRequest) (plugin.MatchResult, error) {
			mutateEverything(req.Graph, req.Registry, req.Target)
			return plugin.MatchResult{}, errors.New("upstream timed out")
		}},
		deltaMatcher{name: "full-registry", match: func(req MatchRequest) (plugin.MatchResult, error) {
			pkg, _ := req.Registry.Get(txOtherPURL)
			pkg.Licenses = []model.PackageLicense{{Value: "MIT", SPDXExpression: "MIT", Type: model.LicenseTypeDeclared}}
			return plugin.MatchResult{
				Registry: req.Registry,
				PackageUpdates: []*model.Package{{
					Coordinates:     model.Coordinates{PURL: txPURL},
					Vulnerabilities: []model.Vulnerability{{Source: "osv", ID: "GHSA-ignored-delta"}},
				}},
			}, nil
		}},
	}
	run := func(t *testing.T, wrap func(plugin.Matcher) plugin.Matcher) (string, txState) {
		t.Helper()
		state := newTxState(t)
		components := newTestRegistry()
		for _, matcher := range matchers {
			components.registerMatcher(wrap(matcher))
		}
		before := state.encoded(t)
		result, err := NewEngine(components).Match(context.Background(), plugin.MatchRequest{Graph: state.graph, Registry: state.registry, Target: state.target})
		if err == nil || !strings.Contains(err.Error(), "matcher careless: upstream timed out") {
			t.Fatalf("Match error = %v, want the careless matcher's failure", err)
		}
		if after := state.encoded(t); after != before {
			t.Fatalf("the host's graph or target was changed in place:\nbefore %s\nafter  %s", before, after)
		}
		assertNoFailureMarks(t, state.registry)
		pkg, _ := result.Registry.Get(txPURL)
		var ids []string
		for _, v := range pkg.Vulnerabilities {
			ids = append(ids, v.ID)
		}
		slices.Sort(ids)
		if want := []string{"GHSA-from-enricher", "GHSA-seed-seed-seed"}; !slices.Equal(ids, want) {
			t.Errorf("advisories = %v, want %v: the earlier success kept once, the failure and the ignored delta absent", ids, want)
		}
		if _, leaked := result.Registry.Get("pkg:npm/leaked@1.0.0"); leaked || pkg.Matched {
			t.Error("the failed matcher's changes reached the result")
		}
		other, _ := result.Registry.Get(txOtherPURL)
		if len(other.Licenses) != 1 {
			t.Errorf("the full-registry matcher's license was not committed: %v", other.Licenses)
		}
		data, err := json.Marshal(result.Registry)
		if err != nil {
			t.Fatal(err)
		}
		return string(data), state
	}
	embedded, _ := run(t, func(m plugin.Matcher) plugin.Matcher { return m })
	managed, _ := run(t, func(m plugin.Matcher) plugin.Matcher { return wireMatcher{t: t, inner: m} })
	if embedded != managed {
		t.Errorf("embedded and managed execution disagree:\nembedded %s\nmanaged  %s", embedded, managed)
	}
}

// TestEngineAnalyzeCommitsOnlySuccessfulCalls is the analyzer twin.
func TestEngineAnalyzeCommitsOnlySuccessfulCalls(t *testing.T) {
	reachable := &model.Reachability{Status: model.ReachabilityReachable}
	analyzers := []plugin.Analyzer{
		deltaAnalyzer{name: "careless", analyze: func(req plugin.AnalyzeRequest) (plugin.AnalyzeResult, error) {
			mutateEverything(req.Graph, req.Registry, req.Target)
			return plugin.AnalyzeResult{}, errors.New("toolchain missing")
		}},
		deltaAnalyzer{name: "reach", analyze: func(req plugin.AnalyzeRequest) (plugin.AnalyzeResult, error) {
			pkg, _ := req.Registry.Get(txPURL)
			update := pkg.Clone()
			update.Vulnerabilities[0].Reachability = reachable.Clone()
			return plugin.AnalyzeResult{PackageUpdates: []*model.Package{update}}, nil
		}},
	}
	run := func(t *testing.T, wrap func(plugin.Analyzer) plugin.Analyzer) string {
		t.Helper()
		state := newTxState(t)
		components := newTestRegistry()
		for _, analyzer := range analyzers {
			components.RegisterAnalyzer(wrap(analyzer))
		}
		before := state.encoded(t)
		result, err := NewEngine(components).Analyze(context.Background(), plugin.AnalyzeRequest{Graph: state.graph, Registry: state.registry, Target: state.target})
		if err == nil || !strings.Contains(err.Error(), "analyzer careless: toolchain missing") {
			t.Fatalf("Analyze error = %v, want the careless analyzer's failure", err)
		}
		if after := state.encoded(t); after != before {
			t.Fatalf("the host's graph or target was changed in place:\nbefore %s\nafter  %s", before, after)
		}
		assertNoFailureMarks(t, state.registry)
		assertNoFailureMarks(t, result.Registry)
		pkg, _ := result.Registry.Get(txPURL)
		if len(pkg.Vulnerabilities) != 1 || pkg.Vulnerabilities[0].ID != "GHSA-seed-seed-seed" || pkg.Vulnerabilities[0].Reachability == nil {
			t.Errorf("want the seed advisory annotated by the later success and nothing from the failure, got %+v", pkg.Vulnerabilities)
		}
		data, err := json.Marshal(result.Registry)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	embedded := run(t, func(a plugin.Analyzer) plugin.Analyzer { return a })
	managed := run(t, func(a plugin.Analyzer) plugin.Analyzer { return wireAnalyzer{t: t, inner: a} })
	if embedded != managed {
		t.Errorf("embedded and managed execution disagree:\nembedded %s\nmanaged  %s", embedded, managed)
	}
}

// TestEngineMatchDiscardsWorkFinishedAfterCancellation: a matcher that
// returns success after the command was cancelled has its result discarded,
// since a component that ignored its context may have returned partial work.
func TestEngineMatchDiscardsWorkFinishedAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	state := newTxState(t)
	components := newTestRegistry()
	components.registerMatcher(deltaMatcher{name: "ignores-context", match: func(req MatchRequest) (plugin.MatchResult, error) {
		cancel()
		mutateEverything(req.Graph, req.Registry, req.Target)
		return plugin.MatchResult{Registry: req.Registry}, nil
	}})
	before := state.encoded(t)
	result, err := NewEngine(components).Match(ctx, plugin.MatchRequest{Graph: state.graph, Registry: state.registry, Target: state.target})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Match error = %v, want the cancellation", err)
	}
	if _, leaked := result.Registry.Get("pkg:npm/leaked@1.0.0"); leaked {
		t.Error("work finished after cancellation was committed")
	}
	if after := state.encoded(t); after != before {
		t.Error("the host's graph or target was changed in place")
	}
	assertNoFailureMarks(t, state.registry)
}
