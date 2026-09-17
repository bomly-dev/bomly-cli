package diff

import (
	"context"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/auditors/license"
	"github.com/bomly-dev/bomly-cli/internal/engine"
	"github.com/bomly-dev/bomly-cli/internal/testnodes"
	"go.uber.org/zap"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

func TestRun_SkipsAuditFindingsWhenNoDependencyChanges(t *testing.T) {
	react := npmPackage("react", "18.2.0")
	base := diffTestPipeline(t, graphFixture(t, react), map[string][]model.Finding{
		react.NodeID(): {{ID: "CVE-UNCHANGED", Kind: model.FindingKindVulnerability, Source: "osv"}},
	})
	head := diffTestPipeline(t, graphFixture(t, react.Clone()), map[string][]model.Finding{
		react.NodeID(): {{ID: "CVE-UNCHANGED", Kind: model.FindingKindVulnerability, Source: "osv"}},
	})

	result, err := Run(context.Background(), Request{
		Base: Target{Pipeline: base, Request: diffTestRequest()},
		Head: Target{Pipeline: head, Request: diffTestRequest()},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	assertFindingIDs(t, result.Audit.Introduced)
	assertFindingIDs(t, result.Audit.Persisted)
	assertFindingIDs(t, result.Audit.Resolved)
}

func TestRun_ReportsAddedPackageFindingAsIntroduced(t *testing.T) {
	react := npmPackage("react", "18.2.0")
	base := diffTestPipeline(t, graphFixture(t), nil)
	head := diffTestPipeline(t, graphFixture(t, react), map[string][]model.Finding{
		react.NodeID(): {{ID: "CVE-ADDED", Kind: model.FindingKindVulnerability, Source: "osv"}},
	})

	result, err := Run(context.Background(), Request{
		Base: Target{Pipeline: base, Request: diffTestRequest()},
		Head: Target{Pipeline: head, Request: diffTestRequest()},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	assertFindingIDs(t, result.Audit.Introduced, "CVE-ADDED")
	assertFindingIDs(t, result.Audit.Resolved)
	assertFindingIDs(t, result.Audit.Persisted)
}

func TestRun_PassesCanonicalDetailChangesOnlyToHeadAudit(t *testing.T) {
	baseDependency := npmPackage("example", "1.0.0")
	baseDependency.Source = model.DependencySourceRegistry
	headDependency := baseDependency.Clone()
	headDependency.Source = model.DependencySourceGit

	pipeline := func(graph *model.Graph) *engine.Pipeline {
		registry := engine.NewRegistry(engine.RegistryConfigs{}, *zap.NewNop())
		registry.RegisterDetector(fakeDetector{
			descriptor: detectorDescriptor(),
			result: plugin.DetectionResult{
				Graphs: engine.SingleGraphContainer(graph, model.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"}),
			},
		})
		registry.RegisterAuditor(fakeAuditor{
			descriptor:    plugin.AuditorDescriptor{Name: "detail-policy"},
			detailFinding: true,
		})
		return engine.NewPipeline(registry, zap.NewNop())
	}

	result, err := Run(context.Background(), Request{
		Base: Target{Pipeline: pipeline(graphFixture(t, baseDependency)), Request: diffTestRequest()},
		Head: Target{Pipeline: pipeline(graphFixture(t, headDependency)), Request: diffTestRequest()},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertFindingIDs(t, result.Audit.Introduced, "detail-policy")
	assertFindingIDs(t, result.Audit.Persisted)
	assertFindingIDs(t, result.Audit.Resolved)
}

func TestRun_AppliesEachSidesAuditPolicyStatusResolvers(t *testing.T) {
	react := npmPackage("react", "18.2.0")
	base := diffTestPipeline(t, graphFixture(t), nil)
	head := diffTestPipeline(t, graphFixture(t, react), map[string][]model.Finding{
		react.NodeID(): {{ID: "CVE-ADDED", Kind: model.FindingKindVulnerability, Source: "osv", PolicyStatus: model.FindingPolicyStatusFail}},
	})
	headRequest := diffTestRequest()
	headRequest.FindingPolicyResolvers = []model.FindingPolicyResolver{diffPolicyResolver{}}
	result, err := Run(context.Background(), Request{
		Base: Target{Pipeline: base, Request: diffTestRequest()},
		Head: Target{Pipeline: head, Request: headRequest},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Audit.Introduced) != 1 || result.Audit.Introduced[0].PolicyStatus != model.FindingPolicyStatusSuppressed {
		t.Fatalf("introduced findings = %#v", result.Audit.Introduced)
	}
}

type diffPolicyResolver struct{}

func (diffPolicyResolver) ResolveFindingPolicy(context.Context, model.Finding, *model.PackageRegistry) (model.FindingPolicyDecision, bool) {
	return model.FindingPolicyDecision{Status: model.FindingPolicyStatusSuppressed, Source: "test"}, true
}

func TestRun_ReportsRemovedPackageFindingAsResolved(t *testing.T) {
	react := npmPackage("react", "18.2.0")
	base := diffTestPipeline(t, graphFixture(t, react), map[string][]model.Finding{
		react.NodeID(): {{ID: "CVE-REMOVED", Kind: model.FindingKindVulnerability, Source: "osv"}},
	})
	head := diffTestPipeline(t, graphFixture(t), nil)

	result, err := Run(context.Background(), Request{
		Base: Target{Pipeline: base, Request: diffTestRequest()},
		Head: Target{Pipeline: head, Request: diffTestRequest()},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	assertFindingIDs(t, result.Audit.Introduced)
	assertFindingIDs(t, result.Audit.Resolved, "CVE-REMOVED")
	assertFindingIDs(t, result.Audit.Persisted)
}

func TestRun_AuditsOnlyVersionChangedPackages(t *testing.T) {
	oldReact := npmPackage("react", "18.2.0")
	newReact := npmPackage("react", "18.2.1")
	oldLodash := npmPackage("lodash", "4.17.20")
	newLodash := npmPackage("lodash", "4.17.20")
	base := diffTestPipeline(t, graphFixture(t, oldReact, oldLodash), map[string][]model.Finding{
		oldReact.NodeID():  {{ID: "CVE-REACT-OLD", Kind: model.FindingKindVulnerability, Source: "osv"}},
		oldLodash.NodeID(): {{ID: "CVE-LODASH", Kind: model.FindingKindVulnerability, Source: "osv"}},
	})
	head := diffTestPipeline(t, graphFixture(t, newReact, newLodash), map[string][]model.Finding{
		newReact.NodeID():  {{ID: "CVE-REACT-NEW", Kind: model.FindingKindVulnerability, Source: "osv"}},
		newLodash.NodeID(): {{ID: "CVE-LODASH", Kind: model.FindingKindVulnerability, Source: "osv"}},
	})

	result, err := Run(context.Background(), Request{
		Base: Target{Pipeline: base, Request: diffTestRequest()},
		Head: Target{Pipeline: head, Request: diffTestRequest()},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	assertFindingIDs(t, result.Audit.Introduced, "CVE-REACT-NEW")
	assertFindingIDs(t, result.Audit.Resolved, "CVE-REACT-OLD")
	assertFindingIDs(t, result.Audit.Persisted)
}

func TestRun_SameVulnerabilityAcrossVersionBumpPersists(t *testing.T) {
	// A version bump that does not remediate the advisory must classify as
	// persisted, not as one introduced + one resolved, so the diff sections
	// agree that the project is still subject to the same vulnerability.
	oldLodash := npmPackage("lodash", "4.17.20")
	newLodash := npmPackage("lodash", "4.17.21")
	base := diffTestPipeline(t, graphFixture(t, oldLodash), map[string][]model.Finding{
		oldLodash.NodeID(): {{ID: "CVE-LODASH", Kind: model.FindingKindVulnerability, Source: "osv"}},
	})
	head := diffTestPipeline(t, graphFixture(t, newLodash), map[string][]model.Finding{
		newLodash.NodeID(): {{ID: "CVE-LODASH", Kind: model.FindingKindVulnerability, Source: "osv"}},
	})

	result, err := Run(context.Background(), Request{
		Base: Target{Pipeline: base, Request: diffTestRequest()},
		Head: Target{Pipeline: head, Request: diffTestRequest()},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	assertFindingIDs(t, result.Audit.Introduced)
	assertFindingIDs(t, result.Audit.Resolved)
	assertFindingIDs(t, result.Audit.Persisted, "CVE-LODASH")
}

func TestRun_SameLicenseIssueAcrossVersionBumpPersists(t *testing.T) {
	// The license finding id hashes the full PURL, so it differs per version.
	// Keying on the base PURL keeps a carried-over license issue persisted.
	oldLib := npmPackage("lib", "1.0.0")
	newLib := npmPackage("lib", "1.1.0")
	licenseFinding := func(purl string) model.Finding {
		return model.Finding{
			ID:       "INVALID-from-" + purl,
			Kind:     model.FindingKindLicense,
			Source:   "license",
			Severity: model.SeverityWarning,
		}
	}
	base := diffTestPipeline(t, graphFixture(t, oldLib), map[string][]model.Finding{
		oldLib.NodeID(): {licenseFinding(oldLib.NodeID())},
	})
	head := diffTestPipeline(t, graphFixture(t, newLib), map[string][]model.Finding{
		newLib.NodeID(): {licenseFinding(newLib.NodeID())},
	})

	result, err := Run(context.Background(), Request{
		Base: Target{Pipeline: base, Request: diffTestRequest()},
		Head: Target{Pipeline: head, Request: diffTestRequest()},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(result.Audit.Introduced) != 0 || len(result.Audit.Resolved) != 0 {
		t.Fatalf("license issue carried across the bump should not be introduced/resolved: %+v", result.Audit)
	}
	if len(result.Audit.Persisted) != 1 {
		t.Fatalf("expected the license finding to persist, got %#v", result.Audit.Persisted)
	}
}

func TestRun_UnknownLicenseFindingIsEmittedForFocusedPackage(t *testing.T) {
	react := npmPackage("react", "18.2.0")
	registry := engine.NewRegistry(engine.RegistryConfigs{}, *zap.NewNop())
	registry.RegisterDetector(fakeDetector{
		descriptor: detectorDescriptor(),
		result: plugin.DetectionResult{
			Graphs: engine.SingleGraphContainer(graphFixture(t, react), model.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"}),
		},
	})
	registry.RegisterAuditor(license.Auditor{})
	head := engine.NewPipeline(registry, zap.NewNop())
	base := diffTestPipeline(t, graphFixture(t), nil)

	result, err := Run(context.Background(), Request{
		Base: Target{Pipeline: base, Request: diffTestRequest()},
		Head: Target{Pipeline: head, Request: diffTestRequest()},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(result.Audit.Introduced) != 1 {
		t.Fatalf("expected 1 introduced unknown-license finding, got %#v", result.Audit.Introduced)
	}
	finding := result.Audit.Introduced[0]
	if !strings.HasPrefix(finding.ID, "UNKNOWN-") || len(strings.Split(finding.ID, "-")) != 4 {
		t.Fatalf("expected compact unknown-license finding ID, got %#v", finding)
	}
	if finding.PackageRef != react.NodeID() {
		t.Fatalf("expected finding package ref %q, got %q", react.NodeID(), finding.PackageRef)
	}
}

func diffTestPipeline(t *testing.T, g *model.Graph, findings map[string][]model.Finding) *engine.Pipeline {
	t.Helper()
	registry := engine.NewRegistry(engine.RegistryConfigs{}, *zap.NewNop())
	registry.RegisterDetector(fakeDetector{
		descriptor: detectorDescriptor(),
		result: plugin.DetectionResult{
			Graphs: engine.SingleGraphContainer(g, model.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"}),
		},
	})
	registry.RegisterAuditor(fakeAuditor{
		descriptor:        plugin.AuditorDescriptor{Name: "severity-policy"},
		findingsByPackage: findings,
	})
	return engine.NewPipeline(registry, zap.NewNop())
}

func detectorDescriptor() plugin.DetectorDescriptor {
	return plugin.DetectorDescriptor{
		Name:                "npm-detector",
		SupportedEcosystems: []model.Ecosystem{model.EcosystemNPM},
		SupportedManagers:   []model.PackageManager{model.PackageManagerNPM},
	}
}

func diffTestRequest() engine.PipelineRequest {
	return engine.PipelineRequest{
		Subprojects: []plugin.Subproject{{
			ExecutionTarget:         plugin.ExecutionTarget{Kind: plugin.ExecutionTargetFilesystem, Location: "/repo"},
			RelativePath:            ".",
			PrimaryDetector:         "npm-detector",
			DetectedPackageManagers: []model.PackageManager{model.PackageManagerNPM},
			Ecosystem:               model.EcosystemNPM,
		}},
		AuditEnabled: true,
	}
}

func npmPackage(name, version string) *model.DependencyNode {
	purl := "pkg:npm/" + name + "@" + version
	return testnodes.DepFrom(model.DependencyNode{Coordinates: model.Coordinates{Ecosystem: model.EcosystemNPM,
		Name:    name,
		Version: version,
		PURL:    purl},
	})
}

func graphFixture(t *testing.T, packages ...*model.DependencyNode) *model.Graph {
	t.Helper()
	g := model.New()
	for _, pkg := range packages {
		if err := g.AddNode(pkg.Clone()); err != nil {
			t.Fatalf("add package %q: %v", pkg.NodeID(), err)
		}
	}
	return g
}

func assertFindingIDs(t *testing.T, findings []model.Finding, want ...string) {
	t.Helper()
	if len(findings) != len(want) {
		t.Fatalf("expected finding IDs %#v, got %#v", want, findings)
	}
	got := make(map[string]struct{}, len(findings))
	for _, finding := range findings {
		got[finding.ID] = struct{}{}
	}
	for _, id := range want {
		if _, ok := got[id]; !ok {
			t.Fatalf("expected finding ID %q in %#v", id, findings)
		}
	}
}

type fakeDetector struct {
	descriptor plugin.DetectorDescriptor
	result     plugin.DetectionResult
}

func (f fakeDetector) Descriptor() plugin.DetectorDescriptor {
	return f.descriptor
}

func (f fakeDetector) PackageManagerSupport() []plugin.PackageManagerSupport {
	return nil
}

func (f fakeDetector) Ready(context.Context, plugin.DetectionRequest) error {
	return nil
}

func (f fakeDetector) Applicable(context.Context, plugin.DetectionRequest) (bool, error) {
	return true, nil
}

func (f fakeDetector) ResolveGraph(context.Context, plugin.DetectionRequest) (plugin.DetectionResult, error) {
	return f.result, nil
}

type fakeAuditor struct {
	descriptor        plugin.AuditorDescriptor
	findingsByPackage map[string][]model.Finding
	detailFinding     bool
}

func (f fakeAuditor) Descriptor() plugin.AuditorDescriptor {
	return f.descriptor
}

func (f fakeAuditor) Ready(context.Context, plugin.AuditRequest) error {
	return nil
}

func (f fakeAuditor) Applicable(context.Context, plugin.AuditRequest) (bool, error) {
	return true, nil
}

func (f fakeAuditor) Audit(_ context.Context, req plugin.AuditRequest) (plugin.AuditResult, error) {
	if f.detailFinding && len(req.DependencyDetailChanges) > 0 {
		return plugin.AuditResult{Findings: []model.Finding{{
			ID:             "detail-policy",
			Kind:           model.FindingKindPackage,
			PolicyStatus:   model.FindingPolicyStatusWarn,
			RuleID:         "detail-policy",
			PackageRef:     req.DependencyDetailChanges[0].After.NodeID(),
			DependencyRefs: []string{req.DependencyDetailChanges[0].After.NodeID()},
		}}}, nil
	}
	if req.Graph == nil {
		return plugin.AuditResult{}, nil
	}
	var findings []model.Finding
	for _, pkg := range req.Graph.DependencyNodes() {
		if pkg == nil {
			continue
		}
		for _, finding := range f.findingsByPackage[pkg.NodeID()] {
			finding.PackageRef = pkg.NodeID()
			findings = append(findings, finding)
		}
	}
	return plugin.AuditResult{Findings: findings}, nil
}
