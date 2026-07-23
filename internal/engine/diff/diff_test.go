package diff

import (
	"context"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/auditors/license"
	"github.com/bomly-dev/bomly-cli/internal/engine"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

func TestRun_SkipsAuditFindingsWhenNoDependencyChanges(t *testing.T) {
	react := npmPackage("react", "18.2.0")
	base := diffTestPipeline(t, graphFixture(t, react), map[string][]sdk.Finding{
		react.ID: {{ID: "CVE-UNCHANGED", Kind: sdk.FindingKindVulnerability, Source: "osv"}},
	})
	head := diffTestPipeline(t, graphFixture(t, react.Clone()), map[string][]sdk.Finding{
		react.ID: {{ID: "CVE-UNCHANGED", Kind: sdk.FindingKindVulnerability, Source: "osv"}},
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
	head := diffTestPipeline(t, graphFixture(t, react), map[string][]sdk.Finding{
		react.ID: {{ID: "CVE-ADDED", Kind: sdk.FindingKindVulnerability, Source: "osv"}},
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

func TestRun_AppliesEachSidesAuditDispositionResolvers(t *testing.T) {
	react := npmPackage("react", "18.2.0")
	base := diffTestPipeline(t, graphFixture(t), nil)
	head := diffTestPipeline(t, graphFixture(t, react), map[string][]sdk.Finding{
		react.ID: {{ID: "CVE-ADDED", Kind: sdk.FindingKindVulnerability, Source: "osv", Disposition: sdk.FindingDispositionFail}},
	})
	headRequest := diffTestRequest()
	headRequest.FindingPolicyResolvers = []sdk.FindingPolicyResolver{diffPolicyResolver{}}
	result, err := Run(context.Background(), Request{
		Base: Target{Pipeline: base, Request: diffTestRequest()},
		Head: Target{Pipeline: head, Request: headRequest},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Audit.Introduced) != 1 || result.Audit.Introduced[0].Disposition != sdk.FindingDispositionSuppressed {
		t.Fatalf("introduced findings = %#v", result.Audit.Introduced)
	}
}

type diffPolicyResolver struct{}

func (diffPolicyResolver) ResolveFindingPolicy(context.Context, sdk.Finding, *sdk.PackageRegistry) (sdk.FindingPolicyDecision, bool) {
	return sdk.FindingPolicyDecision{Status: sdk.FindingDispositionSuppressed, Source: "test"}, true
}

func TestRun_ReportsRemovedPackageFindingAsResolved(t *testing.T) {
	react := npmPackage("react", "18.2.0")
	base := diffTestPipeline(t, graphFixture(t, react), map[string][]sdk.Finding{
		react.ID: {{ID: "CVE-REMOVED", Kind: sdk.FindingKindVulnerability, Source: "osv"}},
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
	base := diffTestPipeline(t, graphFixture(t, oldReact, oldLodash), map[string][]sdk.Finding{
		oldReact.ID:  {{ID: "CVE-REACT-OLD", Kind: sdk.FindingKindVulnerability, Source: "osv"}},
		oldLodash.ID: {{ID: "CVE-LODASH", Kind: sdk.FindingKindVulnerability, Source: "osv"}},
	})
	head := diffTestPipeline(t, graphFixture(t, newReact, newLodash), map[string][]sdk.Finding{
		newReact.ID:  {{ID: "CVE-REACT-NEW", Kind: sdk.FindingKindVulnerability, Source: "osv"}},
		newLodash.ID: {{ID: "CVE-LODASH", Kind: sdk.FindingKindVulnerability, Source: "osv"}},
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
	base := diffTestPipeline(t, graphFixture(t, oldLodash), map[string][]sdk.Finding{
		oldLodash.ID: {{ID: "CVE-LODASH", Kind: sdk.FindingKindVulnerability, Source: "osv"}},
	})
	head := diffTestPipeline(t, graphFixture(t, newLodash), map[string][]sdk.Finding{
		newLodash.ID: {{ID: "CVE-LODASH", Kind: sdk.FindingKindVulnerability, Source: "osv"}},
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
	licenseFinding := func(purl string) sdk.Finding {
		return sdk.Finding{
			ID:       "INVALID-from-" + purl,
			Kind:     sdk.FindingKindLicense,
			Source:   "license",
			Severity: sdk.SeverityWarning,
		}
	}
	base := diffTestPipeline(t, graphFixture(t, oldLib), map[string][]sdk.Finding{
		oldLib.ID: {licenseFinding(oldLib.PURL)},
	})
	head := diffTestPipeline(t, graphFixture(t, newLib), map[string][]sdk.Finding{
		newLib.ID: {licenseFinding(newLib.PURL)},
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
		result: sdk.DetectionResult{
			Graphs: engine.SingleGraphContainer(graphFixture(t, react), sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"}),
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
	if finding.PackageRef != react.PURL {
		t.Fatalf("expected finding package ref %q, got %q", react.PURL, finding.PackageRef)
	}
}

func diffTestPipeline(t *testing.T, g *sdk.Graph, findings map[string][]sdk.Finding) *engine.Pipeline {
	t.Helper()
	registry := engine.NewRegistry(engine.RegistryConfigs{}, *zap.NewNop())
	registry.RegisterDetector(fakeDetector{
		descriptor: detectorDescriptor(),
		result: sdk.DetectionResult{
			Graphs: engine.SingleGraphContainer(g, sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"}),
		},
	})
	registry.RegisterAuditor(fakeAuditor{
		descriptor:        sdk.AuditorDescriptor{Name: "severity-policy"},
		findingsByPackage: findings,
	})
	return engine.NewPipeline(registry, zap.NewNop())
}

func detectorDescriptor() sdk.DetectorDescriptor {
	return sdk.DetectorDescriptor{
		Name:                "npm-detector",
		SupportedEcosystems: []sdk.Ecosystem{sdk.EcosystemNPM},
		SupportedManagers:   []sdk.PackageManager{sdk.PackageManagerNPM},
	}
}

func diffTestRequest() engine.PipelineRequest {
	return engine.PipelineRequest{
		Subprojects: []sdk.Subproject{{
			ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: "/repo"},
			RelativePath:            ".",
			PrimaryDetector:         "npm-detector",
			DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
			Ecosystem:               sdk.EcosystemNPM,
		}},
		AuditEnabled: true,
	}
}

func npmPackage(name, version string) *sdk.Dependency {
	purl := "pkg:npm/" + name + "@" + version
	return sdk.NewDependencyWithID(purl, sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemNPM,
		Name:    name,
		Version: version,
		PURL:    purl},
	})
}

func graphFixture(t *testing.T, packages ...*sdk.Dependency) *sdk.Graph {
	t.Helper()
	g := sdk.New()
	for _, pkg := range packages {
		if err := g.AddNode(pkg.Clone()); err != nil {
			t.Fatalf("add package %q: %v", pkg.ID, err)
		}
	}
	return g
}

func assertFindingIDs(t *testing.T, findings []sdk.Finding, want ...string) {
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
	descriptor sdk.DetectorDescriptor
	result     sdk.DetectionResult
}

func (f fakeDetector) Descriptor() sdk.DetectorDescriptor {
	return f.descriptor
}

func (f fakeDetector) PackageManagerSupport() []sdk.PackageManagerSupport {
	return nil
}

func (f fakeDetector) Ready(context.Context, sdk.DetectionRequest) error {
	return nil
}

func (f fakeDetector) Applicable(context.Context, sdk.DetectionRequest) (bool, error) {
	return true, nil
}

func (f fakeDetector) ResolveGraph(context.Context, sdk.DetectionRequest) (sdk.DetectionResult, error) {
	return f.result, nil
}

type fakeAuditor struct {
	descriptor        sdk.AuditorDescriptor
	findingsByPackage map[string][]sdk.Finding
}

func (f fakeAuditor) Descriptor() sdk.AuditorDescriptor {
	return f.descriptor
}

func (f fakeAuditor) Ready(context.Context, sdk.AuditRequest) error {
	return nil
}

func (f fakeAuditor) Applicable(context.Context, sdk.AuditRequest) (bool, error) {
	return true, nil
}

func (f fakeAuditor) Audit(_ context.Context, req sdk.AuditRequest) (sdk.AuditResult, error) {
	if req.Graph == nil {
		return sdk.AuditResult{}, nil
	}
	var findings []sdk.Finding
	for _, pkg := range req.Graph.Nodes() {
		if pkg == nil {
			continue
		}
		for _, finding := range f.findingsByPackage[pkg.ID] {
			finding.PackageRef = pkg.PURL
			findings = append(findings, finding)
		}
	}
	return sdk.AuditResult{Findings: findings}, nil
}
