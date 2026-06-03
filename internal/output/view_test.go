package output_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/engine/consolidation"
	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestBuildScanResponseIncludesAuditData(t *testing.T) {
	g := newViewTestGraph(t)
	started := time.Now().Add(-2 * time.Second)
	results := []sdk.DetectionResult{{
		SubprojectInfo: sdk.Subproject{
			RelativePath:            ".",
			PrimaryDetector:         "npm-detector",
			DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
			Ecosystem:               sdk.EcosystemNPM,
		},
		DetectorName: "npm",
		Graphs: &sdk.GraphContainer{Entries: []sdk.GraphEntry{{
			Graph:    g,
			Manifest: sdk.ManifestMetadata{Path: "/tmp/demo/package-lock.json", Kind: "package-lock.json"},
		}}},
	}}

	findings := []sdk.Finding{{
		ID:         "OSV-1",
		Kind:       sdk.FindingKindVulnerability,
		Severity:   "high",
		PackageRef: "pkg:npm/react@18.2.0",
		Title:      "Prototype pollution",
		Source:     "osv",
	}}
	consolidated, err := consolidation.ConsolidateGraphs(results)
	if err != nil {
		t.Fatalf("ConsolidateGraphs() error = %v", err)
	}
	response := output.BuildScanResponse(output.ProjectDescriptor{Name: "demo", Path: "/tmp/demo"}, consolidated, nil, findings, started)
	if response.Command != "scan" {
		t.Fatalf("expected scan command, got %q", response.Command)
	}
	if len(response.Manifests) != 1 {
		t.Fatalf("expected 1 manifest, got %d", len(response.Manifests))
	}
	if got := len(response.Manifests[0].Packages); got != 4 {
		t.Fatalf("expected 4 packages, got %d", got)
	}
	if filepath.Base(response.Manifests[0].Path) != "package-lock.json" {
		t.Fatalf("expected normalized manifest path, got %#v", response.Manifests[0].Path)
	}
	if response.AuditSummary == nil || response.AuditSummary.High != 1 || response.AuditSummary.Total != 1 {
		t.Fatalf("unexpected audit summary: %#v", response.AuditSummary)
	}
	if response.Metadata.DurationMS <= 0 {
		t.Fatalf("expected positive duration, got %d", response.Metadata.DurationMS)
	}
}

func TestBuildScanResponseGatesReachability(t *testing.T) {
	g := newViewTestGraph(t)
	pkg, ok := g.Node("react@18.2.0")
	if !ok {
		t.Fatal("react package not found")
	}
	// Reachability lives on registry packages, not graph nodes. Build a
	// registry that mirrors the consolidated graph and stash a reachable
	// vulnerability on the react PURL.
	const reactPURL = "pkg:npm/react@18.2.0"
	pkg.PURL = reactPURL
	registry := sdk.NewPackageRegistry()
	regPkg := registry.Ensure(reactPURL)
	regPkg.Name = "react"
	regPkg.Version = "18.2.0"
	regPkg.Vulnerabilities = []sdk.Vulnerability{{
		ID:     "OSV-REACH",
		Source: "osv",
		Reachability: &sdk.Reachability{
			Status:   sdk.ReachabilityReachable,
			Tier:     sdk.TierPackage,
			Analyzer: "jsreach",
		},
	}}
	results := []sdk.DetectionResult{{
		SubprojectInfo: sdk.Subproject{RelativePath: ".", PrimaryDetector: "npm-detector", DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerNPM}, Ecosystem: sdk.EcosystemNPM},
		Graphs: &sdk.GraphContainer{Entries: []sdk.GraphEntry{{
			Graph:    g,
			Manifest: sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"},
		}}},
	}}
	consolidated, err := consolidation.ConsolidateGraphs(results)
	if err != nil {
		t.Fatalf("ConsolidateGraphs() error = %v", err)
	}
	finding := sdk.Finding{
		ID:              "OSV-REACH",
		VulnerabilityID: "OSV-REACH",
		Kind:            sdk.FindingKindVulnerability,
		PackageRef:      reactPURL,
		Source:          "osv",
	}

	disabled := output.BuildScanResponse(output.ProjectDescriptor{Name: "demo"}, consolidated, registry, []sdk.Finding{finding}, time.Now().Add(-time.Second))
	if disabled.Metadata.ReachabilityEnabled {
		t.Fatal("reachability metadata should be omitted when disabled")
	}
	if got := scanPackageByName(t, disabled.Manifests[0].Packages, "react").Vulnerabilities[0].Reachability; got != nil {
		t.Fatalf("disabled scan package reachability leaked: %#v", got)
	}
	if got := disabled.Findings[0].Reachability; got != nil {
		t.Fatalf("disabled scan finding reachability leaked: %#v", got)
	}

	enabled := output.BuildScanResponse(output.ProjectDescriptor{Name: "demo"}, consolidated, registry, []sdk.Finding{finding}, time.Now().Add(-time.Second), output.ReportOptions{
		ReachabilityEnabled: true,
		AnalyzerRuns:        []string{"jsreach"},
		AnalyzerStats:       map[string]sdk.ReachabilityStats{"jsreach": {Reachable: 1}},
	})
	if !enabled.Metadata.ReachabilityEnabled {
		t.Fatal("reachability metadata should be set when enabled")
	}
	if len(enabled.Metadata.AnalyzerRuns) != 1 || enabled.Metadata.AnalyzerRuns[0] != "jsreach" {
		t.Fatalf("unexpected analyzer runs: %#v", enabled.Metadata.AnalyzerRuns)
	}
	if enabled.Metadata.AnalyzerStats["jsreach"].Reachable != 1 {
		t.Fatalf("unexpected analyzer stats: %#v", enabled.Metadata.AnalyzerStats)
	}
	if got := scanPackageByName(t, enabled.Manifests[0].Packages, "react").Vulnerabilities[0].Reachability; got == nil || got.Status != sdk.ReachabilityReachable {
		t.Fatalf("enabled scan package reachability missing: %#v", got)
	}
	if got := enabled.Findings[0].Reachability; got == nil || got.Status != sdk.ReachabilityReachable {
		t.Fatalf("enabled scan finding reachability missing: %#v", got)
	}
}

func TestBuildScanResponseDeduplicatesManifestAndPrefersNative(t *testing.T) {
	projectRoot := "/tmp/demo"
	manifestPath := filepath.Join(projectRoot, "package-lock.json")

	syftGraph := sdk.New()
	if err := syftGraph.AddNode(sdk.NewDependencyWithID("123", sdk.Dependency{
		Name:      "demo-app",
		Version:   "1.0.0",
		Ecosystem: "npm",
		PURL:      "pkg:npm/demo-app@1.0.0",
	})); err != nil {
		t.Fatalf("add syft package: %v", err)
	}

	nativeGraph := newViewTestGraph(t)
	results := []sdk.DetectionResult{
		{
			SubprojectInfo: sdk.Subproject{
				ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: projectRoot},
				RelativePath:            ".",
				PrimaryDetector:         "npm-detector",
				DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
				Ecosystem:               sdk.EcosystemNPM,
			},
			DetectorName: "syft-detector",
			Origin:       sdk.BundledOrigin,
			Technique:    sdk.MultipleTechnique,
			Graphs: &sdk.GraphContainer{Entries: []sdk.GraphEntry{{
				Graph:    syftGraph,
				Manifest: sdk.ManifestMetadata{Path: manifestPath, Kind: "package-lock.json"},
			}}},
		},
		{
			SubprojectInfo: sdk.Subproject{
				ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: projectRoot},
				RelativePath:            ".",
				PrimaryDetector:         "npm-detector",
				DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
				Ecosystem:               sdk.EcosystemNPM,
			},
			DetectorName: "npm-detector",
			Origin:       sdk.CoreOrigin,
			Technique:    sdk.BuildToolTechnique,
			Graphs: &sdk.GraphContainer{Entries: []sdk.GraphEntry{{
				Graph:    nativeGraph,
				Manifest: sdk.ManifestMetadata{Path: manifestPath, Kind: "package-lock.json"},
			}}},
		},
	}

	consolidated, err := consolidation.ConsolidateGraphs(results)
	if err != nil {
		t.Fatalf("ConsolidateGraphs() error = %v", err)
	}
	response := output.BuildScanResponse(output.ProjectDescriptor{Name: "demo", Path: projectRoot}, consolidated, nil, nil, time.Now().Add(-time.Second))
	if len(response.Manifests) != 1 {
		t.Fatalf("expected 1 deduplicated manifest, got %d", len(response.Manifests))
	}
	if response.Manifests[0].Detector != "npm-detector" {
		t.Fatalf("expected native detector to win, got %q", response.Manifests[0].Detector)
	}
	if got := len(response.Manifests[0].Packages); got != 4 {
		t.Fatalf("expected native manifest packages, got %d", got)
	}
}

func TestBuildScanResponseDeduplicatesSameManifestWhenMetadataDiffers(t *testing.T) {
	projectRoot := "/tmp/demo"
	manifestPath := filepath.Join(projectRoot, "package-lock.json")

	nativeGraph := newViewTestGraph(t)
	syftGraph := sdk.New()
	if err := syftGraph.AddNode(sdk.NewDependencyWithID("123", sdk.Dependency{
		Name:      "demo-app",
		Version:   "1.0.0",
		Ecosystem: "npm",
		PURL:      "pkg:npm/demo-app@1.0.0",
	})); err != nil {
		t.Fatalf("add syft package: %v", err)
	}

	results := []sdk.DetectionResult{
		{
			SubprojectInfo: sdk.Subproject{
				ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: projectRoot},
				RelativePath:            ".",
				PrimaryDetector:         "npm-detector",
				DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
				Ecosystem:               sdk.EcosystemNPM,
			},
			DetectorName: "npm-detector",
			Origin:       sdk.CoreOrigin,
			Technique:    sdk.BuildToolTechnique,
			Graphs: &sdk.GraphContainer{Entries: []sdk.GraphEntry{{
				Graph:    nativeGraph,
				Manifest: sdk.ManifestMetadata{Path: manifestPath, Kind: "package-lock.json"},
			}}},
		},
		{
			SubprojectInfo: sdk.Subproject{
				ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: projectRoot},
				RelativePath:            ".",
				PrimaryDetector:         "npm-detector",
				DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
				Ecosystem:               sdk.EcosystemNPM,
			},
			DetectorName: "syft-detector",
			Origin:       sdk.BundledOrigin,
			Technique:    sdk.MultipleTechnique,
			Graphs: &sdk.GraphContainer{Entries: []sdk.GraphEntry{{
				Graph:    syftGraph,
				Manifest: sdk.ManifestMetadata{Path: "package-lock.json", Kind: "npm-lockfile"},
			}}},
		},
	}

	consolidated, err := consolidation.ConsolidateGraphs(results)
	if err != nil {
		t.Fatalf("ConsolidateGraphs() error = %v", err)
	}
	response := output.BuildScanResponse(output.ProjectDescriptor{Name: "demo", Path: projectRoot}, consolidated, nil, nil, time.Now().Add(-time.Second))
	if len(response.Manifests) != 1 {
		t.Fatalf("expected same manifest file to deduplicate despite metadata drift, got %#v", response.Manifests)
	}
	if response.Manifests[0].Kind != "package-lock.json" {
		t.Fatalf("expected native manifest metadata to win, got %q", response.Manifests[0].Kind)
	}
}

func TestBuildExplainResponseFlattensSingleTarget(t *testing.T) {
	started := time.Now().Add(-1 * time.Second)
	targets := []output.ExplainTargetResponse{{
		Project:    output.ProjectDescriptor{Name: "demo"},
		Dependency: output.PackageRef{Name: "react", ID: "react@18.2.0"},
		Paths:      []output.DependencyPath{{Relationship: "direct"}},
	}}

	response := output.BuildExplainResponse(output.ProjectDescriptor{Name: "demo"}, "react", targets, started)
	if response.Dependency.ID != "react@18.2.0" {
		t.Fatalf("expected flattened dependency, got %#v", response.Dependency)
	}
	if len(response.Paths) != 1 {
		t.Fatalf("expected flattened paths, got %#v", response.Paths)
	}
}

func TestBuildExplainResponseGatesReachability(t *testing.T) {
	targets := []output.ExplainTargetResponse{{
		Project: output.ProjectDescriptor{Name: "demo"},
		Dependency: output.PackageRef{
			Name: "react",
			ID:   "react@18.2.0",
			Vulnerabilities: []output.VulnerabilityRef{{
				ID:           "OSV-REACH",
				Source:       "osv",
				Reachability: &sdk.Reachability{Status: sdk.ReachabilityReachable, Tier: sdk.TierPackage},
			}},
		},
		Paths: []output.DependencyPath{{Packages: []output.PackageRef{{
			Name: "react",
			ID:   "react@18.2.0",
			Vulnerabilities: []output.VulnerabilityRef{{
				ID:           "OSV-REACH",
				Source:       "osv",
				Reachability: &sdk.Reachability{Status: sdk.ReachabilityReachable, Tier: sdk.TierPackage},
			}},
		}}}},
		Findings: []output.AuditFinding{{
			ID:           "OSV-REACH",
			Kind:         "vulnerability",
			Package:      output.PackageRef{Name: "react"},
			Reachability: &sdk.Reachability{Status: sdk.ReachabilityReachable, Tier: sdk.TierPackage},
		}},
	}}
	disabled := output.BuildExplainResponse(output.ProjectDescriptor{Name: "demo"}, "react", targets, time.Now().Add(-time.Second))
	if disabled.Dependency.Vulnerabilities[0].Reachability != nil || disabled.Targets[0].Findings[0].Reachability != nil {
		t.Fatalf("disabled explain reachability leaked: %#v", disabled)
	}

	enabled := output.BuildExplainResponse(output.ProjectDescriptor{Name: "demo"}, "react", targets, time.Now().Add(-time.Second), output.ReportOptions{ReachabilityEnabled: true})
	if !enabled.Metadata.ReachabilityEnabled {
		t.Fatal("reachability metadata should be set when enabled")
	}
	if got := enabled.Dependency.Vulnerabilities[0].Reachability; got == nil || got.Status != sdk.ReachabilityReachable {
		t.Fatalf("enabled explain reachability missing: %#v", got)
	}
}

func TestBuildDiffResponseAggregatesManifestChanges(t *testing.T) {
	baseGraph := newViewTestGraph(t)
	headGraph := newViewTestGraph(t)
	if err := headGraph.AddNode(sdk.NewDependencyRef("newpkg", "1.0.0")); err != nil {
		t.Fatalf("add package: %v", err)
	}
	if err := headGraph.AddEdge("app@1.0.0", "newpkg@1.0.0"); err != nil {
		t.Fatalf("add dependency: %v", err)
	}

	baseResults := []sdk.DetectionResult{{
		SubprojectInfo: sdk.Subproject{RelativePath: ".", PrimaryDetector: "npm-detector", DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerNPM}, Ecosystem: sdk.EcosystemNPM},
		Graphs: &sdk.GraphContainer{Entries: []sdk.GraphEntry{{
			Graph:    baseGraph,
			Manifest: sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"},
		}}},
	}}
	headResults := []sdk.DetectionResult{{
		SubprojectInfo: sdk.Subproject{RelativePath: ".", PrimaryDetector: "npm-detector", DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerNPM}, Ecosystem: sdk.EcosystemNPM},
		Graphs: &sdk.GraphContainer{Entries: []sdk.GraphEntry{{
			Graph:    headGraph,
			Manifest: sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"},
		}}},
	}}

	baseConsolidated, err := consolidation.ConsolidateGraphs(baseResults)
	if err != nil {
		t.Fatalf("ConsolidateGraphs(base) error = %v", err)
	}
	headConsolidated, err := consolidation.ConsolidateGraphs(headResults)
	if err != nil {
		t.Fatalf("ConsolidateGraphs(head) error = %v", err)
	}
	response := output.BuildDiffResponse("/tmp/demo", "base", "head", baseConsolidated, headConsolidated, nil, time.Now().Add(-time.Second))
	if response.Command != "diff" {
		t.Fatalf("expected diff command, got %q", response.Command)
	}
	if response.Summary.ChangedManifestCount != 1 || response.Summary.AddedPackageCount != 1 {
		t.Fatalf("unexpected diff summary: %#v", response.Summary)
	}
	if response.Summary.UnmatchedPackageCount != 1 {
		t.Fatalf("expected one unmatched package, got %#v", response.Summary)
	}
	if len(response.Results.Dependencies.Added) != 1 || response.Results.Dependencies.Added[0].Package.Name != "newpkg" {
		t.Fatalf("expected global dependency aggregate, got %#v", response.Results.Dependencies)
	}
	if len(response.Results.Manifests) != 1 || response.Results.Manifests[0].Status != "changed" {
		t.Fatalf("unexpected manifest results: %#v", response.Results.Manifests)
	}
}

func TestBuildDiffResponseGatesReachability(t *testing.T) {
	// Reachability on Diff result vulnerabilities is sourced from registry
	// packages keyed by PURL. The diff result aggregator currently builds
	// vulnerability change records from graph dependencies only; plumbing
	// the registry through it is tracked separately. Until then this test
	// only exercises the audit-finding reachability gating path, which is
	// the primary surface SARIF consumers rely on.
	baseGraph := newViewTestGraph(t)
	headGraph := newViewTestGraph(t)
	pkg := sdk.NewDependencyRef("newpkg", "1.0.0")
	pkg.PURL = "pkg:npm/newpkg@1.0.0"
	if err := headGraph.AddNode(pkg); err != nil {
		t.Fatalf("add package: %v", err)
	}
	if err := headGraph.AddEdge("app@1.0.0", pkg.ID); err != nil {
		t.Fatalf("add dependency: %v", err)
	}

	baseConsolidated, err := consolidation.ConsolidateGraphs([]sdk.DetectionResult{{
		SubprojectInfo: sdk.Subproject{RelativePath: ".", PrimaryDetector: "npm-detector", DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerNPM}, Ecosystem: sdk.EcosystemNPM},
		Graphs: &sdk.GraphContainer{Entries: []sdk.GraphEntry{{
			Graph:    baseGraph,
			Manifest: sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"},
		}}},
	}})
	if err != nil {
		t.Fatalf("ConsolidateGraphs(base) error = %v", err)
	}
	headConsolidated, err := consolidation.ConsolidateGraphs([]sdk.DetectionResult{{
		SubprojectInfo: sdk.Subproject{RelativePath: ".", PrimaryDetector: "npm-detector", DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerNPM}, Ecosystem: sdk.EcosystemNPM},
		Graphs: &sdk.GraphContainer{Entries: []sdk.GraphEntry{{
			Graph:    headGraph,
			Manifest: sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"},
		}}},
	}})
	if err != nil {
		t.Fatalf("ConsolidateGraphs(head) error = %v", err)
	}
	reachable := &sdk.Reachability{Status: sdk.ReachabilityReachable, Tier: sdk.TierPackage}
	audit := &output.DiffAudit{
		Introduced: []output.AuditFinding{{
			ID:           "OSV-REACH",
			Kind:         "vulnerability",
			Package:      output.PackageFromGraphPackage(pkg),
			Reachability: reachable,
		}},
	}
	disabled := output.BuildDiffResponse("/tmp/demo", "base", "head", baseConsolidated, headConsolidated, audit, time.Now().Add(-time.Second))
	if disabled.Audit.Introduced[0].Reachability != nil {
		t.Fatalf("disabled diff audit reachability leaked: %#v", disabled.Audit.Introduced[0].Reachability)
	}

	enabled := output.BuildDiffResponse("/tmp/demo", "base", "head", baseConsolidated, headConsolidated, audit, time.Now().Add(-time.Second), output.ReportOptions{ReachabilityEnabled: true})
	if !enabled.Metadata.ReachabilityEnabled {
		t.Fatal("reachability metadata should be set when enabled")
	}
	if enabled.Audit.Introduced[0].Reachability == nil {
		t.Fatal("enabled diff audit reachability missing")
	}
}

func TestBuildDiffResponseMatchesSameManifestWhenKindDiffers(t *testing.T) {
	baseGraph := newViewTestGraph(t)
	headGraph := newViewTestGraph(t)
	if err := headGraph.AddNode(sdk.NewDependencyRef("newpkg", "1.0.0")); err != nil {
		t.Fatalf("add package: %v", err)
	}
	if err := headGraph.AddEdge("app@1.0.0", "newpkg@1.0.0"); err != nil {
		t.Fatalf("add dependency: %v", err)
	}

	baseResults := []sdk.DetectionResult{{
		SubprojectInfo: sdk.Subproject{RelativePath: ".", PrimaryDetector: "go-detector", DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerGoMod}, Ecosystem: sdk.EcosystemGo},
		Graphs: &sdk.GraphContainer{Entries: []sdk.GraphEntry{{
			Graph:    baseGraph,
			Manifest: sdk.ManifestMetadata{Path: "go.mod", Kind: "go-module"},
		}}},
	}}
	headResults := []sdk.DetectionResult{{
		SubprojectInfo: sdk.Subproject{RelativePath: ".", PrimaryDetector: "go-detector", DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerGoMod}, Ecosystem: sdk.EcosystemGo},
		Graphs: &sdk.GraphContainer{Entries: []sdk.GraphEntry{{
			Graph:    headGraph,
			Manifest: sdk.ManifestMetadata{Path: "go.mod", Kind: "go.mod"},
		}}},
	}}

	baseConsolidated, err := consolidation.ConsolidateGraphs(baseResults)
	if err != nil {
		t.Fatalf("ConsolidateGraphs(base) error = %v", err)
	}
	headConsolidated, err := consolidation.ConsolidateGraphs(headResults)
	if err != nil {
		t.Fatalf("ConsolidateGraphs(head) error = %v", err)
	}

	response := output.BuildDiffResponse("/tmp/demo", "base", "head", baseConsolidated, headConsolidated, nil, time.Now().Add(-time.Second))
	if response.Summary.ChangedManifestCount != 1 {
		t.Fatalf("expected one changed manifest, got %#v", response.Summary)
	}
	if response.Summary.AddedManifestCount != 0 || response.Summary.RemovedManifestCount != 0 {
		t.Fatalf("expected same manifest path to match despite kind drift, got %#v", response.Summary)
	}
	if len(response.Results.Manifests) != 1 || response.Results.Manifests[0].Kind != "go.mod" {
		t.Fatalf("expected head manifest metadata on the matched result, got %#v", response.Results.Manifests)
	}
}

func TestBuildDiffResponseTreatsSBOMFilesAsSameManifestWhenOnlyEvidencePathDiffers(t *testing.T) {
	baseGraph := newViewTestGraph(t)
	headGraph := newViewTestGraph(t)
	if err := headGraph.AddNode(sdk.NewDependencyRef("newpkg", "1.0.0")); err != nil {
		t.Fatalf("add package: %v", err)
	}
	if err := headGraph.AddEdge("app@1.0.0", "newpkg@1.0.0"); err != nil {
		t.Fatalf("add dependency: %v", err)
	}

	baseTarget := sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: "/tmp/base.spdx.json"}
	headTarget := sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: "/tmp/head.spdx.json"}
	baseResults := []sdk.DetectionResult{{
		SubprojectInfo: sdk.Subproject{
			ExecutionTarget:         baseTarget,
			RelativePath:            "base.spdx.json",
			PrimaryDetector:         "sbom-detector",
			DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerSBOM},
			Ecosystem:               sdk.EcosystemSBOM,
		},
		DetectorName: "sbom-detector",
		Origin:       sdk.CoreOrigin,
		Technique:    sdk.SBOMTechnique,
		Graphs: &sdk.GraphContainer{Entries: []sdk.GraphEntry{{
			Graph:    baseGraph,
			Manifest: sdk.ManifestMetadata{Path: baseTarget.Location, Kind: "github.spdx"},
		}}},
	}}
	headResults := []sdk.DetectionResult{{
		SubprojectInfo: sdk.Subproject{
			ExecutionTarget:         headTarget,
			RelativePath:            "head.spdx.json",
			PrimaryDetector:         "sbom-detector",
			DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerSBOM},
			Ecosystem:               sdk.EcosystemSBOM,
		},
		DetectorName: "sbom-detector",
		Origin:       sdk.CoreOrigin,
		Technique:    sdk.SBOMTechnique,
		Graphs: &sdk.GraphContainer{Entries: []sdk.GraphEntry{{
			Graph:    headGraph,
			Manifest: sdk.ManifestMetadata{Path: headTarget.Location, Kind: "bomly.spdx"},
		}}},
	}}

	baseConsolidated, err := consolidation.ConsolidateGraphs(baseResults)
	if err != nil {
		t.Fatalf("ConsolidateGraphs(base) error = %v", err)
	}
	headConsolidated, err := consolidation.ConsolidateGraphs(headResults)
	if err != nil {
		t.Fatalf("ConsolidateGraphs(head) error = %v", err)
	}

	response := output.BuildDiffResponse("/tmp/demo", "base", "head", baseConsolidated, headConsolidated, nil, time.Now().Add(-time.Second))
	if response.Summary.ChangedManifestCount != 1 {
		t.Fatalf("expected one changed manifest, got %#v", response.Summary)
	}
	if response.Summary.AddedManifestCount != 0 || response.Summary.RemovedManifestCount != 0 {
		t.Fatalf("expected synthetic SBOM manifest matching, got %#v", response.Summary)
	}
}

func TestBuildDiffResponsePrunesSBOMPseudoRootPackages(t *testing.T) {
	baseGraph := sdk.New()
	githubRoot := sdk.NewDependencyWithID("pkg:github/bomly-dev/example@main", sdk.Dependency{
		Ecosystem:   "github-actions",
		BuildSystem: "sbom",
		Name:        "com.github.bomly-dev/example",
		Version:     "main",
		PURL:        "pkg:github/bomly-dev/example@main",
	})
	shared := sdk.NewDependencyWithID("pkg:npm/react@18.2.0", sdk.Dependency{
		Ecosystem:   "npm",
		BuildSystem: "npm",
		Name:        "react",
		Version:     "18.2.0",
		PURL:        "pkg:npm/react@18.2.0",
	})
	for _, pkg := range []*sdk.Dependency{githubRoot, shared} {
		if err := baseGraph.AddNode(pkg); err != nil {
			t.Fatalf("base add package %q: %v", pkg.ID, err)
		}
	}
	if err := baseGraph.AddEdge(githubRoot.ID, shared.ID); err != nil {
		t.Fatalf("base add dependency: %v", err)
	}

	headGraph := sdk.New()
	root := sdk.NewDependencyWithID("pkg:generic/root", sdk.Dependency{Name: "root", PURL: "pkg:generic/root"})
	lockfile := sdk.NewDependencyWithID("pkg:generic/package-lock.json", sdk.Dependency{Name: "package-lock.json", PURL: "pkg:generic/package-lock.json"})
	added := sdk.NewDependencyWithID("pkg:npm/zod@3.23.0", sdk.Dependency{
		Ecosystem:   "npm",
		BuildSystem: "npm",
		Name:        "zod",
		Version:     "3.23.0",
		PURL:        "pkg:npm/zod@3.23.0",
	})
	for _, pkg := range []*sdk.Dependency{root, lockfile, shared, added} {
		if err := headGraph.AddNode(pkg); err != nil {
			t.Fatalf("head add package %q: %v", pkg.ID, err)
		}
	}
	if err := headGraph.AddEdge(root.ID, shared.ID); err != nil {
		t.Fatalf("head add root dependency: %v", err)
	}
	if err := headGraph.AddEdge(lockfile.ID, added.ID); err != nil {
		t.Fatalf("head add lockfile dependency: %v", err)
	}

	baseConsolidated, err := consolidation.ConsolidateGraphs(sbomDiffResults(baseGraph, "/tmp/github.sbom.json", "github.sbom.json"))
	if err != nil {
		t.Fatalf("ConsolidateGraphs(base) error = %v", err)
	}
	headConsolidated, err := consolidation.ConsolidateGraphs(sbomDiffResults(headGraph, "/tmp/bomly.sbom.json", "bomly.sbom.json"))
	if err != nil {
		t.Fatalf("ConsolidateGraphs(head) error = %v", err)
	}

	response := output.BuildDiffResponse("/tmp/demo", "base", "head", baseConsolidated, headConsolidated, nil, time.Now().Add(-time.Second))
	if response.Summary.AddedPackageCount != 1 || response.Summary.RemovedPackageCount != 0 {
		t.Fatalf("expected only real added dependency, got %#v with manifests %#v", response.Summary, response.Results.Manifests)
	}
	if len(response.Results.Manifests) != 1 {
		t.Fatalf("expected one manifest result, got %#v", response.Results.Manifests)
	}
	addedPackages := response.Results.Manifests[0].Added
	if len(addedPackages) != 1 || addedPackages[0].Package.Purl != "pkg:npm/zod@3.23.0" {
		t.Fatalf("expected zod as the only added package, got %#v", addedPackages)
	}
	if len(response.Results.Manifests[0].Removed) != 0 {
		t.Fatalf("expected pseudo GitHub root to be pruned, got %#v", response.Results.Manifests[0].Removed)
	}
}

func TestBuildScanResponsePreservesPropagatedLicensesAcrossDuplicateManifests(t *testing.T) {
	projectRoot := "/tmp/demo"
	nativeGraph := sdk.New()
	nativeApp := sdk.NewDependencyWithID("pkg:npm/app@1.0.0", sdk.Dependency{
		Ecosystem:   "npm",
		BuildSystem: "npm",
		Name:        "app",
		Version:     "1.0.0",
		PURL:        "pkg:npm/app@1.0.0",
	})
	if err := nativeGraph.AddNode(nativeApp); err != nil {
		t.Fatalf("add native app: %v", err)
	}
	nativeReact := sdk.NewDependencyWithID("pkg:npm/react@18.2.0", sdk.Dependency{
		Ecosystem:   "npm",
		BuildSystem: "npm",
		Name:        "react",
		Version:     "18.2.0",
		PURL:        "pkg:npm/react@18.2.0",
	})
	if err := nativeGraph.AddNode(nativeReact); err != nil {
		t.Fatalf("add native react: %v", err)
	}
	if err := nativeGraph.AddEdge(nativeApp.ID, nativeReact.ID); err != nil {
		t.Fatalf("add native dependency: %v", err)
	}

	sbomGraph := sdk.New()
	if err := sbomGraph.AddNode(sdk.NewDependencyWithID("SPDXRef-app", sdk.Dependency{
		Ecosystem:   "npm",
		BuildSystem: "npm",
		Name:        "app",
		Version:     "1.0.0",
		PURL:        "pkg:npm/app@1.0.0",
	})); err != nil {
		t.Fatalf("add sbom app: %v", err)
	}
	if err := sbomGraph.AddNode(sdk.NewDependencyWithID("SPDXRef-react", sdk.Dependency{
		Ecosystem:   "npm",
		BuildSystem: "npm",
		Name:        "react",
		Version:     "18.2.0",
		PURL:        "pkg:npm/react@18.2.0",
	})); err != nil {
		t.Fatalf("add sbom react: %v", err)
	}
	if err := sbomGraph.AddEdge("SPDXRef-app", "SPDXRef-react"); err != nil {
		t.Fatalf("add sbom dependency: %v", err)
	}

	results := []sdk.DetectionResult{
		{
			SubprojectInfo: sdk.Subproject{
				ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: projectRoot},
				RelativePath:            ".",
				PrimaryDetector:         "npm-detector",
				DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
				Ecosystem:               sdk.EcosystemNPM,
			},
			DetectorName: "npm-detector",
			Origin:       sdk.CoreOrigin,
			Technique:    sdk.BuildToolTechnique,
			Graphs: &sdk.GraphContainer{Entries: []sdk.GraphEntry{{
				Graph:    nativeGraph,
				Manifest: sdk.ManifestMetadata{Path: filepath.Join(projectRoot, "package-lock.json"), Kind: "package-lock.json"},
			}}},
		},
		{
			SubprojectInfo: sdk.Subproject{
				ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: projectRoot},
				RelativePath:            "app.spdx.json",
				PrimaryDetector:         "sbom-detector",
				DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerSBOM},
				Ecosystem:               sdk.EcosystemSBOM,
			},
			DetectorName: "sbom-detector",
			Origin:       sdk.CoreOrigin,
			Technique:    sdk.SBOMTechnique,
			Graphs: &sdk.GraphContainer{Entries: []sdk.GraphEntry{{
				Graph:    sbomGraph,
				Manifest: sdk.ManifestMetadata{Path: filepath.Join(projectRoot, "app.spdx.json"), Kind: "spdx"},
			}}},
		},
	}

	consolidated, err := consolidation.ConsolidateGraphs(results)
	if err != nil {
		t.Fatalf("ConsolidateGraphs() error = %v", err)
	}
	// In the registry-mode model, matcher-supplied license data lives on
	// the PURL-keyed *sdk.PackageRegistry. We seed it once and the scan
	// response output layer (PackageFromDependencyAndRegistry) resolves the
	// license back into every manifest's react package by PURL.
	registry := sdk.NewPackageRegistry()
	reactPkg := registry.Ensure("pkg:npm/react@18.2.0")
	reactPkg.Licenses = []sdk.PackageLicense{{SPDXExpression: "MIT"}}
	reactPkg.Matched = true

	response := output.BuildScanResponse(output.ProjectDescriptor{Name: "demo", Path: projectRoot}, consolidated, registry, nil, time.Now().Add(-time.Second))
	if len(response.Manifests) != 2 {
		t.Fatalf("expected 2 manifests, got %d", len(response.Manifests))
	}
	for _, manifest := range response.Manifests {
		found := false
		for _, pkg := range manifest.Packages {
			if pkg.Purl != "pkg:npm/react@18.2.0" {
				continue
			}
			found = true
			if got := len(pkg.Licenses); got != 1 || pkg.Licenses[0].SPDXExpression != "MIT" {
				t.Fatalf("expected manifest %q to include propagated MIT license, got %#v", manifest.Path, pkg.Licenses)
			}
		}
		if !found {
			t.Fatalf("expected manifest %q to contain react package", manifest.Path)
		}
	}
}

func sbomDiffResults(graph *sdk.Graph, location, manifestPath string) []sdk.DetectionResult {
	return []sdk.DetectionResult{{
		SubprojectInfo: sdk.Subproject{
			ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: location},
			RelativePath:            filepath.Base(location),
			PrimaryDetector:         "sbom-detector",
			DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerSBOM},
			Ecosystem:               sdk.EcosystemSBOM,
		},
		DetectorName: "sbom-detector",
		Origin:       sdk.CoreOrigin,
		Technique:    sdk.SBOMTechnique,
		Graphs: &sdk.GraphContainer{Entries: []sdk.GraphEntry{{
			Graph:    graph,
			Manifest: sdk.ManifestMetadata{Path: manifestPath, Kind: "spdx"},
		}}},
	}}
}

func TestBuildDiffResponseFuzzyReconcilesRenamedPackage(t *testing.T) {
	baseGraph := sdk.New()
	headGraph := sdk.New()

	baseApp := sdk.NewDependency(sdk.Dependency{Ecosystem: "npm", BuildSystem: "npm", Name: "app", Version: "1.0.0"})
	baseDep := sdk.NewDependency(sdk.Dependency{Ecosystem: "npm", BuildSystem: "npm", Name: "left-pad", Version: "1.0.0"})
	headApp := sdk.NewDependency(sdk.Dependency{Ecosystem: "npm", BuildSystem: "npm", Name: "app", Version: "1.0.0"})
	headDep := sdk.NewDependency(sdk.Dependency{Ecosystem: "npm", BuildSystem: "npm", Name: "leftpad", Version: "1.1.0"})

	for _, pkg := range []*sdk.Dependency{baseApp, baseDep} {
		if err := baseGraph.AddNode(pkg); err != nil {
			t.Fatalf("base AddPackage(%q) error = %v", pkg.ID, err)
		}
	}
	if err := baseGraph.AddEdge(baseApp.ID, baseDep.ID); err != nil {
		t.Fatalf("base AddDependency() error = %v", err)
	}
	for _, pkg := range []*sdk.Dependency{headApp, headDep} {
		if err := headGraph.AddNode(pkg); err != nil {
			t.Fatalf("head AddPackage(%q) error = %v", pkg.ID, err)
		}
	}
	if err := headGraph.AddEdge(headApp.ID, headDep.ID); err != nil {
		t.Fatalf("head AddDependency() error = %v", err)
	}

	baseResults := []sdk.DetectionResult{{
		SubprojectInfo: sdk.Subproject{
			ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: "/tmp/demo"},
			RelativePath:            ".",
			PrimaryDetector:         "npm-detector",
			DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
			Ecosystem:               sdk.EcosystemNPM,
		},
		Graphs: &sdk.GraphContainer{Entries: []sdk.GraphEntry{{
			Graph:    baseGraph,
			Manifest: sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"},
		}}},
	}}
	headResults := []sdk.DetectionResult{{
		SubprojectInfo: sdk.Subproject{
			ExecutionTarget:         sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: "/tmp/demo"},
			RelativePath:            ".",
			PrimaryDetector:         "npm-detector",
			DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
			Ecosystem:               sdk.EcosystemNPM,
		},
		Graphs: &sdk.GraphContainer{Entries: []sdk.GraphEntry{{
			Graph:    headGraph,
			Manifest: sdk.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"},
		}}},
	}}

	baseConsolidated, err := consolidation.ConsolidateGraphs(baseResults)
	if err != nil {
		t.Fatalf("ConsolidateGraphs(base) error = %v", err)
	}
	headConsolidated, err := consolidation.ConsolidateGraphs(headResults)
	if err != nil {
		t.Fatalf("ConsolidateGraphs(head) error = %v", err)
	}

	response := output.BuildDiffResponse("/tmp/demo", "base", "head", baseConsolidated, headConsolidated, nil, time.Now().Add(-time.Second))
	if response.Summary.ChangedPackageCount != 1 {
		t.Fatalf("expected fuzzy reconciliation to mark one changed package, got %#v", response.Summary)
	}
	if response.Summary.AddedPackageCount != 0 || response.Summary.RemovedPackageCount != 0 {
		t.Fatalf("expected no residual add/remove after fuzzy reconciliation, got %#v", response.Summary)
	}
	if response.Summary.FuzzyMatchCount != 1 || response.Summary.UnmatchedPackageCount != 0 {
		t.Fatalf("expected fuzzy match diagnostics, got %#v", response.Summary)
	}
	if len(response.Results.Manifests) != 1 || len(response.Results.Manifests[0].Changed) != 1 {
		t.Fatalf("expected one changed package in manifest, got %#v", response.Results.Manifests)
	}
	changed := response.Results.Manifests[0].Changed[0]
	if changed.After.Metadata == nil {
		t.Fatalf("expected fuzzy metadata on reconciled package: %#v", changed.After)
	}
	if changed.After.Metadata["bomly.diff.fuzzy_reconciled"] != true {
		t.Fatalf("expected fuzzy reconciliation marker, got %#v", changed.After.Metadata)
	}
}

func newViewTestGraph(t *testing.T) *sdk.Graph {
	t.Helper()
	g := sdk.New()
	for _, pkg := range []*sdk.Dependency{
		sdk.NewDependencyRef("app", "1.0.0"),
		sdk.NewDependencyRef("react", "18.2.0"),
		sdk.NewDependencyRef("zod", "3.23.0"),
		sdk.NewDependencyRef("loose-envify", "1.4.0"),
	} {
		if err := g.AddNode(pkg); err != nil {
			t.Fatalf("add package %s: %v", pkg.ID, err)
		}
	}
	if err := g.AddEdge("app@1.0.0", "react@18.2.0"); err != nil {
		t.Fatalf("add dependency: %v", err)
	}
	if err := g.AddEdge("app@1.0.0", "zod@3.23.0"); err != nil {
		t.Fatalf("add dependency: %v", err)
	}
	if err := g.AddEdge("react@18.2.0", "loose-envify@1.4.0"); err != nil {
		t.Fatalf("add dependency: %v", err)
	}
	return g
}

func scanPackageByName(t *testing.T, packages []output.ScanPackage, name string) output.ScanPackage {
	t.Helper()
	for _, pkg := range packages {
		if pkg.Name == name {
			return pkg
		}
	}
	t.Fatalf("package %q not found in %#v", name, packages)
	return output.ScanPackage{}
}
