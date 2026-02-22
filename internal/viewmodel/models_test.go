package viewmodel

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/bomly/bomly-cli/internal/explain"
	"github.com/bomly/bomly-cli/internal/model"
	"github.com/bomly/bomly-cli/internal/output"
	"github.com/bomly/bomly-cli/internal/scan"
)

func TestBuildScanResponseIncludesAuditData(t *testing.T) {
	g := newTestGraph(t)
	started := time.Now().Add(-2 * time.Second)
	results := []scan.ResolveGraphResult{{
		SubprojectInfo: scan.Subproject{
			RelativePath:   ".",
			PackageManager: scan.PackageManagerNPM,
			Ecosystem:      scan.EcosystemNPM,
		},
		DetectorName: "npm",
		Graphs: &scan.GraphContainer{Entries: []scan.GraphEntry{{
			Graph:    g,
			Manifest: scan.ManifestMetadata{Path: "/tmp/demo/package-lock.json", Kind: "package-lock.json"},
		}}},
	}}

	findings := []scan.Finding{{
		ID:       "OSV-1",
		Kind:     scan.FindingKindVulnerability,
		Severity: "high",
		Package:  model.NewPackageRef("react", "18.2.0"),
		Title:    "Prototype pollution",
		Source:   "osv",
	}}
	consolidated, err := scan.ConsolidateGraphs(results)
	if err != nil {
		t.Fatalf("ConsolidateGraphs() error = %v", err)
	}
	response := BuildScanResponse(output.ProjectDescriptor{Name: "demo", Path: "/tmp/demo"}, consolidated, findings, started)
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

func TestBuildScanResponseDeduplicatesManifestAndPrefersNative(t *testing.T) {
	projectRoot := "/tmp/demo"
	manifestPath := filepath.Join(projectRoot, "package-lock.json")

	syftGraph := model.New()
	if err := syftGraph.AddPackage(model.NewPackageWithID("123", model.Package{
		Name:      "demo-app",
		Version:   "1.0.0",
		Ecosystem: "npm",
		PURL:      "pkg:npm/demo-app@1.0.0",
	})); err != nil {
		t.Fatalf("add syft package: %v", err)
	}

	nativeGraph := newTestGraph(t)
	results := []scan.ResolveGraphResult{
		{
			SubprojectInfo: scan.Subproject{
				ExecutionTarget: scan.ExecutionTarget{Kind: scan.ExecutionTargetFilesystem, Location: projectRoot},
				RelativePath:    ".",
				PackageManager:  scan.PackageManagerNPM,
				Ecosystem:       scan.EcosystemNPM,
			},
			DetectorName: "syft-detector",
			DetectorType: scan.ThirdPartyDetector,
			Graphs: &scan.GraphContainer{Entries: []scan.GraphEntry{{
				Graph:    syftGraph,
				Manifest: scan.ManifestMetadata{Path: manifestPath, Kind: "package-lock.json"},
			}}},
		},
		{
			SubprojectInfo: scan.Subproject{
				ExecutionTarget: scan.ExecutionTarget{Kind: scan.ExecutionTargetFilesystem, Location: projectRoot},
				RelativePath:    ".",
				PackageManager:  scan.PackageManagerNPM,
				Ecosystem:       scan.EcosystemNPM,
			},
			DetectorName: "npm-detector",
			DetectorType: scan.NativeDetector,
			Graphs: &scan.GraphContainer{Entries: []scan.GraphEntry{{
				Graph:    nativeGraph,
				Manifest: scan.ManifestMetadata{Path: manifestPath, Kind: "package-lock.json"},
			}}},
		},
	}

	consolidated, err := scan.ConsolidateGraphs(results)
	if err != nil {
		t.Fatalf("ConsolidateGraphs() error = %v", err)
	}
	response := BuildScanResponse(output.ProjectDescriptor{Name: "demo", Path: projectRoot}, consolidated, nil, time.Now().Add(-time.Second))
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

	nativeGraph := newTestGraph(t)
	syftGraph := model.New()
	if err := syftGraph.AddPackage(model.NewPackageWithID("123", model.Package{
		Name:      "demo-app",
		Version:   "1.0.0",
		Ecosystem: "npm",
		PURL:      "pkg:npm/demo-app@1.0.0",
	})); err != nil {
		t.Fatalf("add syft package: %v", err)
	}

	results := []scan.ResolveGraphResult{
		{
			SubprojectInfo: scan.Subproject{
				ExecutionTarget: scan.ExecutionTarget{Kind: scan.ExecutionTargetFilesystem, Location: projectRoot},
				RelativePath:    ".",
				PackageManager:  scan.PackageManagerNPM,
				Ecosystem:       scan.EcosystemNPM,
			},
			DetectorName: "npm-detector",
			DetectorType: scan.NativeDetector,
			Graphs: &scan.GraphContainer{Entries: []scan.GraphEntry{{
				Graph:    nativeGraph,
				Manifest: scan.ManifestMetadata{Path: manifestPath, Kind: "package-lock.json"},
			}}},
		},
		{
			SubprojectInfo: scan.Subproject{
				ExecutionTarget: scan.ExecutionTarget{Kind: scan.ExecutionTargetFilesystem, Location: projectRoot},
				RelativePath:    ".",
				PackageManager:  scan.PackageManagerNPM,
				Ecosystem:       scan.EcosystemNPM,
			},
			DetectorName: "syft-detector",
			DetectorType: scan.ThirdPartyDetector,
			Graphs: &scan.GraphContainer{Entries: []scan.GraphEntry{{
				Graph:    syftGraph,
				Manifest: scan.ManifestMetadata{Path: "package-lock.json", Kind: "npm-lockfile"},
			}}},
		},
	}

	consolidated, err := scan.ConsolidateGraphs(results)
	if err != nil {
		t.Fatalf("ConsolidateGraphs() error = %v", err)
	}
	response := BuildScanResponse(output.ProjectDescriptor{Name: "demo", Path: projectRoot}, consolidated, nil, time.Now().Add(-time.Second))
	if len(response.Manifests) != 1 {
		t.Fatalf("expected same manifest file to deduplicate despite metadata drift, got %#v", response.Manifests)
	}
	if response.Manifests[0].Kind != "package-lock.json" {
		t.Fatalf("expected native manifest metadata to win, got %q", response.Manifests[0].Kind)
	}
}

func TestBuildExplainResponseFlattensSingleTarget(t *testing.T) {
	started := time.Now().Add(-1 * time.Second)
	targets := []ExplainTargetResponse{{
		Project:    output.ProjectDescriptor{Name: "demo"},
		Dependency: output.PackageRef{Name: "react", ID: "react@18.2.0"},
		Paths:      []explain.Path{{Relationship: "direct"}},
	}}

	response := BuildExplainResponse(output.ProjectDescriptor{Name: "demo"}, "react", targets, started)
	if response.Dependency.ID != "react@18.2.0" {
		t.Fatalf("expected flattened dependency, got %#v", response.Dependency)
	}
	if len(response.Paths) != 1 {
		t.Fatalf("expected flattened paths, got %#v", response.Paths)
	}
}

func TestBuildDiffResponseAggregatesManifestChanges(t *testing.T) {
	baseGraph := newTestGraph(t)
	headGraph := newTestGraph(t)
	if err := headGraph.AddPackage(model.NewPackageRef("newpkg", "1.0.0")); err != nil {
		t.Fatalf("add package: %v", err)
	}
	if err := headGraph.AddDependency("app@1.0.0", "newpkg@1.0.0"); err != nil {
		t.Fatalf("add dependency: %v", err)
	}

	baseResults := []scan.ResolveGraphResult{{
		SubprojectInfo: scan.Subproject{RelativePath: ".", PackageManager: scan.PackageManagerNPM, Ecosystem: scan.EcosystemNPM},
		Graphs: &scan.GraphContainer{Entries: []scan.GraphEntry{{
			Graph:    baseGraph,
			Manifest: scan.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"},
		}}},
	}}
	headResults := []scan.ResolveGraphResult{{
		SubprojectInfo: scan.Subproject{RelativePath: ".", PackageManager: scan.PackageManagerNPM, Ecosystem: scan.EcosystemNPM},
		Graphs: &scan.GraphContainer{Entries: []scan.GraphEntry{{
			Graph:    headGraph,
			Manifest: scan.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"},
		}}},
	}}

	baseConsolidated, err := scan.ConsolidateGraphs(baseResults)
	if err != nil {
		t.Fatalf("ConsolidateGraphs(base) error = %v", err)
	}
	headConsolidated, err := scan.ConsolidateGraphs(headResults)
	if err != nil {
		t.Fatalf("ConsolidateGraphs(head) error = %v", err)
	}
	response := BuildDiffResponse("/tmp/demo", "base", "head", baseConsolidated, headConsolidated, nil, time.Now().Add(-time.Second))
	if response.Command != "diff" {
		t.Fatalf("expected diff command, got %q", response.Command)
	}
	if response.Summary.ChangedManifestCount != 1 || response.Summary.AddedPackageCount != 1 {
		t.Fatalf("unexpected diff summary: %#v", response.Summary)
	}
	if len(response.Results.Manifests) != 1 || response.Results.Manifests[0].Status != "changed" {
		t.Fatalf("unexpected manifest results: %#v", response.Results.Manifests)
	}
}

func TestBuildDiffResponseTreatsSBOMFilesAsSameManifestWhenOnlyEvidencePathDiffers(t *testing.T) {
	baseGraph := newTestGraph(t)
	headGraph := newTestGraph(t)
	if err := headGraph.AddPackage(model.NewPackageRef("newpkg", "1.0.0")); err != nil {
		t.Fatalf("add package: %v", err)
	}
	if err := headGraph.AddDependency("app@1.0.0", "newpkg@1.0.0"); err != nil {
		t.Fatalf("add dependency: %v", err)
	}

	baseTarget := scan.ExecutionTarget{Kind: scan.ExecutionTargetFilesystem, Location: "/tmp/base.spdx.json"}
	headTarget := scan.ExecutionTarget{Kind: scan.ExecutionTargetFilesystem, Location: "/tmp/head.spdx.json"}
	baseResults := []scan.ResolveGraphResult{{
		SubprojectInfo: scan.Subproject{
			ExecutionTarget: baseTarget,
			RelativePath:    "base.spdx.json",
			PackageManager:  scan.PackageManagerSBOM,
			Ecosystem:       scan.EcosystemSBOM,
		},
		Graphs: &scan.GraphContainer{Entries: []scan.GraphEntry{{
			Graph:    baseGraph,
			Manifest: scan.ManifestMetadata{Path: baseTarget.Location, Kind: "github.spdx"},
		}}},
	}}
	headResults := []scan.ResolveGraphResult{{
		SubprojectInfo: scan.Subproject{
			ExecutionTarget: headTarget,
			RelativePath:    "head.spdx.json",
			PackageManager:  scan.PackageManagerSBOM,
			Ecosystem:       scan.EcosystemSBOM,
		},
		Graphs: &scan.GraphContainer{Entries: []scan.GraphEntry{{
			Graph:    headGraph,
			Manifest: scan.ManifestMetadata{Path: headTarget.Location, Kind: "bomly.spdx"},
		}}},
	}}

	baseConsolidated, err := scan.ConsolidateGraphs(baseResults)
	if err != nil {
		t.Fatalf("ConsolidateGraphs(base) error = %v", err)
	}
	headConsolidated, err := scan.ConsolidateGraphs(headResults)
	if err != nil {
		t.Fatalf("ConsolidateGraphs(head) error = %v", err)
	}

	response := BuildDiffResponse("/tmp/demo", "base", "head", baseConsolidated, headConsolidated, nil, time.Now().Add(-time.Second))
	if response.Summary.ChangedManifestCount != 1 {
		t.Fatalf("expected one changed manifest, got %#v", response.Summary)
	}
	if response.Summary.AddedManifestCount != 0 || response.Summary.RemovedManifestCount != 0 {
		t.Fatalf("expected synthetic SBOM manifest matching, got %#v", response.Summary)
	}
}

func TestBuildScanResponsePreservesPropagatedLicensesAcrossDuplicateManifests(t *testing.T) {
	projectRoot := "/tmp/demo"
	nativeGraph := model.New()
	nativeApp := model.NewPackageWithID("pkg:npm/app@1.0.0", model.Package{
		Ecosystem:   "npm",
		BuildSystem: "npm",
		Name:        "app",
		Version:     "1.0.0",
		PURL:        "pkg:npm/app@1.0.0",
	})
	if err := nativeGraph.AddPackage(nativeApp); err != nil {
		t.Fatalf("add native app: %v", err)
	}
	nativeReact := model.NewPackageWithID("pkg:npm/react@18.2.0", model.Package{
		Ecosystem:   "npm",
		BuildSystem: "npm",
		Name:        "react",
		Version:     "18.2.0",
		PURL:        "pkg:npm/react@18.2.0",
	})
	if err := nativeGraph.AddPackage(nativeReact); err != nil {
		t.Fatalf("add native react: %v", err)
	}
	if err := nativeGraph.AddDependency(nativeApp.ID, nativeReact.ID); err != nil {
		t.Fatalf("add native dependency: %v", err)
	}

	sbomGraph := model.New()
	if err := sbomGraph.AddPackage(model.NewPackageWithID("SPDXRef-app", model.Package{
		Ecosystem:   "npm",
		BuildSystem: "npm",
		Name:        "app",
		Version:     "1.0.0",
		PURL:        "pkg:npm/app@1.0.0",
	})); err != nil {
		t.Fatalf("add sbom app: %v", err)
	}
	if err := sbomGraph.AddPackage(model.NewPackageWithID("SPDXRef-react", model.Package{
		Ecosystem:   "npm",
		BuildSystem: "npm",
		Name:        "react",
		Version:     "18.2.0",
		PURL:        "pkg:npm/react@18.2.0",
	})); err != nil {
		t.Fatalf("add sbom react: %v", err)
	}
	if err := sbomGraph.AddDependency("SPDXRef-app", "SPDXRef-react"); err != nil {
		t.Fatalf("add sbom dependency: %v", err)
	}

	results := []scan.ResolveGraphResult{
		{
			SubprojectInfo: scan.Subproject{
				ExecutionTarget: scan.ExecutionTarget{Kind: scan.ExecutionTargetFilesystem, Location: projectRoot},
				RelativePath:    ".",
				PackageManager:  scan.PackageManagerNPM,
				Ecosystem:       scan.EcosystemNPM,
			},
			DetectorName: "npm-detector",
			DetectorType: scan.NativeDetector,
			Graphs: &scan.GraphContainer{Entries: []scan.GraphEntry{{
				Graph:    nativeGraph,
				Manifest: scan.ManifestMetadata{Path: filepath.Join(projectRoot, "package-lock.json"), Kind: "package-lock.json"},
			}}},
		},
		{
			SubprojectInfo: scan.Subproject{
				ExecutionTarget: scan.ExecutionTarget{Kind: scan.ExecutionTargetFilesystem, Location: projectRoot},
				RelativePath:    "app.spdx.json",
				PackageManager:  scan.PackageManagerSBOM,
				Ecosystem:       scan.EcosystemSBOM,
			},
			DetectorName: "sbom-detector",
			DetectorType: scan.NativeDetector,
			Graphs: &scan.GraphContainer{Entries: []scan.GraphEntry{{
				Graph:    sbomGraph,
				Manifest: scan.ManifestMetadata{Path: filepath.Join(projectRoot, "app.spdx.json"), Kind: "spdx"},
			}}},
		},
	}

	consolidated, err := scan.ConsolidateGraphs(results)
	if err != nil {
		t.Fatalf("ConsolidateGraphs() error = %v", err)
	}
	enrichedGraph, err := consolidated.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	pkg, ok := enrichedGraph.Package("pkg:npm/react@18.2.0")
	if !ok || pkg == nil {
		t.Fatalf("expected enriched graph react package, got %s", enrichedGraph.PrettyString())
	}
	pkg.Licenses = []model.PackageLicense{{SPDXExpression: "MIT"}}
	pkg.Matched = true
	scan.SyncConsolidatedEnrichmentToManifests(&consolidated, enrichedGraph)

	response := BuildScanResponse(output.ProjectDescriptor{Name: "demo", Path: projectRoot}, consolidated, nil, time.Now().Add(-time.Second))
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

func TestBuildDiffResponseFuzzyReconcilesRenamedPackage(t *testing.T) {
	baseGraph := model.New()
	headGraph := model.New()

	baseApp := model.NewPackage(model.Package{Ecosystem: "npm", BuildSystem: "npm", Name: "app", Version: "1.0.0"})
	baseDep := model.NewPackage(model.Package{Ecosystem: "npm", BuildSystem: "npm", Name: "left-pad", Version: "1.0.0"})
	headApp := model.NewPackage(model.Package{Ecosystem: "npm", BuildSystem: "npm", Name: "app", Version: "1.0.0"})
	headDep := model.NewPackage(model.Package{Ecosystem: "npm", BuildSystem: "npm", Name: "leftpad", Version: "1.1.0"})

	for _, pkg := range []*model.Package{baseApp, baseDep} {
		if err := baseGraph.AddPackage(pkg); err != nil {
			t.Fatalf("base AddPackage(%q) error = %v", pkg.ID, err)
		}
	}
	if err := baseGraph.AddDependency(baseApp.ID, baseDep.ID); err != nil {
		t.Fatalf("base AddDependency() error = %v", err)
	}
	for _, pkg := range []*model.Package{headApp, headDep} {
		if err := headGraph.AddPackage(pkg); err != nil {
			t.Fatalf("head AddPackage(%q) error = %v", pkg.ID, err)
		}
	}
	if err := headGraph.AddDependency(headApp.ID, headDep.ID); err != nil {
		t.Fatalf("head AddDependency() error = %v", err)
	}

	baseResults := []scan.ResolveGraphResult{{
		SubprojectInfo: scan.Subproject{
			ExecutionTarget: scan.ExecutionTarget{Kind: scan.ExecutionTargetFilesystem, Location: "/tmp/demo"},
			RelativePath:    ".",
			PackageManager:  scan.PackageManagerNPM,
			Ecosystem:       scan.EcosystemNPM,
		},
		Graphs: &scan.GraphContainer{Entries: []scan.GraphEntry{{
			Graph:    baseGraph,
			Manifest: scan.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"},
		}}},
	}}
	headResults := []scan.ResolveGraphResult{{
		SubprojectInfo: scan.Subproject{
			ExecutionTarget: scan.ExecutionTarget{Kind: scan.ExecutionTargetFilesystem, Location: "/tmp/demo"},
			RelativePath:    ".",
			PackageManager:  scan.PackageManagerNPM,
			Ecosystem:       scan.EcosystemNPM,
		},
		Graphs: &scan.GraphContainer{Entries: []scan.GraphEntry{{
			Graph:    headGraph,
			Manifest: scan.ManifestMetadata{Path: "package-lock.json", Kind: "package-lock.json"},
		}}},
	}}

	baseConsolidated, err := scan.ConsolidateGraphs(baseResults)
	if err != nil {
		t.Fatalf("ConsolidateGraphs(base) error = %v", err)
	}
	headConsolidated, err := scan.ConsolidateGraphs(headResults)
	if err != nil {
		t.Fatalf("ConsolidateGraphs(head) error = %v", err)
	}

	response := BuildDiffResponse("/tmp/demo", "base", "head", baseConsolidated, headConsolidated, nil, time.Now().Add(-time.Second))
	if response.Summary.ChangedPackageCount != 1 {
		t.Fatalf("expected fuzzy reconciliation to mark one changed package, got %#v", response.Summary)
	}
	if response.Summary.AddedPackageCount != 0 || response.Summary.RemovedPackageCount != 0 {
		t.Fatalf("expected no residual add/remove after fuzzy reconciliation, got %#v", response.Summary)
	}
	if len(response.Results.Manifests) != 1 || len(response.Results.Manifests[0].Changed) != 1 {
		t.Fatalf("expected one changed package in manifest, got %#v", response.Results.Manifests)
	}
	changed := response.Results.Manifests[0].Changed[0]
	if changed.After.Metadata == nil {
		t.Fatalf("expected fuzzy metadata on reconciled package: %#v", changed.After)
	}
	if changed.After.Metadata[diffFuzzyReconciledKey] != true {
		t.Fatalf("expected fuzzy reconciliation marker, got %#v", changed.After.Metadata)
	}
}

func newTestGraph(t *testing.T) *model.Graph {
	t.Helper()
	g := model.New()
	for _, pkg := range []*model.Package{
		model.NewPackageRef("app", "1.0.0"),
		model.NewPackageRef("react", "18.2.0"),
		model.NewPackageRef("zod", "3.23.0"),
		model.NewPackageRef("loose-envify", "1.4.0"),
	} {
		if err := g.AddPackage(pkg); err != nil {
			t.Fatalf("add package %s: %v", pkg.ID, err)
		}
	}
	if err := g.AddDependency("app@1.0.0", "react@18.2.0"); err != nil {
		t.Fatalf("add dependency: %v", err)
	}
	if err := g.AddDependency("app@1.0.0", "zod@3.23.0"); err != nil {
		t.Fatalf("add dependency: %v", err)
	}
	if err := g.AddDependency("react@18.2.0", "loose-envify@1.4.0"); err != nil {
		t.Fatalf("add dependency: %v", err)
	}
	return g
}
