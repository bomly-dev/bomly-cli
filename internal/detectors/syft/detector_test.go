//go:build bomly_builtin_syft

package syft

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/anchore/syft/syft/artifact"
	syftcpe "github.com/anchore/syft/syft/cpe"
	syftfile "github.com/anchore/syft/syft/file"
	syftpkg "github.com/anchore/syft/syft/pkg"
	syftsbom "github.com/anchore/syft/syft/sbom"
	"github.com/bomly/bomly-cli/internal/detectors"
)

func TestDetectorApplicable(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}

	detector := Detector{}
	applicable, err := detector.Applicable(context.Background(), detectors.ResolveGraphRequest{ProjectPath: projectDir, PackageManager: detectors.PackageManagerNPM})
	if err != nil {
		t.Fatalf("Applicable() error = %v", err)
	}
	if !applicable {
		t.Fatal("expected detector to be applicable")
	}
}

func TestDetectorApplicable_ReturnsFalseWithoutNPMManifest(t *testing.T) {
	detector := Detector{}
	applicable, err := detector.Applicable(context.Background(), detectors.ResolveGraphRequest{ProjectPath: t.TempDir(), PackageManager: detectors.PackageManagerNPM})
	if err != nil {
		t.Fatalf("Applicable() error = %v", err)
	}
	if applicable {
		t.Fatal("expected detector to be inapplicable")
	}
}

func TestDetectorApplicable_PythonManifest(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "pyproject.toml"), []byte("[project]\nname = \"demo\"\n"), 0o644); err != nil {
		t.Fatalf("write pyproject.toml: %v", err)
	}

	detector := Detector{}
	applicable, err := detector.Applicable(context.Background(), detectors.ResolveGraphRequest{ProjectPath: projectDir, PackageManager: detectors.PackageManagerPoetry})
	if err != nil {
		t.Fatalf("Applicable() error = %v", err)
	}
	if !applicable {
		t.Fatal("expected detector to be applicable for Python manifests")
	}
}

func TestDetectorApplicable_RustManifest(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "Cargo.lock"), []byte("version = 3\n"), 0o644); err != nil {
		t.Fatalf("write Cargo.lock: %v", err)
	}

	detector := Detector{}
	applicable, err := detector.Applicable(context.Background(), detectors.ResolveGraphRequest{ProjectPath: projectDir, PackageManager: detectors.PackageManagerCargo})
	if err != nil {
		t.Fatalf("Applicable() error = %v", err)
	}
	if !applicable {
		t.Fatal("expected detector to be applicable for Cargo.lock")
	}
}

func TestDetectorApplicable_ContainerTarget(t *testing.T) {
	detector := Detector{}
	applicable, err := detector.Applicable(context.Background(), detectors.ResolveGraphRequest{
		ExecutionTarget: detectors.ExecutionTarget{Kind: detectors.ExecutionTargetContainerImage, Location: "alpine:3.20"},
		PackageManager:  detectors.PackageManagerRPM,
	})
	if err != nil {
		t.Fatalf("Applicable() error = %v", err)
	}
	if !applicable {
		t.Fatal("expected detector to be applicable for container targets")
	}
}

func TestDetectorDescriptor_AdvertisesAuditEnrichment(t *testing.T) {
	descriptor := Detector{}.Descriptor()
	found := false
	for _, capability := range descriptor.Capabilities {
		if capability == "audit-enrichment" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected syft detector capabilities to include audit-enrichment, got %#v", descriptor.Capabilities)
	}
}

func TestSyftCommandArgs_AddsEnrichmentFlagsForAuditedScans(t *testing.T) {
	args := syftCommandArgs(".", detectors.ResolveGraphRequest{EnrichmentEnabled: true})
	want := []string{".", "-o", "spdx-json", "--enrich", "golang", "--enrich", "java", "--enrich", "javascript", "--enrich", "python"}
	if len(args) != len(want) {
		t.Fatalf("expected %d args, got %d: %#v", len(want), len(args), args)
	}
	for idx := range want {
		if args[idx] != want[idx] {
			t.Fatalf("arg %d = %q, want %q", idx, args[idx], want[idx])
		}
	}
}

func TestSyftCreateSBOMConfig_EnablesOfflineSafeAuditEnrichment(t *testing.T) {
	cfg := syftCreateSBOMConfig(detectors.ResolveGraphRequest{EnrichmentEnabled: true})
	if !cfg.Packages.Golang.SearchLocalModCacheLicenses {
		t.Fatal("expected golang local mod cache license enrichment to be enabled")
	}
	if !cfg.Packages.Golang.SearchLocalVendorLicenses {
		t.Fatal("expected golang local vendor license enrichment to be enabled")
	}
	if cfg.Packages.Golang.SearchRemoteLicenses {
		t.Fatal("expected golang remote license enrichment to remain disabled")
	}
	if !cfg.Packages.JavaArchive.UseMavenLocalRepository {
		t.Fatal("expected java local maven repository enrichment to be enabled")
	}
	if cfg.Packages.JavaArchive.UseNetwork {
		t.Fatal("expected java network enrichment to remain disabled")
	}
	if cfg.Packages.JavaScript.SearchRemoteLicenses {
		t.Fatal("expected javascript remote enrichment to remain disabled by default")
	}
	if cfg.Packages.Python.SearchRemoteLicenses {
		t.Fatal("expected python remote enrichment to remain disabled by default")
	}
}

func TestSyftSourceInput_UsesFileSourceForSingleFileTargets(t *testing.T) {
	projectFile := filepath.Join(t.TempDir(), "Cargo.lock")
	if err := os.WriteFile(projectFile, []byte("version = 3\n"), 0o644); err != nil {
		t.Fatalf("write Cargo.lock: %v", err)
	}

	target, mode, cfg := syftSourceInput(detectors.ExecutionTarget{Kind: detectors.ExecutionTargetFilesystem, Location: projectFile}, projectFile)
	if target != projectFile {
		t.Fatalf("expected target %q, got %q", projectFile, target)
	}
	if mode != "file" {
		t.Fatalf("expected file source mode, got %q", mode)
	}
	if len(cfg.Sources) != 1 || cfg.Sources[0] != "file" {
		t.Fatalf("expected file source config, got %#v", cfg.Sources)
	}
}

func TestSyftSourceInput_UsesDirectorySourceForFilesystemTargets(t *testing.T) {
	projectDir := t.TempDir()

	target, mode, cfg := syftSourceInput(detectors.ExecutionTarget{Kind: detectors.ExecutionTargetFilesystem, Location: projectDir}, filepath.Join(projectDir, "package.json"))
	if target != projectDir {
		t.Fatalf("expected directory target %q, got %q", projectDir, target)
	}
	if mode != "dir" {
		t.Fatalf("expected dir source mode, got %q", mode)
	}
	if len(cfg.Sources) != 1 || cfg.Sources[0] != "dir" {
		t.Fatalf("expected dir source config, got %#v", cfg.Sources)
	}
}

func TestSyftSourceInput_UsesContainerReferenceForContainerTargets(t *testing.T) {
	target, mode, cfg := syftSourceInput(detectors.ExecutionTarget{Kind: detectors.ExecutionTargetContainerImage, Location: "alpine:3.20"}, t.TempDir())
	if target != "alpine:3.20" {
		t.Fatalf("expected container target, got %q", target)
	}
	if mode != "container" {
		t.Fatalf("expected container source mode, got %q", mode)
	}
	if len(cfg.Sources) != 0 {
		t.Fatalf("expected default source resolution for containers, got %#v", cfg.Sources)
	}
}

func TestGraphFromSyftSBOM(t *testing.T) {
	app := syftpkg.Package{
		Name:      "demo-app",
		Version:   "1.0.0",
		Type:      syftpkg.NpmPkg,
		Language:  syftpkg.JavaScript,
		PURL:      "pkg:npm/demo-app@1.0.0",
		FoundBy:   "package-lock-cataloger",
		Locations: syftfile.NewLocationSet(syftfile.NewLocation("package-lock.json")),
		Licenses:  syftpkg.NewLicenseSet(syftpkg.NewLicense("MIT")),
	}
	app.SetID()

	dependency := syftpkg.Package{
		Name:      "demo-lib",
		Version:   "2.1.0",
		Type:      syftpkg.JavaPkg,
		Language:  syftpkg.Java,
		PURL:      "pkg:maven/com.example/demo-lib@2.1.0",
		FoundBy:   "pom-cataloger",
		Locations: syftfile.NewLocationSet(syftfile.NewLocation("pom.xml")),
		Licenses:  syftpkg.NewLicenseSet(syftpkg.NewLicense("Apache-2.0")),
		CPEs:      []syftcpe.CPE{syftcpe.Must("cpe:2.3:a:example:demo-lib:2.1.0:*:*:*:*:*:*:*", syftcpe.GeneratedSource)},
	}
	dependency.SetID()

	s := &syftsbom.SBOM{
		Artifacts: syftsbom.Artifacts{
			Packages: syftpkg.NewCollection(app, dependency),
		},
		Relationships: []artifact.Relationship{
			{From: dependency, To: app, Type: artifact.DependencyOfRelationship},
		},
	}

	depsGraph, err := graphFromSyftSBOM(s)
	if err != nil {
		t.Fatalf("graphFromSyftSBOM() error = %v", err)
	}
	if got := depsGraph.Size(); got != 2 {
		t.Fatalf("expected graph size 2, got %d", got)
	}
	deps, err := depsGraph.Dependencies(string(app.ID()))
	if err != nil {
		t.Fatalf("Dependencies() error = %v", err)
	}
	if len(deps) != 1 || deps[0].ID != string(dependency.ID()) {
		t.Fatalf("unexpected dependencies: %#v", deps)
	}

	mapped, ok := depsGraph.Package(string(dependency.ID()))
	if !ok {
		t.Fatalf("expected dependency package %q", dependency.ID())
	}
	if mapped.Ecosystem != "maven" || mapped.Org != "com.example" || mapped.Type != string(syftpkg.JavaPkg) {
		t.Fatalf("unexpected mapped package identity: %#v", mapped)
	}
	if mapped.PURL != dependency.PURL || mapped.Language != dependency.Language.String() || mapped.FoundBy != dependency.FoundBy {
		t.Fatalf("unexpected mapped package metadata: %#v", mapped)
	}
	if len(mapped.Licenses) != 1 || mapped.Licenses[0].Value != "Apache-2.0" {
		t.Fatalf("unexpected mapped licenses: %#v", mapped.Licenses)
	}
	if len(mapped.Locations) != 1 || mapped.Locations[0].RealPath != "pom.xml" {
		t.Fatalf("unexpected mapped locations: %#v", mapped.Locations)
	}
	if len(mapped.CPEs) != 1 || mapped.CPEs[0] == "" {
		t.Fatalf("unexpected mapped cpes: %#v", mapped.CPEs)
	}
}

func TestGraphContainerFromSyftSBOM_SplitsGraphsByManifestPath(t *testing.T) {
	webApp := syftpkg.Package{
		Name:      "web-app",
		Version:   "1.0.0",
		Type:      syftpkg.NpmPkg,
		Language:  syftpkg.JavaScript,
		PURL:      "pkg:npm/web-app@1.0.0",
		Locations: syftfile.NewLocationSet(syftfile.NewLocation("apps/web/package-lock.json")),
	}
	webApp.SetID()

	webDependency := syftpkg.Package{
		Name:      "react",
		Version:   "18.2.0",
		Type:      syftpkg.NpmPkg,
		Language:  syftpkg.JavaScript,
		PURL:      "pkg:npm/react@18.2.0",
		Locations: syftfile.NewLocationSet(syftfile.NewLocation("apps/web/package-lock.json")),
	}
	webDependency.SetID()

	apiApp := syftpkg.Package{
		Name:      "api-app",
		Version:   "1.0.0",
		Type:      syftpkg.NpmPkg,
		Language:  syftpkg.JavaScript,
		PURL:      "pkg:npm/api-app@1.0.0",
		Locations: syftfile.NewLocationSet(syftfile.NewLocation("apps/api/package-lock.json")),
	}
	apiApp.SetID()

	apiDependency := syftpkg.Package{
		Name:      "express",
		Version:   "4.18.2",
		Type:      syftpkg.NpmPkg,
		Language:  syftpkg.JavaScript,
		PURL:      "pkg:npm/express@4.18.2",
		Locations: syftfile.NewLocationSet(syftfile.NewLocation("apps/api/package-lock.json")),
	}
	apiDependency.SetID()

	s := &syftsbom.SBOM{
		Artifacts: syftsbom.Artifacts{
			Packages: syftpkg.NewCollection(webApp, webDependency, apiApp, apiDependency),
		},
		Relationships: []artifact.Relationship{
			{From: webDependency, To: webApp, Type: artifact.DependencyOfRelationship},
			{From: apiDependency, To: apiApp, Type: artifact.DependencyOfRelationship},
		},
	}

	container, err := graphContainerFromSyftSBOM(s, detectors.PackageManagerNPM)
	if err != nil {
		t.Fatalf("graphContainerFromSyftSBOM() error = %v", err)
	}
	if container == nil || len(container.Entries) != 2 {
		t.Fatalf("expected 2 graph entries, got %#v", container)
	}

	manifests := []string{container.Entries[0].Manifest.Path, container.Entries[1].Manifest.Path}
	if manifests[0] == manifests[1] {
		t.Fatalf("expected separate manifest paths, got %#v", manifests)
	}
}

func TestDetectorResolveGraph_UsesSyftLibrary(t *testing.T) {
	projectDir := writeNPMProject(t)

	detector := Detector{WorkingDir: projectDir}
	result, err := detector.ResolveGraph(context.Background(), detectors.ResolveGraphRequest{
		ProjectPath:    projectDir,
		PackageManager: detectors.PackageManagerNPM,
		Mode:           detectors.TargetModeComponent,
		Query:          detectors.ComponentQuery{Name: "react"},
	})
	if err != nil {
		t.Fatalf("ResolveGraph() error = %v", err)
	}
	if result.Graphs == nil || result.Graphs.Len() == 0 {
		t.Fatal("expected graph container result")
	}
	depsGraph, err := result.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	if depsGraph == nil || depsGraph.Size() < 2 {
		t.Fatalf("expected at least 2 graph packages, got %d", depsGraph.Size())
	}
	foundReact := false
	for _, pkg := range depsGraph.Packages() {
		if pkg.Name == "react" {
			foundReact = true
			break
		}
	}
	if !foundReact {
		t.Fatal("expected graph to contain react package")
	}
}

func writeNPMProject(t *testing.T) string {
	t.Helper()
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package.json"), []byte(`{
		"name": "demo-app",
		"version": "1.0.0",
		"dependencies": {
			"react": "18.2.0"
		}
	}
`), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "package-lock.json"), []byte(`{
		"name": "demo-app",
		"version": "1.0.0",
		"lockfileVersion": 2,
		"requires": true,
		"packages": {
			"": {
				"name": "demo-app",
				"version": "1.0.0",
				"dependencies": {
					"react": "18.2.0"
				}
			},
			"node_modules/react": {
				"version": "18.2.0"
			}
		},
		"dependencies": {
			"react": {
				"version": "18.2.0"
			}
		}
	}
`), 0o644); err != nil {
		t.Fatalf("write package-lock.json: %v", err)
	}
	return projectDir
}
