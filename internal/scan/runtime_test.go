package scan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrepare_PlansFilesystemFallbackChain(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}

	registry := NewRegistry()
	syftDetector := fakeDetector{
		descriptor: DetectorDescriptor{
			Name:           "syft-detector",
			SupportedModes: []TargetMode{TargetModeFullGraph},
		},
	}
	registry.RegisterDetector(fakeFallbackDetector{
		fakeDetector: fakeDetector{
			descriptor: DetectorDescriptor{
				Name:                "npm-detector",
				SupportedEcosystems: []Ecosystem{EcosystemNPM},
				SupportedManagers:   []PackageManager{PackageManagerNPM},
				SupportedModes:      []TargetMode{TargetModeFullGraph},
			},
		},
		fallback: syftDetector,
	})
	registry.RegisterDetector(syftDetector)

	runtime, err := Prepare(PrepareRequest{
		Registry:        registry,
		ExecutionTarget: ExecutionTarget{Kind: ExecutionTargetFilesystem, Location: projectDir},
	})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if len(runtime.Subprojects) != 1 {
		t.Fatalf("expected 1 subproject, got %d", len(runtime.Subprojects))
	}
	if got := runtime.Subprojects[0].PackageManager; got != PackageManagerNPM {
		t.Fatalf("expected npm package manager, got %q", got.Name())
	}
	want := []string{"npm-detector", "syft-detector"}
	if len(runtime.Subprojects[0].PlannedDetectors) != len(want) {
		t.Fatalf("expected planned detectors %#v, got %#v", want, runtime.Subprojects[0].PlannedDetectors)
	}
	for i, detectorName := range want {
		if runtime.Subprojects[0].PlannedDetectors[i] != detectorName {
			t.Fatalf("expected planned detectors %#v, got %#v", want, runtime.Subprojects[0].PlannedDetectors)
		}
	}
}

func TestPrepare_PlansFilesystemWithSyftOnlyFilter(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}

	registry := NewRegistry()
	registry.RegisterDetector(fakeDetector{
		descriptor: DetectorDescriptor{
			Name:           "syft-detector",
			SupportedModes: []TargetMode{TargetModeFullGraph},
		},
	})

	runtime, err := Prepare(PrepareRequest{
		Registry:        registry,
		ExecutionTarget: ExecutionTarget{Kind: ExecutionTargetFilesystem, Location: projectDir},
		DetectorFilter:  DetectorFilter{Include: []string{"syft-detector"}},
	})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if len(runtime.Subprojects) != 1 {
		t.Fatalf("expected 1 subproject, got %d", len(runtime.Subprojects))
	}
	if got := runtime.Subprojects[0].PackageManager; got != PackageManagerNPM {
		t.Fatalf("expected npm package manager, got %q", got.Name())
	}
	if got := runtime.Subprojects[0].PlannedDetectors; len(got) != 1 || got[0] != "syft-detector" {
		t.Fatalf("expected syft-only detector chain, got %#v", got)
	}
}

func TestPrepare_PlansFilesystemSingleFileWithSyftOnlyFilter(t *testing.T) {
	projectFile := filepath.Join(t.TempDir(), "Cargo.lock")
	if err := os.WriteFile(projectFile, []byte("version = 3\n"), 0o644); err != nil {
		t.Fatalf("write Cargo.lock: %v", err)
	}

	registry := NewRegistry()
	registry.RegisterDetector(fakeDetector{
		descriptor: DetectorDescriptor{
			Name:           "syft-detector",
			SupportedModes: []TargetMode{TargetModeFullGraph},
		},
	})

	runtime, err := Prepare(PrepareRequest{
		Registry:        registry,
		ExecutionTarget: ExecutionTarget{Kind: ExecutionTargetFilesystem, Location: projectFile},
		DetectorFilter:  DetectorFilter{Include: []string{"syft-detector"}},
	})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if len(runtime.Subprojects) != 1 {
		t.Fatalf("expected 1 subproject, got %d", len(runtime.Subprojects))
	}
	if got := runtime.Subprojects[0].PackageManager; got != PackageManagerCargo {
		t.Fatalf("expected cargo package manager, got %q", got.Name())
	}
	if got := runtime.Subprojects[0].ExecutionTarget.Location; got != projectFile {
		t.Fatalf("expected execution target %q, got %q", projectFile, got)
	}
	if got := runtime.Subprojects[0].PlannedDetectors; len(got) != 1 || got[0] != "syft-detector" {
		t.Fatalf("expected syft-only detector chain, got %#v", got)
	}
}

func TestPrepare_PlansContainerTargetFromDiscoveryMetadata(t *testing.T) {
	registry := NewRegistry()
	registry.RegisterDetector(fakeDetector{
		descriptor: DetectorDescriptor{
			Name:                "syft-detector",
			SupportedEcosystems: []Ecosystem{EcosystemNPM},
			SupportedModes:      []TargetMode{TargetModeFullGraph},
		},
	})
	registry.RegisterDetectorDiscoveryPlan("syft-detector", DetectorDiscoveryPlan{
		SupportedEcosystems: []Ecosystem{EcosystemRPM, EcosystemAPK},
		SupportedManagers:   []PackageManager{PackageManagerRPM, PackageManagerAPK},
		TargetKinds:         []ExecutionTargetKind{ExecutionTargetContainerImage},
	})

	runtime, err := Prepare(PrepareRequest{
		Registry:        registry,
		ExecutionTarget: ExecutionTarget{Kind: ExecutionTargetContainerImage, Location: "alpine:3.20"},
		IncludeEcosystems: map[Ecosystem]struct{}{
			EcosystemRPM: {},
		},
	})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if len(runtime.Subprojects) != 1 {
		t.Fatalf("expected 1 subproject, got %d", len(runtime.Subprojects))
	}
	if got := runtime.Subprojects[0].Ecosystem; got != EcosystemRPM {
		t.Fatalf("expected rpm ecosystem, got %q", got)
	}
	if got := runtime.Subprojects[0].PlannedDetectors; len(got) != 1 || got[0] != "syft-detector" {
		t.Fatalf("expected syft detector chain, got %#v", got)
	}
}

func TestPrepare_UsesConcreteSBOMFilePathForSingleFileTarget(t *testing.T) {
	projectDir := t.TempDir()
	sbomPath := filepath.Join(projectDir, "reports", "app.spdx.json")
	if err := os.MkdirAll(filepath.Dir(sbomPath), 0o755); err != nil {
		t.Fatalf("mkdir sbom dir: %v", err)
	}
	if err := os.WriteFile(sbomPath, []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write sbom file: %v", err)
	}

	registry := NewRegistry()
	registry.RegisterDetector(fakeDetector{
		descriptor: DetectorDescriptor{
			Name:                "sbom-detector",
			SupportedEcosystems: []Ecosystem{EcosystemSBOM},
			SupportedManagers:   []PackageManager{PackageManagerSBOM},
			SupportedModes:      []TargetMode{TargetModeFullGraph},
		},
	})

	runtime, err := Prepare(PrepareRequest{
		Registry:        registry,
		ExecutionTarget: ExecutionTarget{Kind: ExecutionTargetFilesystem, Location: sbomPath},
	})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if len(runtime.Subprojects) != 1 {
		t.Fatalf("expected 1 subproject, got %d", len(runtime.Subprojects))
	}
	if got := runtime.Subprojects[0].ExecutionTarget.Location; got != sbomPath {
		t.Fatalf("expected subproject path %q, got %q", sbomPath, got)
	}
	if got := runtime.Subprojects[0].RelativePath; got != "." {
		t.Fatalf("expected relative path ., got %q", got)
	}
}
