package scan

import (
	"os"
	"path/filepath"
	"testing"

	model "github.com/bomly-dev/bomly-cli/sdk"
)

func TestPrepare_PlansFilesystemFallbackChain(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}

	registry := newTestRegistry()
	syftDetector := fakeDetector{
		descriptor: DetectorDescriptor{
			Name:           "syft-detector",
			Enabled:        true,
			SupportedModes: []TargetMode{TargetModeFullGraph},
		},
	}
	registry.registerDetector(fakeFallbackDetector{
		fakeDetector: fakeDetector{
			descriptor: DetectorDescriptor{
				Name:                "npm-detector",
				Enabled:             true,
				SupportedEcosystems: []Ecosystem{EcosystemNPM},
				SupportedManagers:   []PackageManager{PackageManagerNPM},
				SupportedModes:      []TargetMode{TargetModeFullGraph},
			},
		},
		fallback: syftDetector,
	})
	registry.registerDetector(syftDetector)

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
	if got := runtime.Subprojects[0].PrimaryPackageManager(); got != PackageManagerNPM {
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

	registry := newTestRegistry()
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{
			Name:           "syft-detector",
			Enabled:        true,
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
	if got := runtime.Subprojects[0].PrimaryPackageManager(); got != PackageManagerNPM {
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

	registry := newTestRegistry()
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{
			Name:           "syft-detector",
			Enabled:        true,
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
	if got := runtime.Subprojects[0].PrimaryPackageManager(); got != PackageManagerCargo {
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
	registry := newTestRegistry()
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{
			Name:                "syft-detector",
			Enabled:             true,
			SupportedEcosystems: []Ecosystem{EcosystemNPM},
			SupportedModes:      []TargetMode{TargetModeFullGraph},
		},
	})
	registry.registerDetectorDiscoveryPlan("syft-detector", DetectorDiscoveryPlan{
		SupportedEcosystems: []Ecosystem{EcosystemRPM, EcosystemAPK},
		SupportedManagers:   []PackageManager{PackageManagerRPM, PackageManagerAPK},
		TargetKinds:         []ExecutionTargetKind{ExecutionTargetContainerImage},
	})

	runtime, err := Prepare(PrepareRequest{
		Registry:        registry,
		ExecutionTarget: ExecutionTarget{Kind: ExecutionTargetContainerImage, Location: "alpine:3.20"},
		EcosystemFilter: model.EcosystemFilter{Include: []model.Ecosystem{model.EcosystemRPM}},
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

	registry := newTestRegistry()
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{
			Name:                "sbom-detector",
			Enabled:             true,
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

func TestPrepare_IntegratesDiscoveryPlanDetectorsIntoPackageManagerPlanning(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "go.mod"), []byte("module example.com/demo\n"), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	registry := newTestRegistry()
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{
			Name:                "go-detector",
			Enabled:             true,
			SupportedEcosystems: []Ecosystem{EcosystemGo},
			SupportedManagers:   []PackageManager{PackageManagerGoMod},
			SupportedModes:      []TargetMode{TargetModeFullGraph},
		},
	})
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{
			Name:                "plugin-go-detector",
			Enabled:             true,
			SupportedEcosystems: []Ecosystem{EcosystemGo},
			SupportedManagers:   []PackageManager{PackageManagerGoMod},
			SupportedModes:      []TargetMode{TargetModeFullGraph},
		},
	})
	registry.registerDetectorDiscoveryPlan("plugin-go-detector", DetectorDiscoveryPlan{
		SupportedEcosystems: []Ecosystem{EcosystemGo},
		SupportedManagers:   []PackageManager{PackageManagerGoMod},
		EvidencePatterns:    []string{"go.mod"},
		TargetKinds:         []ExecutionTargetKind{ExecutionTargetFilesystem},
	})

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
	want := []string{"go-detector", "plugin-go-detector"}
	if len(runtime.Subprojects[0].PlannedDetectors) != len(want) {
		t.Fatalf("expected planned detectors %#v, got %#v", want, runtime.Subprojects[0].PlannedDetectors)
	}
	for i, detectorName := range want {
		if runtime.Subprojects[0].PlannedDetectors[i] != detectorName {
			t.Fatalf("expected planned detectors %#v, got %#v", want, runtime.Subprojects[0].PlannedDetectors)
		}
	}
}

func TestPrepare_UsesPluginEvidencePatternsToDiscoverPackageManagerSubprojects(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "custom.go.graph"), []byte("module example.com/demo\n"), 0o644); err != nil {
		t.Fatalf("write custom plugin evidence file: %v", err)
	}

	registry := newTestRegistry()
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{
			Name:                "plugin-go-detector",
			Enabled:             true,
			SupportedEcosystems: []Ecosystem{EcosystemGo},
			SupportedManagers:   []PackageManager{PackageManagerGoMod},
			SupportedModes:      []TargetMode{TargetModeFullGraph},
		},
	})
	registry.registerDetectorDiscoveryPlan("plugin-go-detector", DetectorDiscoveryPlan{
		SupportedEcosystems: []Ecosystem{EcosystemGo},
		SupportedManagers:   []PackageManager{PackageManagerGoMod},
		EvidencePatterns:    []string{"custom.go.graph"},
		TargetKinds:         []ExecutionTargetKind{ExecutionTargetFilesystem},
	})

	runtime, err := Prepare(PrepareRequest{
		Registry:        registry,
		ExecutionTarget: ExecutionTarget{Kind: ExecutionTargetFilesystem, Location: projectDir},
		DetectorFilter:  DetectorFilter{Include: []string{"plugin-go-detector"}},
	})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if len(runtime.Subprojects) != 1 {
		t.Fatalf("expected 1 subproject, got %d", len(runtime.Subprojects))
	}
	if got := runtime.Subprojects[0].PrimaryPackageManager(); got != PackageManagerGoMod {
		t.Fatalf("expected go package manager, got %q", got.Name())
	}
	if got := runtime.Subprojects[0].PlannedDetectors; len(got) != 1 || got[0] != "plugin-go-detector" {
		t.Fatalf("expected plugin-only detector chain, got %#v", got)
	}
}

func TestPrepare_UsesPluginEvidencePatternsForOtherPackageManager(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "custom.lock"), []byte("custom\n"), 0o644); err != nil {
		t.Fatalf("write custom plugin evidence file: %v", err)
	}

	registry := newTestRegistry()
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{
			Name:                "plugin-other-detector",
			Enabled:             true,
			SupportedEcosystems: []Ecosystem{model.EcosystemOther},
			SupportedManagers:   []PackageManager{model.PackageManagerOther},
			SupportedModes:      []TargetMode{TargetModeFullGraph},
		},
	})
	registry.registerDetectorDiscoveryPlan("plugin-other-detector", DetectorDiscoveryPlan{
		SupportedEcosystems: []Ecosystem{model.EcosystemOther},
		SupportedManagers:   []PackageManager{model.PackageManagerOther},
		EvidencePatterns:    []string{"custom.lock"},
		TargetKinds:         []ExecutionTargetKind{ExecutionTargetFilesystem},
	})

	runtime, err := Prepare(PrepareRequest{
		Registry:        registry,
		ExecutionTarget: ExecutionTarget{Kind: ExecutionTargetFilesystem, Location: projectDir},
		DetectorFilter:  DetectorFilter{Include: []string{"plugin-other-detector"}},
	})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if len(runtime.Subprojects) != 1 {
		t.Fatalf("expected 1 subproject, got %d", len(runtime.Subprojects))
	}
	if got := runtime.Subprojects[0].PrimaryPackageManager(); got != model.PackageManagerOther {
		t.Fatalf("expected other package manager, got %q", got.Name())
	}
	if got := runtime.Subprojects[0].Ecosystem; got != model.EcosystemOther {
		t.Fatalf("expected other ecosystem, got %q", got)
	}
}

func TestPrepare_DoesNotAutoDiscoverOtherPackageManagerWithoutPluginEvidence(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "custom.lock"), []byte("custom\n"), 0o644); err != nil {
		t.Fatalf("write custom plugin evidence file: %v", err)
	}

	registry := newTestRegistry()
	registry.registerDetector(fakeDetector{
		descriptor: DetectorDescriptor{
			Name:                "plugin-other-detector",
			Enabled:             true,
			SupportedEcosystems: []Ecosystem{model.EcosystemOther},
			SupportedManagers:   []PackageManager{model.PackageManagerOther},
			SupportedModes:      []TargetMode{TargetModeFullGraph},
		},
	})
	registry.registerDetectorDiscoveryPlan("plugin-other-detector", DetectorDiscoveryPlan{
		SupportedEcosystems: []Ecosystem{model.EcosystemOther},
		SupportedManagers:   []PackageManager{model.PackageManagerOther},
		TargetKinds:         []ExecutionTargetKind{ExecutionTargetFilesystem},
	})

	_, err := Prepare(PrepareRequest{
		Registry:        registry,
		ExecutionTarget: ExecutionTarget{Kind: ExecutionTargetFilesystem, Location: projectDir},
		DetectorFilter:  DetectorFilter{Include: []string{"plugin-other-detector"}},
	})
	if err == nil {
		t.Fatal("expected Prepare() to fail without plugin evidence patterns")
	}
}
