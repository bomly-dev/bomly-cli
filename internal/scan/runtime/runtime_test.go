package runtime_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/scan"
	"github.com/bomly-dev/bomly-cli/internal/scan/runtime"
	model "github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

type fakeDetector struct {
	descriptor model.DetectorDescriptor
}

func (f fakeDetector) Descriptor() model.DetectorDescriptor { return f.descriptor }

func (f fakeDetector) PackageManagerSupport() []model.PackageManagerSupport {
	supports := make([]model.PackageManagerSupport, 0, len(f.descriptor.SupportedManagers))
	for _, manager := range f.descriptor.SupportedManagers {
		supports = append(supports, model.PackageManagerSupport{PackageManager: manager})
	}
	return supports
}

func (f fakeDetector) ResolveGraph(_ context.Context, _ model.DetectionRequest) (model.DetectionResult, error) {
	return model.DetectionResult{}, nil
}

func (f fakeDetector) Ready() bool { return true }

func (f fakeDetector) Applicable(_ context.Context, _ model.DetectionRequest) (bool, error) {
	return true, nil
}

type fakeFallbackDetector struct {
	fakeDetector
	fallback model.Detector
}

func (f fakeFallbackDetector) FallbackDetector() model.Detector { return f.fallback }

func newTestRegistry() *scan.Registry {
	return scan.NewRegistry(scan.RegistryConfigs{}, *zap.NewNop())
}

func TestPrepare_PlansFilesystemFallbackChain(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}

	registry := newTestRegistry()
	syftDetector := fakeDetector{
		descriptor: model.DetectorDescriptor{
			Name:           "syft-detector",
			Enabled:        true,
			SupportedModes: []model.TargetMode{model.TargetModeFullGraph},
		},
	}
	registry.Registry.RegisterDetector(fakeFallbackDetector{
		fakeDetector: fakeDetector{
			descriptor: model.DetectorDescriptor{
				Name:                "npm-detector",
				Enabled:             true,
				SupportedEcosystems: []model.Ecosystem{model.EcosystemNPM},
				SupportedManagers:   []model.PackageManager{model.PackageManagerNPM},
				SupportedModes:      []model.TargetMode{model.TargetModeFullGraph},
			},
		},
		fallback: syftDetector,
	})
	registry.Registry.RegisterDetector(syftDetector)

	prepared, err := runtime.Prepare(runtime.Request{
		Registry:        registry,
		ExecutionTarget: model.ExecutionTarget{Kind: model.ExecutionTargetFilesystem, Location: projectDir},
	})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if len(prepared.Subprojects) != 1 {
		t.Fatalf("expected 1 subproject, got %d", len(prepared.Subprojects))
	}
	if got := prepared.Subprojects[0].PrimaryPackageManager(); got != model.PackageManagerNPM {
		t.Fatalf("expected npm package manager, got %q", got.Name())
	}
	want := []string{"npm-detector", "syft-detector"}
	if len(prepared.Subprojects[0].PlannedDetectors) != len(want) {
		t.Fatalf("expected planned detectors %#v, got %#v", want, prepared.Subprojects[0].PlannedDetectors)
	}
	for i, detectorName := range want {
		if prepared.Subprojects[0].PlannedDetectors[i] != detectorName {
			t.Fatalf("expected planned detectors %#v, got %#v", want, prepared.Subprojects[0].PlannedDetectors)
		}
	}
}

func TestPrepare_PlansFilesystemWithSyftOnlyFilter(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}

	registry := newTestRegistry()
	registry.Registry.RegisterDetector(fakeDetector{
		descriptor: model.DetectorDescriptor{
			Name:           "syft-detector",
			Enabled:        true,
			SupportedModes: []model.TargetMode{model.TargetModeFullGraph},
		},
	})

	prepared, err := runtime.Prepare(runtime.Request{
		Registry:        registry,
		ExecutionTarget: model.ExecutionTarget{Kind: model.ExecutionTargetFilesystem, Location: projectDir},
		DetectorFilter:  model.DetectorFilter{Include: []string{"syft-detector"}},
	})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if len(prepared.Subprojects) != 1 {
		t.Fatalf("expected 1 subproject, got %d", len(prepared.Subprojects))
	}
	if got := prepared.Subprojects[0].PrimaryPackageManager(); got != model.PackageManagerNPM {
		t.Fatalf("expected npm package manager, got %q", got.Name())
	}
	if got := prepared.Subprojects[0].PlannedDetectors; len(got) != 1 || got[0] != "syft-detector" {
		t.Fatalf("expected syft-only detector chain, got %#v", got)
	}
}

func TestPrepare_PlansFilesystemSingleFileWithSyftOnlyFilter(t *testing.T) {
	projectFile := filepath.Join(t.TempDir(), "Cargo.lock")
	if err := os.WriteFile(projectFile, []byte("version = 3\n"), 0o644); err != nil {
		t.Fatalf("write Cargo.lock: %v", err)
	}

	registry := newTestRegistry()
	registry.Registry.RegisterDetector(fakeDetector{
		descriptor: model.DetectorDescriptor{
			Name:           "syft-detector",
			Enabled:        true,
			SupportedModes: []model.TargetMode{model.TargetModeFullGraph},
		},
	})

	prepared, err := runtime.Prepare(runtime.Request{
		Registry:        registry,
		ExecutionTarget: model.ExecutionTarget{Kind: model.ExecutionTargetFilesystem, Location: projectFile},
		DetectorFilter:  model.DetectorFilter{Include: []string{"syft-detector"}},
	})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if len(prepared.Subprojects) != 1 {
		t.Fatalf("expected 1 subproject, got %d", len(prepared.Subprojects))
	}
	if got := prepared.Subprojects[0].PrimaryPackageManager(); got != model.PackageManagerCargo {
		t.Fatalf("expected cargo package manager, got %q", got.Name())
	}
	if got := prepared.Subprojects[0].ExecutionTarget.Location; got != projectFile {
		t.Fatalf("expected execution target %q, got %q", projectFile, got)
	}
	if got := prepared.Subprojects[0].PlannedDetectors; len(got) != 1 || got[0] != "syft-detector" {
		t.Fatalf("expected syft-only detector chain, got %#v", got)
	}
}

func TestPrepare_PlansContainerTargetFromDiscoveryMetadata(t *testing.T) {
	registry := newTestRegistry()
	registry.Registry.RegisterDetector(fakeDetector{
		descriptor: model.DetectorDescriptor{
			Name:                "syft-detector",
			Enabled:             true,
			SupportedEcosystems: []model.Ecosystem{model.EcosystemNPM},
			SupportedModes:      []model.TargetMode{model.TargetModeFullGraph},
		},
	})
	registry.Registry.RegisterDetectorDiscoveryPlan("syft-detector", scan.DetectorDiscoveryPlan{
		SupportedEcosystems: []model.Ecosystem{model.EcosystemRPM, model.EcosystemAPK},
		SupportedManagers:   []model.PackageManager{model.PackageManagerRPM, model.PackageManagerAPK},
		TargetKinds:         []model.ExecutionTargetKind{model.ExecutionTargetContainerImage},
	})

	prepared, err := runtime.Prepare(runtime.Request{
		Registry:        registry,
		ExecutionTarget: model.ExecutionTarget{Kind: model.ExecutionTargetContainerImage, Location: "alpine:3.20"},
		EcosystemFilter: model.EcosystemFilter{Include: []model.Ecosystem{model.EcosystemRPM}},
	})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if len(prepared.Subprojects) != 1 {
		t.Fatalf("expected 1 subproject, got %d", len(prepared.Subprojects))
	}
	if got := prepared.Subprojects[0].Ecosystem; got != model.EcosystemRPM {
		t.Fatalf("expected rpm ecosystem, got %q", got)
	}
	if got := prepared.Subprojects[0].PlannedDetectors; len(got) != 1 || got[0] != "syft-detector" {
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
	registry.Registry.RegisterDetector(fakeDetector{
		descriptor: model.DetectorDescriptor{
			Name:                "sbom-detector",
			Enabled:             true,
			SupportedEcosystems: []model.Ecosystem{model.EcosystemSBOM},
			SupportedManagers:   []model.PackageManager{model.PackageManagerSBOM},
			SupportedModes:      []model.TargetMode{model.TargetModeFullGraph},
		},
	})

	prepared, err := runtime.Prepare(runtime.Request{
		Registry:        registry,
		ExecutionTarget: model.ExecutionTarget{Kind: model.ExecutionTargetFilesystem, Location: sbomPath},
	})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if len(prepared.Subprojects) != 1 {
		t.Fatalf("expected 1 subproject, got %d", len(prepared.Subprojects))
	}
	if got := prepared.Subprojects[0].ExecutionTarget.Location; got != sbomPath {
		t.Fatalf("expected subproject path %q, got %q", sbomPath, got)
	}
	if got := prepared.Subprojects[0].RelativePath; got != "." {
		t.Fatalf("expected relative path ., got %q", got)
	}
}

func TestPrepare_IntegratesDiscoveryPlanDetectorsIntoPackageManagerPlanning(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "go.mod"), []byte("module example.com/demo\n"), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	registry := newTestRegistry()
	registry.Registry.RegisterDetector(fakeDetector{
		descriptor: model.DetectorDescriptor{
			Name:                "go-detector",
			Enabled:             true,
			SupportedEcosystems: []model.Ecosystem{model.EcosystemGo},
			SupportedManagers:   []model.PackageManager{model.PackageManagerGoMod},
			SupportedModes:      []model.TargetMode{model.TargetModeFullGraph},
		},
	})
	registry.Registry.RegisterDetector(fakeDetector{
		descriptor: model.DetectorDescriptor{
			Name:                "plugin-go-detector",
			Enabled:             true,
			SupportedEcosystems: []model.Ecosystem{model.EcosystemGo},
			SupportedManagers:   []model.PackageManager{model.PackageManagerGoMod},
			SupportedModes:      []model.TargetMode{model.TargetModeFullGraph},
		},
	})
	registry.Registry.RegisterDetectorDiscoveryPlan("plugin-go-detector", scan.DetectorDiscoveryPlan{
		SupportedEcosystems: []model.Ecosystem{model.EcosystemGo},
		SupportedManagers:   []model.PackageManager{model.PackageManagerGoMod},
		EvidencePatterns:    []string{"go.mod"},
		TargetKinds:         []model.ExecutionTargetKind{model.ExecutionTargetFilesystem},
	})

	prepared, err := runtime.Prepare(runtime.Request{
		Registry:        registry,
		ExecutionTarget: model.ExecutionTarget{Kind: model.ExecutionTargetFilesystem, Location: projectDir},
	})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if len(prepared.Subprojects) != 1 {
		t.Fatalf("expected 1 subproject, got %d", len(prepared.Subprojects))
	}
	want := []string{"go-detector", "plugin-go-detector"}
	if len(prepared.Subprojects[0].PlannedDetectors) != len(want) {
		t.Fatalf("expected planned detectors %#v, got %#v", want, prepared.Subprojects[0].PlannedDetectors)
	}
	for i, detectorName := range want {
		if prepared.Subprojects[0].PlannedDetectors[i] != detectorName {
			t.Fatalf("expected planned detectors %#v, got %#v", want, prepared.Subprojects[0].PlannedDetectors)
		}
	}
}

func TestPrepare_UsesPluginEvidencePatternsToDiscoverPackageManagerSubprojects(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "custom.go.graph"), []byte("module example.com/demo\n"), 0o644); err != nil {
		t.Fatalf("write custom plugin evidence file: %v", err)
	}

	registry := newTestRegistry()
	registry.Registry.RegisterDetector(fakeDetector{
		descriptor: model.DetectorDescriptor{
			Name:                "plugin-go-detector",
			Enabled:             true,
			SupportedEcosystems: []model.Ecosystem{model.EcosystemGo},
			SupportedManagers:   []model.PackageManager{model.PackageManagerGoMod},
			SupportedModes:      []model.TargetMode{model.TargetModeFullGraph},
		},
	})
	registry.Registry.RegisterDetectorDiscoveryPlan("plugin-go-detector", scan.DetectorDiscoveryPlan{
		SupportedEcosystems: []model.Ecosystem{model.EcosystemGo},
		SupportedManagers:   []model.PackageManager{model.PackageManagerGoMod},
		EvidencePatterns:    []string{"custom.go.graph"},
		TargetKinds:         []model.ExecutionTargetKind{model.ExecutionTargetFilesystem},
	})

	prepared, err := runtime.Prepare(runtime.Request{
		Registry:        registry,
		ExecutionTarget: model.ExecutionTarget{Kind: model.ExecutionTargetFilesystem, Location: projectDir},
		DetectorFilter:  model.DetectorFilter{Include: []string{"plugin-go-detector"}},
	})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if len(prepared.Subprojects) != 1 {
		t.Fatalf("expected 1 subproject, got %d", len(prepared.Subprojects))
	}
	if got := prepared.Subprojects[0].PrimaryPackageManager(); got != model.PackageManagerGoMod {
		t.Fatalf("expected go package manager, got %q", got.Name())
	}
	if got := prepared.Subprojects[0].PlannedDetectors; len(got) != 1 || got[0] != "plugin-go-detector" {
		t.Fatalf("expected plugin-only detector chain, got %#v", got)
	}
}

func TestPrepare_UsesPluginEvidencePatternsForOtherPackageManager(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "custom.lock"), []byte("custom\n"), 0o644); err != nil {
		t.Fatalf("write custom plugin evidence file: %v", err)
	}

	registry := newTestRegistry()
	registry.Registry.RegisterDetector(fakeDetector{
		descriptor: model.DetectorDescriptor{
			Name:                "plugin-other-detector",
			Enabled:             true,
			SupportedEcosystems: []model.Ecosystem{model.EcosystemOther},
			SupportedManagers:   []model.PackageManager{model.PackageManagerOther},
			SupportedModes:      []model.TargetMode{model.TargetModeFullGraph},
		},
	})
	registry.Registry.RegisterDetectorDiscoveryPlan("plugin-other-detector", scan.DetectorDiscoveryPlan{
		SupportedEcosystems: []model.Ecosystem{model.EcosystemOther},
		SupportedManagers:   []model.PackageManager{model.PackageManagerOther},
		EvidencePatterns:    []string{"custom.lock"},
		TargetKinds:         []model.ExecutionTargetKind{model.ExecutionTargetFilesystem},
	})

	prepared, err := runtime.Prepare(runtime.Request{
		Registry:        registry,
		ExecutionTarget: model.ExecutionTarget{Kind: model.ExecutionTargetFilesystem, Location: projectDir},
		DetectorFilter:  model.DetectorFilter{Include: []string{"plugin-other-detector"}},
	})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if len(prepared.Subprojects) != 1 {
		t.Fatalf("expected 1 subproject, got %d", len(prepared.Subprojects))
	}
	if got := prepared.Subprojects[0].PrimaryPackageManager(); got != model.PackageManagerOther {
		t.Fatalf("expected other package manager, got %q", got.Name())
	}
	if got := prepared.Subprojects[0].Ecosystem; got != model.EcosystemOther {
		t.Fatalf("expected other ecosystem, got %q", got)
	}
}

func TestPrepare_DoesNotAutoDiscoverOtherPackageManagerWithoutPluginEvidence(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "custom.lock"), []byte("custom\n"), 0o644); err != nil {
		t.Fatalf("write custom plugin evidence file: %v", err)
	}

	registry := newTestRegistry()
	registry.Registry.RegisterDetector(fakeDetector{
		descriptor: model.DetectorDescriptor{
			Name:                "plugin-other-detector",
			Enabled:             true,
			SupportedEcosystems: []model.Ecosystem{model.EcosystemOther},
			SupportedManagers:   []model.PackageManager{model.PackageManagerOther},
			SupportedModes:      []model.TargetMode{model.TargetModeFullGraph},
		},
	})
	registry.Registry.RegisterDetectorDiscoveryPlan("plugin-other-detector", scan.DetectorDiscoveryPlan{
		SupportedEcosystems: []model.Ecosystem{model.EcosystemOther},
		SupportedManagers:   []model.PackageManager{model.PackageManagerOther},
		TargetKinds:         []model.ExecutionTargetKind{model.ExecutionTargetFilesystem},
	})

	_, err := runtime.Prepare(runtime.Request{
		Registry:        registry,
		ExecutionTarget: model.ExecutionTarget{Kind: model.ExecutionTargetFilesystem, Location: projectDir},
		DetectorFilter:  model.DetectorFilter{Include: []string{"plugin-other-detector"}},
	})
	if err == nil {
		t.Fatal("expected Prepare() to fail without plugin evidence patterns")
	}
}
