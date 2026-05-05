package python

import (
	"context"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/system"
	model "github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// PoetryDetector resolves Python dependencies through Poetry.
type PoetryDetector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   model.Detector
}

var poetryEvidencePatterns = []string{"poetry.lock", "pyproject.toml"}

// PackageManagerSupport returns Poetry package-manager discovery metadata.
func (d PoetryDetector) PackageManagerSupport() []model.PackageManagerSupport {
	return []model.PackageManagerSupport{model.Support(model.PackageManagerPoetry, poetryEvidencePatterns...)}
}

// Ready reports whether Poetry is available.
func (d PoetryDetector) Ready() bool {
	_, err := system.LookPath("poetry")
	return err == nil
}

// Applicable reports whether Poetry manifests are present.
func (d PoetryDetector) Applicable(ctx context.Context, req model.DetectionRequest) (bool, error) {
	return d.base().applicable(ctx, req, "pyproject.toml", "poetry.lock")
}

// Descriptor describes the Poetry detector.
func (d PoetryDetector) Descriptor() model.DetectorDescriptor {
	return model.DetectorDescriptor{
		Name:                detectors.NamePoetry,
		Enabled:             true,
		Origin:              model.CoreOrigin,
		Technique:           model.BuildToolTechnique,
		SupportedEcosystems: []model.Ecosystem{model.EcosystemPython},
		SupportedManagers:   []model.PackageManager{model.PackageManagerPoetry},
		SupportedModes:      []model.TargetMode{model.TargetModeFullGraph, model.TargetModeComponent},
		Capabilities:        []string{"graph-resolution", "component-targeting"},
	}
}

// ResolveGraph resolves a Python dependency graph through Poetry.
func (d PoetryDetector) ResolveGraph(_ context.Context, req model.DetectionRequest) (model.DetectionResult, error) {
	command, err := pipInspectCommand("poetry", "run")
	if err != nil {
		return model.DetectionResult{}, err
	}
	depsGraph, err := d.base().resolveGraph(req.Stderr, req.ProjectPath, req.Verbose, "Poetry detector", command)
	if err != nil {
		return model.DetectionResult{}, err
	}
	return model.DetectionResult{
		Graphs: model.SingleGraphContainer(depsGraph, detectors.InferManifestMetadata(req, poetryEvidencePatterns)),
	}, nil
}

// FallbackDetector returns the configured fallback detector.
func (d PoetryDetector) FallbackDetector() model.Detector {
	return d.Fallback
}

func (d PoetryDetector) base() baseDetector {
	return baseDetector{
		Logger:     d.Logger,
		WorkingDir: d.WorkingDir,
	}
}

// Install prepares Poetry dependencies before graph resolution.
func (d PoetryDetector) Install(ctx context.Context, req model.DetectionRequest) error {
	return d.base().install(ctx, req, "Poetry detector", []string{"poetry", "install"})
}
