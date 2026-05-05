package python

import (
	"context"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/system"
	model "github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// PipenvDetector resolves Python dependencies through Pipenv.
type PipenvDetector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   model.Detector
}

var pipenvEvidencePatterns = []string{"Pipfile", "Pipfile.lock"}

// PackageManagerSupport returns Pipenv package-manager discovery metadata.
func (d PipenvDetector) PackageManagerSupport() []model.PackageManagerSupport {
	return []model.PackageManagerSupport{model.Support(model.PackageManagerPipenv, pipenvEvidencePatterns...)}
}

// Ready reports whether Pipenv is available.
func (d PipenvDetector) Ready() bool {
	_, err := system.LookPath("pipenv")
	return err == nil
}

// Applicable reports whether Pipenv manifests are present.
func (d PipenvDetector) Applicable(ctx context.Context, req model.DetectionRequest) (bool, error) {
	return d.base().applicable(ctx, req, "Pipfile", "Pipfile.lock")
}

// Descriptor describes the Pipenv detector.
func (d PipenvDetector) Descriptor() model.DetectorDescriptor {
	return model.DetectorDescriptor{
		Name:                detectors.NamePipenv,
		Enabled:             true,
		Origin:              model.CoreOrigin,
		Technique:           model.BuildToolTechnique,
		SupportedEcosystems: []model.Ecosystem{model.EcosystemPython},
		SupportedManagers:   []model.PackageManager{model.PackageManagerPipenv},
		SupportedModes:      []model.TargetMode{model.TargetModeFullGraph, model.TargetModeComponent},
		Capabilities:        []string{"graph-resolution", "component-targeting"},
	}
}

// ResolveGraph resolves a Python dependency graph through Pipenv.
func (d PipenvDetector) ResolveGraph(_ context.Context, req model.DetectionRequest) (model.DetectionResult, error) {
	command, err := pipInspectCommand("pipenv", "run")
	if err != nil {
		return model.DetectionResult{}, err
	}
	depsGraph, err := d.base().resolveGraph(req.Stderr, req.ProjectPath, req.Verbose, "Pipenv detector", command)
	if err != nil {
		return model.DetectionResult{}, err
	}
	return model.DetectionResult{
		Graphs: model.SingleGraphContainer(depsGraph, detectors.InferManifestMetadata(req, pipenvEvidencePatterns)),
	}, nil
}

// FallbackDetector returns the configured fallback detector.
func (d PipenvDetector) FallbackDetector() model.Detector {
	return d.Fallback
}

func (d PipenvDetector) base() baseDetector {
	return baseDetector{
		Logger:     d.Logger,
		WorkingDir: d.WorkingDir,
	}
}

// Install prepares Pipenv dependencies before graph resolution.
func (d PipenvDetector) Install(ctx context.Context, req model.DetectionRequest) error {
	return d.base().install(ctx, req, "Pipenv detector", []string{"pipenv", "install"})
}
