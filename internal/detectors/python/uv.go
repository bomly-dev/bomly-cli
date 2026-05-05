package python

import (
	"context"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/system"
	model "github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// UVDetector resolves Python dependencies through uv.
type UVDetector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   model.Detector
}

var uvEvidencePatterns = []string{"uv.lock", "pyproject.toml"}

// PackageManagerSupport returns uv package-manager discovery metadata.
func (d UVDetector) PackageManagerSupport() []model.PackageManagerSupport {
	return []model.PackageManagerSupport{model.Support(model.PackageManagerUV, uvEvidencePatterns...)}
}

// Ready reports whether uv is available.
func (d UVDetector) Ready() bool {
	_, err := system.LookPath("uv")
	return err == nil
}

// Applicable reports whether uv manifests are present.
func (d UVDetector) Applicable(ctx context.Context, req model.DetectionRequest) (bool, error) {
	return d.base().applicable(ctx, req, "pyproject.toml", "uv.lock")
}

// Descriptor describes the uv detector.
func (d UVDetector) Descriptor() model.DetectorDescriptor {
	return model.DetectorDescriptor{
		Name:                detectors.NameUV,
		Enabled:             true,
		Origin:              model.CoreOrigin,
		Technique:           model.BuildToolTechnique,
		SupportedEcosystems: []model.Ecosystem{model.EcosystemPython},
		SupportedManagers:   []model.PackageManager{model.PackageManagerUV},
		SupportedModes:      []model.TargetMode{model.TargetModeFullGraph, model.TargetModeComponent},
		Capabilities:        []string{"graph-resolution", "component-targeting"},
	}
}

// ResolveGraph resolves a Python dependency graph through uv.
func (d UVDetector) ResolveGraph(_ context.Context, req model.DetectionRequest) (model.DetectionResult, error) {
	command, err := pipInspectCommand("uv", "run")
	if err != nil {
		return model.DetectionResult{}, err
	}
	depsGraph, err := d.base().resolveGraph(req.Stderr, req.ProjectPath, req.Verbose, "uv detector", command)
	if err != nil {
		return model.DetectionResult{}, err
	}
	return model.DetectionResult{
		Graphs: model.SingleGraphContainer(depsGraph, detectors.InferManifestMetadata(req, uvEvidencePatterns)),
	}, nil
}

// FallbackDetector returns the configured fallback detector.
func (d UVDetector) FallbackDetector() model.Detector {
	return d.Fallback
}

func (d UVDetector) base() baseDetector {
	return baseDetector{
		Logger:     d.Logger,
		WorkingDir: d.WorkingDir,
	}
}

// Install prepares uv dependencies before graph resolution.
func (d UVDetector) Install(ctx context.Context, req model.DetectionRequest) error {
	return d.base().install(ctx, req, "uv detector", []string{"uv", "sync"})
}
