package python

import (
	"context"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/system"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// UVDetector resolves Python dependencies through uv.
type UVDetector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   sdk.Detector
}

var uvEvidencePatterns = []string{"uv.lock", "pyproject.toml"}

// PackageManagerSupport returns uv package-manager discovery metadata.
func (d UVDetector) PackageManagerSupport() []sdk.PackageManagerSupport {
	return []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerUV, uvEvidencePatterns...)}
}

// Ready reports whether uv is available.
func (d UVDetector) Ready() bool {
	_, err := system.LookPath("uv")
	return err == nil
}

// Applicable reports whether uv manifests are present.
func (d UVDetector) Applicable(ctx context.Context, req sdk.DetectionRequest) (bool, error) {
	return d.base().applicable(ctx, req, "pyproject.toml", "uv.lock")
}

// Descriptor describes the uv detector.
func (d UVDetector) Descriptor() sdk.DetectorDescriptor {
	return sdk.DetectorDescriptor{
		Name:                detectors.NameUV,
		Enabled:             true,
		Origin:              sdk.CoreOrigin,
		Technique:           sdk.BuildToolTechnique,
		SupportedEcosystems: []sdk.Ecosystem{sdk.EcosystemPython},
		SupportedManagers:   []sdk.PackageManager{sdk.PackageManagerUV},
		SupportedModes:      []sdk.TargetMode{sdk.TargetModeFullGraph, sdk.TargetModeComponent},
		Capabilities:        []string{"graph-resolution", "component-targeting"},
	}
}

// ResolveGraph resolves a Python dependency graph through uv.
func (d UVDetector) ResolveGraph(_ context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	command, err := pipInspectCommand("uv", "run")
	if err != nil {
		return sdk.DetectionResult{}, err
	}
	depsGraph, err := d.base().resolveGraph(req.Stderr, req.ProjectPath, req.Verbose, "uv detector", command)
	if err != nil {
		return sdk.DetectionResult{}, err
	}
	return sdk.DetectionResult{
		Graphs: sdk.SingleGraphContainer(depsGraph, detectors.InferManifestMetadata(req, uvEvidencePatterns)),
	}, nil
}

// FallbackDetector returns the configured fallback detector.
func (d UVDetector) FallbackDetector() sdk.Detector {
	return d.Fallback
}

func (d UVDetector) base() baseDetector {
	return baseDetector{
		Logger:     d.Logger,
		WorkingDir: d.WorkingDir,
	}
}

// Install prepares uv dependencies before graph resolution.
func (d UVDetector) Install(ctx context.Context, req sdk.DetectionRequest) error {
	return d.base().install(ctx, req, "uv detector", []string{"uv", "sync"})
}
