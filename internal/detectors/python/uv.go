package python

import (
	"context"

	"github.com/bomly/bomly-cli/internal/detectors"
	"github.com/bomly/bomly-cli/pkg/system"
	"go.uber.org/zap"
)

// UVDetector resolves Python dependencies through uv.
type UVDetector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   detectors.Detector
}

// Ready reports whether uv is available.
func (d UVDetector) Ready() bool {
	_, err := system.LookPath("uv")
	return err == nil
}

// Applicable reports whether uv manifests are present.
func (d UVDetector) Applicable(ctx context.Context, req detectors.ResolveGraphRequest) (bool, error) {
	return d.base().applicable(ctx, req, "pyproject.toml", "uv.lock")
}

// Descriptor describes the uv detector.
func (d UVDetector) Descriptor() detectors.DetectorDescriptor {
	return detectors.DetectorDescriptor{
		Name:                "uv-detector",
		ImplementationType:  detectors.NativeDetector,
		SupportedEcosystems: []detectors.Ecosystem{detectors.EcosystemPython},
		SupportedManagers:   []detectors.PackageManager{detectors.PackageManagerUV},
		SupportedModes:      []detectors.TargetMode{detectors.TargetModeFullGraph, detectors.TargetModeComponent},
		Capabilities:        []string{"graph-resolution", "component-targeting"},
	}
}

// ResolveGraph resolves a Python dependency graph through uv.
func (d UVDetector) ResolveGraph(_ context.Context, req detectors.ResolveGraphRequest) (detectors.ResolveGraphResult, error) {
	command, err := pipInspectCommand("uv", "run")
	if err != nil {
		return detectors.ResolveGraphResult{}, err
	}
	depsGraph, err := d.base().resolveGraph(req.Stderr, req.ProjectPath, req.Verbose, "uv detector", command)
	if err != nil {
		return detectors.ResolveGraphResult{}, err
	}
	return detectors.ResolveGraphResult{
		Graphs: detectors.SingleGraphContainer(depsGraph, detectors.InferManifestMetadata(req)),
	}, nil
}

// FallbackDetector returns the configured fallback detector.
func (d UVDetector) FallbackDetector() detectors.Detector {
	return d.Fallback
}

func (d UVDetector) base() baseDetector {
	return baseDetector{
		Logger:     d.Logger,
		WorkingDir: d.WorkingDir,
	}
}

// Install prepares uv dependencies before graph resolution.
func (d UVDetector) Install(ctx context.Context, req detectors.ResolveGraphRequest) error {
	return d.base().install(ctx, req, "uv detector", []string{"uv", "sync"})
}
