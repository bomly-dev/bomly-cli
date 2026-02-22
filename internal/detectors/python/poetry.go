package python

import (
	"context"

	"github.com/bomly/bomly-cli/internal/detectors"
	"github.com/bomly/bomly-cli/internal/system"
	"go.uber.org/zap"
)

// PoetryDetector resolves Python dependencies through Poetry.
type PoetryDetector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   detectors.Detector
}

// Ready reports whether Poetry is available.
func (d PoetryDetector) Ready() bool {
	_, err := system.LookPath("poetry")
	return err == nil
}

// Applicable reports whether Poetry manifests are present.
func (d PoetryDetector) Applicable(ctx context.Context, req detectors.ResolveGraphRequest) (bool, error) {
	return d.base().applicable(ctx, req, "pyproject.toml", "poetry.lock")
}

// Descriptor describes the Poetry detector.
func (d PoetryDetector) Descriptor() detectors.DetectorDescriptor {
	return detectors.DetectorDescriptor{
		Name:                "poetry-detector",
		ImplementationType:  detectors.NativeDetector,
		SupportedEcosystems: []detectors.Ecosystem{detectors.EcosystemPython},
		SupportedManagers:   []detectors.PackageManager{detectors.PackageManagerPoetry},
		SupportedModes:      []detectors.TargetMode{detectors.TargetModeFullGraph, detectors.TargetModeComponent},
		Capabilities:        []string{"graph-resolution", "component-targeting"},
	}
}

// ResolveGraph resolves a Python dependency graph through Poetry.
func (d PoetryDetector) ResolveGraph(_ context.Context, req detectors.ResolveGraphRequest) (detectors.ResolveGraphResult, error) {
	command, err := pipInspectCommand("poetry", "run")
	if err != nil {
		return detectors.ResolveGraphResult{}, err
	}
	depsGraph, err := d.base().resolveGraph(req.Stderr, req.ProjectPath, req.Verbose, "Poetry detector", command)
	if err != nil {
		return detectors.ResolveGraphResult{}, err
	}
	return detectors.ResolveGraphResult{
		Graphs: detectors.SingleGraphContainer(depsGraph, detectors.InferManifestMetadata(req)),
	}, nil
}

// FallbackDetector returns the configured fallback detector.
func (d PoetryDetector) FallbackDetector() detectors.Detector {
	return d.Fallback
}

func (d PoetryDetector) base() baseDetector {
	return baseDetector{
		Logger:     d.Logger,
		WorkingDir: d.WorkingDir,
	}
}

// Install prepares Poetry dependencies before graph resolution.
func (d PoetryDetector) Install(ctx context.Context, req detectors.ResolveGraphRequest) error {
	return d.base().install(ctx, req, "Poetry detector", []string{"poetry", "install"})
}
