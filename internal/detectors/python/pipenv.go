package python

import (
	"context"

	"github.com/bomly/bomly-cli/internal/detectors"
	"github.com/bomly/bomly-cli/pkg/system"
	"go.uber.org/zap"
)

// PipenvDetector resolves Python dependencies through Pipenv.
type PipenvDetector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   detectors.Detector
}

// Ready reports whether Pipenv is available.
func (d PipenvDetector) Ready() bool {
	_, err := system.LookPath("pipenv")
	return err == nil
}

// Applicable reports whether Pipenv manifests are present.
func (d PipenvDetector) Applicable(ctx context.Context, req detectors.ResolveGraphRequest) (bool, error) {
	return d.base().applicable(ctx, req, "Pipfile", "Pipfile.lock")
}

// Descriptor describes the Pipenv detector.
func (d PipenvDetector) Descriptor() detectors.DetectorDescriptor {
	return detectors.DetectorDescriptor{
		Name:                "pipenv-detector",
		ImplementationType:  detectors.NativeDetector,
		SupportedEcosystems: []detectors.Ecosystem{detectors.EcosystemPython},
		SupportedManagers:   []detectors.PackageManager{detectors.PackageManagerPipenv},
		SupportedModes:      []detectors.TargetMode{detectors.TargetModeFullGraph, detectors.TargetModeComponent},
		Capabilities:        []string{"graph-resolution", "component-targeting"},
	}
}

// ResolveGraph resolves a Python dependency graph through Pipenv.
func (d PipenvDetector) ResolveGraph(_ context.Context, req detectors.ResolveGraphRequest) (detectors.ResolveGraphResult, error) {
	command, err := pipInspectCommand("pipenv", "run")
	if err != nil {
		return detectors.ResolveGraphResult{}, err
	}
	depsGraph, err := d.base().resolveGraph(req.Stderr, req.ProjectPath, req.Verbose, "Pipenv detector", command)
	if err != nil {
		return detectors.ResolveGraphResult{}, err
	}
	return detectors.ResolveGraphResult{
		Graphs: detectors.SingleGraphContainer(depsGraph, detectors.InferManifestMetadata(req)),
	}, nil
}

// FallbackDetector returns the configured fallback detector.
func (d PipenvDetector) FallbackDetector() detectors.Detector {
	return d.Fallback
}

func (d PipenvDetector) base() baseDetector {
	return baseDetector{
		Logger:     d.Logger,
		WorkingDir: d.WorkingDir,
	}
}

// Install prepares Pipenv dependencies before graph resolution.
func (d PipenvDetector) Install(ctx context.Context, req detectors.ResolveGraphRequest) error {
	return d.base().install(ctx, req, "Pipenv detector", []string{"pipenv", "install"})
}
