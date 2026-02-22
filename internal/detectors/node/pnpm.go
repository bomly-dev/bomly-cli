package node

import (
	"context"
	"path/filepath"

	"github.com/bomly/bomly-cli/internal/detectors"
	"github.com/bomly/bomly-cli/pkg/system"
	"go.uber.org/zap"
)

// PNPMDetector resolves dependency graphs with pnpm.
type PNPMDetector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   detectors.Detector
}

// Ready reports whether pnpm is available.
func (d PNPMDetector) Ready() bool {
	_, err := system.LookPath("pnpm")
	return err == nil
}

// Applicable reports whether pnpm manifests are present.
func (d PNPMDetector) Applicable(ctx context.Context, req detectors.ResolveGraphRequest) (bool, error) {
	_ = ctx
	workingDir := d.base().workingDir(req.ProjectPath)
	for _, name := range []string{"package.json", "pnpm-lock.yaml"} {
		exists, err := system.FileExists(filepath.Join(workingDir, name))
		if err != nil {
			return false, err
		}
		if exists {
			return true, nil
		}
	}
	return false, nil
}

// Descriptor describes the pnpm detector.
func (d PNPMDetector) Descriptor() detectors.DetectorDescriptor {
	return detectors.DetectorDescriptor{
		Name:                "pnpm-detector",
		ImplementationType:  detectors.NativeDetector,
		SupportedEcosystems: []detectors.Ecosystem{detectors.EcosystemNPM},
		SupportedManagers:   []detectors.PackageManager{detectors.PackageManagerPNPM},
		SupportedModes:      []detectors.TargetMode{detectors.TargetModeFullGraph, detectors.TargetModeComponent},
		Capabilities:        []string{"graph-resolution", "component-targeting"},
	}
}

// ResolveGraph resolves a pnpm dependency graph.
func (d PNPMDetector) ResolveGraph(_ context.Context, req detectors.ResolveGraphRequest) (detectors.ResolveGraphResult, error) {
	depsGraph, err := d.base().resolveGraph(req.Stderr, req.ProjectPath, req.Verbose, "pnpm", []string{"list", "--json", "--depth", "Infinity"}, "pnpm detector", depGraphFromPNPMJSON)
	if err != nil {
		return detectors.ResolveGraphResult{}, err
	}
	if err := annotateScopesFromPackageJSON(d.base().workingDir(req.ProjectPath), depsGraph); err != nil {
		return detectors.ResolveGraphResult{}, err
	}
	return detectors.ResolveGraphResult{
		Graphs: detectors.SingleGraphContainer(depsGraph, detectors.InferManifestMetadata(req)),
	}, nil
}

// FallbackDetector returns the configured fallback detector.
func (d PNPMDetector) FallbackDetector() detectors.Detector {
	return d.Fallback
}

func (d PNPMDetector) base() baseDetector {
	return baseDetector{
		Logger:     d.Logger,
		WorkingDir: d.WorkingDir,
	}
}

// Install prepares pnpm dependencies before graph resolution.
func (d PNPMDetector) Install(ctx context.Context, req detectors.ResolveGraphRequest) error {
	return d.base().install(ctx, req, "pnpm", []string{"i"}, "pnpm detector")
}
