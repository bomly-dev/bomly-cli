package node

import (
	"context"
	"path/filepath"

	"github.com/bomly/bomly-cli/internal/detectors"
	"github.com/bomly/bomly-cli/internal/system"
	"go.uber.org/zap"
)

// NPMDetector resolves dependency graphs with npm.
type NPMDetector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   detectors.Detector
}

// Ready reports whether npm is available.
func (d NPMDetector) Ready() bool {
	_, err := system.LookPath("npm")
	return err == nil
}

// Applicable reports whether npm manifests are present.
func (d NPMDetector) Applicable(ctx context.Context, req detectors.ResolveGraphRequest) (bool, error) {
	_ = ctx
	workingDir := d.base().workingDir(req.ProjectPath)
	for _, name := range []string{"package.json", "package-lock.json"} {
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

// Descriptor describes the npm detector.
func (d NPMDetector) Descriptor() detectors.DetectorDescriptor {
	return detectors.DetectorDescriptor{
		Name:                "npm-detector",
		ImplementationType:  detectors.NativeDetector,
		SupportedEcosystems: []detectors.Ecosystem{detectors.EcosystemNPM},
		SupportedManagers:   []detectors.PackageManager{detectors.PackageManagerNPM},
		SupportedModes:      []detectors.TargetMode{detectors.TargetModeFullGraph, detectors.TargetModeComponent},
		Capabilities:        []string{"graph-resolution", "component-targeting"},
	}
}

// ResolveGraph resolves an npm dependency graph.
func (d NPMDetector) ResolveGraph(_ context.Context, req detectors.ResolveGraphRequest) (detectors.ResolveGraphResult, error) {
	depsGraph, err := d.base().resolveGraph(req.Stderr, req.ProjectPath, req.Verbose, "npm", []string{"ls", "--all", "--json", "--package-lock-only"}, "NPM detector", depGraphFromNPMJSON)
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

func (d NPMDetector) base() baseDetector {
	return baseDetector{
		Logger:     d.Logger,
		WorkingDir: d.WorkingDir,
	}
}

// FallbackDetector returns the configured fallback detector.
func (d NPMDetector) FallbackDetector() detectors.Detector {
	return d.Fallback
}

// Install prepares npm dependencies before graph resolution.
func (d NPMDetector) Install(ctx context.Context, req detectors.ResolveGraphRequest) error {
	return d.base().install(ctx, req, "npm", []string{"i"}, "NPM detector")
}
