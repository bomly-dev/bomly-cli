package node

import (
	"context"
	"path/filepath"

	"github.com/bomly/bomly-cli/internal/detectors"
	"github.com/bomly/bomly-cli/pkg/system"
	"go.uber.org/zap"
)

// YarnDetector resolves dependency graphs with Yarn.
type YarnDetector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   detectors.Detector
}

// Ready reports whether Yarn is available.
func (d YarnDetector) Ready() bool {
	_, err := system.LookPath("yarn")
	return err == nil
}

// Applicable reports whether Yarn manifests are present.
func (d YarnDetector) Applicable(ctx context.Context, req detectors.ResolveGraphRequest) (bool, error) {
	_ = ctx
	workingDir := d.base().workingDir(req.ProjectPath)
	for _, name := range []string{"package.json", "yarn.lock"} {
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

// Descriptor describes the Yarn detector.
func (d YarnDetector) Descriptor() detectors.DetectorDescriptor {
	return detectors.DetectorDescriptor{
		Name:                "yarn-detector",
		ImplementationType:  detectors.NativeDetector,
		SupportedEcosystems: []detectors.Ecosystem{detectors.EcosystemNPM},
		SupportedManagers:   []detectors.PackageManager{detectors.PackageManagerYarn},
		SupportedModes:      []detectors.TargetMode{detectors.TargetModeFullGraph, detectors.TargetModeComponent},
		Capabilities:        []string{"graph-resolution", "component-targeting"},
	}
}

// ResolveGraph resolves a Yarn dependency graph.
func (d YarnDetector) ResolveGraph(_ context.Context, req detectors.ResolveGraphRequest) (detectors.ResolveGraphResult, error) {
	depsGraph, err := d.base().resolveGraph(req.Stderr, req.ProjectPath, req.Verbose, "yarn", []string{"list", "--json"}, "Yarn detector", depGraphFromYarnJSON)
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
func (d YarnDetector) FallbackDetector() detectors.Detector {
	return d.Fallback
}

func (d YarnDetector) base() baseDetector {
	return baseDetector{
		Logger:     d.Logger,
		WorkingDir: d.WorkingDir,
	}
}

// Install prepares Yarn dependencies before graph resolution.
func (d YarnDetector) Install(ctx context.Context, req detectors.ResolveGraphRequest) error {
	return d.base().install(ctx, req, "yarn", []string{"install"}, "Yarn detector")
}
