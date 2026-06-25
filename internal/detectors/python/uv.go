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
		Name:                 detectors.NameUV,
		Technique:            sdk.BuildToolTechnique,
		SupportedEcosystems:  []sdk.Ecosystem{sdk.EcosystemPython},
		SupportedManagers:    []sdk.PackageManager{sdk.PackageManagerUV},
		Tags:                 []string{"graph-resolution", "component-targeting"},
		SupportsInstallFirst: true,
	}
}

// ResolveGraph resolves a Python dependency graph through uv.
func (d UVDetector) ResolveGraph(_ context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	workingDir := d.base().workingDir(req.ProjectPath)

	// Prefer the native uv.lock parser: it produces a proper transitive graph
	// with runtime/development scope from the lock file's dependency groups.
	if lockPath := uvLockFilePath(workingDir); lockPath != "" {
		depsGraph, err := depGraphFromUVLock(lockPath)
		if err == nil {
			attachDeclaredPositions(depsGraph, workingDir)
			attachLoosePythonPositions(depsGraph, workingDir)
			return sdk.DetectionResult{
				Graphs: sdk.SingleGraphContainer(depsGraph, detectors.InferManifestMetadata(req, uvEvidencePatterns)),
			}, nil
		}
		// Fall through to pip-inspect on parse failure.
	}

	command, err := pipInspectCommand("uv", "run", "--no-sync")
	if err != nil {
		return sdk.DetectionResult{}, err
	}
	depsGraph, err := d.base().resolveGraph(req.Stderr, req.ProjectPath, req.Verbose, "uv detector", command)
	if err != nil {
		return sdk.DetectionResult{}, err
	}
	depsGraph, err = filterPythonToolPackages(depsGraph, workingDir)
	if err != nil {
		return sdk.DetectionResult{}, err
	}
	annotateGraphScopes(depsGraph, workingDir)
	attachDeclaredPositions(depsGraph, workingDir)
	attachLoosePythonPositions(depsGraph, workingDir)
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
	base := d.base()
	if err := base.install(ctx, req, "uv detector", []string{"uv", "sync", "--no-install-project"}); err != nil {
		return err
	}
	return base.install(ctx, req, "uv detector", []string{"uv", "pip", "install", "pip"})
}
