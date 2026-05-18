package python

import (
	"context"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/system"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// PoetryDetector resolves Python dependencies through Poetry.
type PoetryDetector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   sdk.Detector
}

var poetryEvidencePatterns = []string{"poetry.lock", "pyproject.toml"}

// PackageManagerSupport returns Poetry package-manager discovery metadata.
func (d PoetryDetector) PackageManagerSupport() []sdk.PackageManagerSupport {
	return []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerPoetry, poetryEvidencePatterns...)}
}

// Ready reports whether Poetry is available.
func (d PoetryDetector) Ready() bool {
	_, err := system.LookPath("poetry")
	return err == nil
}

// Applicable reports whether Poetry manifests are present.
func (d PoetryDetector) Applicable(ctx context.Context, req sdk.DetectionRequest) (bool, error) {
	return d.base().applicable(ctx, req, "pyproject.toml", "poetry.lock")
}

// Descriptor describes the Poetry detector.
func (d PoetryDetector) Descriptor() sdk.DetectorDescriptor {
	return sdk.DetectorDescriptor{
		Name:                 detectors.NamePoetry,
		Enabled:              true,
		Origin:               sdk.CoreOrigin,
		Technique:            sdk.BuildToolTechnique,
		SupportedEcosystems:  []sdk.Ecosystem{sdk.EcosystemPython},
		SupportedManagers:    []sdk.PackageManager{sdk.PackageManagerPoetry},
		SupportedModes:       []sdk.TargetMode{sdk.TargetModeFullGraph, sdk.TargetModeComponent},
		Capabilities:         []string{"graph-resolution", "component-targeting"},
		SupportsInstallFirst: true,
	}
}

// ResolveGraph resolves a Python dependency graph through Poetry.
func (d PoetryDetector) ResolveGraph(_ context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	workingDir := d.base().workingDir(req.ProjectPath)

	// Fast-path: poetry.lock has full transitive tree and group-based scope.
	// This avoids executing `poetry run pip inspect`, which marks every package
	// as requested=true (no transitive information).
	if lockPath := poetryLockFilePath(workingDir); lockPath != "" {
		if depsGraph, err := depGraphFromPoetryLock(lockPath, workingDir); err == nil {
			return sdk.DetectionResult{
				Graphs: sdk.SingleGraphContainer(depsGraph, detectors.InferManifestMetadata(req, poetryEvidencePatterns)),
			}, nil
		}
	}

	command, err := pipInspectCommand("poetry", "run")
	if err != nil {
		return sdk.DetectionResult{}, err
	}
	depsGraph, err := d.base().resolveGraph(req.Stderr, req.ProjectPath, req.Verbose, "Poetry detector", command)
	if err != nil {
		return sdk.DetectionResult{}, err
	}
	depsGraph, err = filterPythonToolPackages(depsGraph, d.base().workingDir(req.ProjectPath))
	if err != nil {
		return sdk.DetectionResult{}, err
	}
	annotateGraphScopes(depsGraph, d.base().workingDir(req.ProjectPath))
	attachDeclaredPositions(depsGraph, d.base().workingDir(req.ProjectPath))
	attachLoosePythonPositions(depsGraph, d.base().workingDir(req.ProjectPath))
	return sdk.DetectionResult{
		Graphs: sdk.SingleGraphContainer(depsGraph, detectors.InferManifestMetadata(req, poetryEvidencePatterns)),
	}, nil
}

// FallbackDetector returns the configured fallback detector.
func (d PoetryDetector) FallbackDetector() sdk.Detector {
	return d.Fallback
}

func (d PoetryDetector) base() baseDetector {
	return baseDetector{
		Logger:     d.Logger,
		WorkingDir: d.WorkingDir,
	}
}

// Install prepares Poetry dependencies before graph resolution.
func (d PoetryDetector) Install(ctx context.Context, req sdk.DetectionRequest) error {
	return d.base().install(ctx, req, "Poetry detector", []string{"poetry", "install", "--no-root"})
}
