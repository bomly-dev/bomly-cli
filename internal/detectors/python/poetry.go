package python

import (
	"context"
	"fmt"

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
func (d PoetryDetector) Ready(context.Context, sdk.DetectionRequest) error {
	_, err := system.LookPath("poetry")
	return detectors.CommandNotReadyError("poetry", err)
}

// Applicable reports whether Poetry manifests are present.
func (d PoetryDetector) Applicable(ctx context.Context, req sdk.DetectionRequest) (bool, error) {
	return d.base().applicable(ctx, req, "pyproject.toml", "poetry.lock")
}

// Descriptor describes the Poetry detector.
func (d PoetryDetector) Descriptor() sdk.DetectorDescriptor {
	return sdk.DetectorDescriptor{
		Name:                 detectors.NamePoetry,
		Technique:            sdk.BuildToolTechnique,
		SupportedEcosystems:  []sdk.Ecosystem{sdk.EcosystemPython},
		SupportedManagers:    []sdk.PackageManager{sdk.PackageManagerPoetry},
		Tags:                 []string{"graph-resolution", "component-targeting"},
		SupportsInstallFirst: true,
	}
}

// ResolveGraph resolves a Python dependency graph through Poetry.
func (d PoetryDetector) ResolveGraph(ctx context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	// Prefer the request-scoped logger (bound to this subproject) so
	// concurrent per-subproject resolution stays attributable in logs.
	d.Logger = req.DetectorLogger(d.Logger)
	workingDir := d.base().workingDir(req.ProjectPath)
	base := d.base()

	// Fast-path: poetry.lock has full transitive tree and group-based scope.
	// This avoids executing `poetry run pip inspect`, which marks every package
	// as requested=true (no transitive information).
	if lockPath := poetryLockFilePath(workingDir); lockPath != "" {
		if depsGraph, err := depGraphFromPoetryLock(lockPath, workingDir); err == nil {
			attachDeclaredPositions(depsGraph, workingDir)
			attachLoosePythonPositions(depsGraph, workingDir)
			resolution := resolutionMetadata(sdk.ResolutionMethodLockfile, false, nil, workingDir)
			logResolution(base.Logger, "Poetry detector", workingDir, resolution)
			return sdk.DetectionResult{
				Graphs: sdk.SingleGraphContainer(depsGraph, manifestWithResolution(req, poetryEvidencePatterns, resolution)),
			}, nil
		}
	} else {
		return sdk.DetectionResult{}, fmt.Errorf("poetry detector: poetry.lock not found; refusing to inspect an unprepared or ambient environment")
	}

	installCommand := poetryInstallCommand()
	if err := base.install(ctx, req, "Poetry detector", installCommand); err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("poetry detector: prepare locked project environment: %w", err)
	}

	command, err := pipInspectCommand("poetry", "run")
	if err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("poetry detector: build pip inspect command: %w", err)
	}
	depsGraph, err := base.resolveGraph(req.Stderr, req.ProjectPath, req.Verbose, "Poetry detector", command)
	if err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("poetry detector: resolve project environment graph: %w", err)
	}
	depsGraph, err = filterPythonToolPackages(depsGraph, workingDir)
	if err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("poetry detector: filter tool packages: %w", err)
	}
	annotateGraphScopes(depsGraph, workingDir)
	attachDeclaredPositions(depsGraph, workingDir)
	attachLoosePythonPositions(depsGraph, workingDir)
	resolution := resolutionMetadata(sdk.ResolutionMethodProjectEnvironment, true, append(installCommand, req.InstallArgs...), workingDir)
	logResolution(base.Logger, "Poetry detector", workingDir, resolution)
	return sdk.DetectionResult{
		Graphs: sdk.SingleGraphContainer(depsGraph, manifestWithResolution(req, poetryEvidencePatterns, resolution)),
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
	return d.base().install(ctx, req, "Poetry detector", poetryInstallCommand())
}

func poetryInstallCommand() []string {
	return []string{"poetry", "install", "--no-root", "--sync"}
}

func poetryReconstructedInstallCommand(req sdk.DetectionRequest) []string {
	if !req.InstallFirst {
		return nil
	}
	return append(poetryInstallCommand(), req.InstallArgs...)
}
