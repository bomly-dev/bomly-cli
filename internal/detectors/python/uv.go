package python

import (
	"context"
	"fmt"

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
func (d UVDetector) Ready(context.Context, sdk.DetectionRequest) error {
	_, err := system.LookPath("uv")
	return detectors.CommandNotReadyError("uv", err)
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
func (d UVDetector) ResolveGraph(ctx context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	// Prefer the request-scoped logger (bound to this subproject) so
	// concurrent per-subproject resolution stays attributable in logs.
	d.Logger = req.DetectorLogger(d.Logger)
	workingDir := d.base().workingDir(req.ProjectPath)
	base := d.base()

	// Prefer the native uv.lock parser: it produces a proper transitive graph
	// with runtime/development scope from the lock file's dependency groups.
	if lockPath := uvLockFilePath(workingDir); lockPath != "" {
		depsGraph, err := depGraphFromUVLock(lockPath)
		if err == nil {
			attachDeclaredPositions(depsGraph, workingDir)
			attachLoosePythonPositions(depsGraph, workingDir)
			resolution := resolutionMetadata(sdk.ResolutionMethodLockfile, false, nil, workingDir)
			logResolution(base.Logger, "uv detector", workingDir, resolution)
			return sdk.DetectionResult{
				Graphs: sdk.SingleGraphContainer(depsGraph, manifestWithResolution(req, uvEvidencePatterns, resolution)),
			}, nil
		}
		// Fall through to pip-inspect on parse failure.
	} else {
		return sdk.DetectionResult{}, fmt.Errorf("uv detector: uv.lock not found; refusing to inspect an unprepared or ambient environment")
	}

	installCommand := uvSyncCommand()
	if err := base.install(ctx, req, "uv detector", installCommand); err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("uv detector: prepare frozen project environment: %w", err)
	}
	if err := base.install(ctx, req, "uv detector", uvPipInstallCommand()); err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("uv detector: ensure pip is available in project environment: %w", err)
	}

	command, err := pipInspectCommand("uv", "run", "--no-sync")
	if err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("uv detector: build pip inspect command: %w", err)
	}
	depsGraph, err := base.resolveGraph(req.Stderr, req.ProjectPath, req.Verbose, "uv detector", command)
	if err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("uv detector: resolve project environment graph: %w", err)
	}
	depsGraph, err = filterPythonToolPackages(depsGraph, workingDir)
	if err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("uv detector: filter tool packages: %w", err)
	}
	annotateGraphScopes(depsGraph, workingDir)
	attachDeclaredPositions(depsGraph, workingDir)
	attachLoosePythonPositions(depsGraph, workingDir)
	resolution := resolutionMetadata(sdk.ResolutionMethodProjectEnvironment, true, append(installCommand, req.InstallArgs...), workingDir)
	logResolution(base.Logger, "uv detector", workingDir, resolution)
	return sdk.DetectionResult{
		Graphs: sdk.SingleGraphContainer(depsGraph, manifestWithResolution(req, uvEvidencePatterns, resolution)),
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
	if err := base.install(ctx, req, "uv detector", uvSyncCommand()); err != nil {
		return fmt.Errorf("uv detector: prepare frozen project environment: %w", err)
	}
	if err := base.install(ctx, req, "uv detector", uvPipInstallCommand()); err != nil {
		return fmt.Errorf("uv detector: ensure pip is available in project environment: %w", err)
	}
	return nil
}

func uvSyncCommand() []string {
	return []string{"uv", "sync", "--frozen", "--no-install-project"}
}

func uvPipInstallCommand() []string {
	return []string{"uv", "pip", "install", "pip"}
}

func uvReconstructedInstallCommand(req sdk.DetectionRequest) []string {
	if !req.InstallFirst {
		return nil
	}
	return append(uvSyncCommand(), req.InstallArgs...)
}
