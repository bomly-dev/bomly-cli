package python

import (
	"context"
	"fmt"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	detectorkit "github.com/bomly-dev/bomly-sdk/detectorkit"
	"github.com/bomly-dev/bomly-sdk/system"
	"go.uber.org/zap"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

// PoetryDetector resolves Python dependencies through Poetry.
type PoetryDetector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   plugin.Detector
}

var poetryEvidencePatterns = []string{"poetry.lock", "pyproject.toml"}

// PackageManagerSupport returns Poetry package-manager discovery metadata.
func (d PoetryDetector) PackageManagerSupport() []plugin.PackageManagerSupport {
	return []plugin.PackageManagerSupport{plugin.Support(model.PackageManagerPoetry, poetryEvidencePatterns...)}
}

// Ready reports whether Poetry is available.
func (d PoetryDetector) Ready(context.Context, plugin.DetectionRequest) error {
	_, err := system.LookPath("poetry")
	return detectorkit.CommandNotReadyError("poetry", err)
}

// Applicable reports whether Poetry manifests are present.
func (d PoetryDetector) Applicable(ctx context.Context, req plugin.DetectionRequest) (bool, error) {
	return d.base().applicable(ctx, req, "pyproject.toml", "poetry.lock")
}

// Descriptor describes the Poetry detector.
func (d PoetryDetector) Descriptor() plugin.DetectorDescriptor {
	return plugin.DetectorDescriptor{
		IgnoredDirectories:      []string{"__pycache__"},
		IgnoredDirectoryMarkers: []string{"pyvenv.cfg"},
		Name:                    detectors.NamePoetry,
		RemediationCapabilities: poetryRemediationCapabilities(),
		Technique:               plugin.BuildToolTechnique,
		SupportedEcosystems:     []model.Ecosystem{model.EcosystemPython},
		SupportedManagers:       []model.PackageManager{model.PackageManagerPoetry},
		Tags:                    []string{"graph-resolution", "component-targeting"},
		SupportsInstallFirst:    true,
	}
}

// ResolveGraph resolves a Python dependency graph through Poetry.
func (d PoetryDetector) ResolveGraph(ctx context.Context, req plugin.DetectionRequest) (plugin.DetectionResult, error) {
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
			resolution := resolutionMetadata(model.ResolutionMethodLockfile, false, nil, workingDir)
			logResolution(base.Logger, "Poetry detector", workingDir, resolution)
			return detectors.Attributed(plugin.DetectionResult{
				Graphs: model.SingleGraphContainer(depsGraph, manifestWithResolution(req, poetryEvidencePatterns, resolution)),
			}), nil
		}
	} else {
		return plugin.DetectionResult{}, fmt.Errorf("poetry detector: poetry.lock not found; refusing to inspect an unprepared or ambient environment")
	}

	installCommand := poetryInstallCommand()
	if err := base.install(ctx, req, "Poetry detector", installCommand); err != nil {
		return plugin.DetectionResult{}, fmt.Errorf("poetry detector: prepare locked project environment: %w", err)
	}

	command, err := pipInspectCommand("poetry", "run")
	if err != nil {
		return plugin.DetectionResult{}, fmt.Errorf("poetry detector: build pip inspect command: %w", err)
	}
	depsGraph, err := base.resolveGraph(req, "Poetry detector", command)
	if err != nil {
		return plugin.DetectionResult{}, fmt.Errorf("poetry detector: resolve project environment graph: %w", err)
	}
	depsGraph, err = filterPythonToolPackages(depsGraph, workingDir, model.PackageManagerPoetry, pythonRootName(req, workingDir))
	if err != nil {
		return plugin.DetectionResult{}, fmt.Errorf("poetry detector: filter tool packages: %w", err)
	}
	annotateGraphScopes(depsGraph, workingDir)
	attachDeclaredPositions(depsGraph, workingDir)
	attachLoosePythonPositions(depsGraph, workingDir)
	resolution := resolutionMetadata(model.ResolutionMethodProjectEnvironment, true, append(installCommand, req.InstallArgs...), workingDir)
	logResolution(base.Logger, "Poetry detector", workingDir, resolution)
	return detectors.Attributed(plugin.DetectionResult{
		Graphs: model.SingleGraphContainer(depsGraph, manifestWithResolution(req, poetryEvidencePatterns, resolution)),
	}), nil
}

// FallbackDetector returns the configured fallback detector.
func (d PoetryDetector) FallbackDetector() plugin.Detector {
	return d.Fallback
}

func (d PoetryDetector) base() baseDetector {
	return baseDetector{
		Logger:     d.Logger,
		WorkingDir: d.WorkingDir,
		Manager:    model.PackageManagerPoetry,
	}
}

// Install prepares Poetry dependencies before graph resolution.
func (d PoetryDetector) Install(ctx context.Context, req plugin.DetectionRequest) error {
	return d.base().install(ctx, req, "Poetry detector", poetryInstallCommand())
}

func poetryInstallCommand() []string {
	return []string{"poetry", "install", "--no-root", "--sync"}
}

func poetryReconstructedInstallCommand(req plugin.DetectionRequest) []string {
	if !req.InstallFirst {
		return nil
	}
	return append(poetryInstallCommand(), req.InstallArgs...)
}
