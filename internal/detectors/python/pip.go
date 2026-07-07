package python

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/system"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// PipDetector resolves Python dependencies with pip inspect.
type PipDetector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   sdk.Detector
}

var pipEvidencePatterns = []string{"requirements.txt", "requirements-dev.txt", "requirements.in", "requirements.lock", "*requirements*.txt"}

// PackageManagerSupport returns pip package-manager discovery metadata.
func (d PipDetector) PackageManagerSupport() []sdk.PackageManagerSupport {
	return []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerPip, pipEvidencePatterns...)}
}

// Ready reports whether a Python interpreter is available.
func (d PipDetector) Ready(context.Context, sdk.DetectionRequest) error {
	_, err := pythonCommand()
	return detectors.CommandNotReadyError("python", err)
}

// Applicable reports whether pip-style manifests are present.
func (d PipDetector) Applicable(ctx context.Context, req sdk.DetectionRequest) (bool, error) {
	return d.base().applicable(ctx, req, "requirements.txt", "requirements-dev.txt", "requirements.in", "requirements.lock")
}

// Descriptor describes the pip detector.
func (d PipDetector) Descriptor() sdk.DetectorDescriptor {
	return sdk.DetectorDescriptor{
		Name:                 detectors.NamePip,
		Technique:            sdk.BuildToolTechnique,
		SupportedEcosystems:  []sdk.Ecosystem{sdk.EcosystemPython},
		SupportedManagers:    []sdk.PackageManager{sdk.PackageManagerPip},
		Tags:                 []string{"graph-resolution", "component-targeting"},
		SupportsInstallFirst: true,
	}
}

// ResolveGraph resolves a Python dependency graph with pip inspect.
func (d PipDetector) ResolveGraph(ctx context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	// Prefer the request-scoped logger (bound to this subproject) so
	// concurrent per-subproject resolution stays attributable in logs.
	d.Logger = req.DetectorLogger(d.Logger)
	workingDir := d.base().workingDir(req.ProjectPath)
	base := d.base()

	// Fast-path: a committed requirements.lock carries the full transitive tree
	// and pinned versions, so we can build the graph without installing into
	// (and inspecting) the ambient Python environment.
	if lockPath := pipLockFilePath(workingDir); lockPath != "" {
		if depsGraph, err := depGraphFromRequirementsLock(lockPath, workingDir); err == nil {
			attachDeclaredPositions(depsGraph, workingDir)
			attachLoosePythonPositions(depsGraph, workingDir)
			resolution := resolutionMetadata(sdk.ResolutionMethodLockfile, false, nil, workingDir)
			logResolution(base.Logger, "pip detector", workingDir, resolution)
			return sdk.DetectionResult{
				Graphs: sdk.SingleGraphContainer(depsGraph, manifestWithResolution(req, pipEvidencePatterns, resolution)),
			}, nil
		}
	}

	installCommand, err := d.ensureIsolatedPipEnvironment(ctx, req)
	if err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("pip detector: prepare isolated Python environment: %w", err)
	}
	venvPython := venvPythonPath(pythonVenvDir(workingDir))
	if venvPython == "" {
		return sdk.DetectionResult{}, fmt.Errorf("pip detector: isolated Python environment was not created under %s", pythonVenvDir(workingDir))
	}
	command := []string{venvPython, "-m", "pip", "inspect", "--local"}
	depsGraph, err := base.resolveGraph(req.Stderr, req.ProjectPath, req.Verbose, "pip detector", command)
	if err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("pip detector: resolve isolated environment graph: %w", err)
	}
	depsGraph, err = filterPythonToolPackages(depsGraph, workingDir)
	if err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("pip detector: filter tool packages: %w", err)
	}
	annotateGraphScopes(depsGraph, workingDir)
	attachDeclaredPositions(depsGraph, workingDir)
	attachLoosePythonPositions(depsGraph, workingDir)
	resolution := resolutionMetadata(sdk.ResolutionMethodIsolatedInstall, true, installCommand, workingDir)
	logResolution(base.Logger, "pip detector", workingDir, resolution)
	return sdk.DetectionResult{
		Graphs: sdk.SingleGraphContainer(depsGraph, manifestWithResolution(req, pipEvidencePatterns, resolution)),
	}, nil
}

// FallbackDetector returns the configured fallback detector.
func (d PipDetector) FallbackDetector() sdk.Detector {
	return d.Fallback
}

func (d PipDetector) base() baseDetector {
	return baseDetector{
		Logger:     d.Logger,
		WorkingDir: d.WorkingDir,
	}
}

// Install prepares pip dependencies before graph resolution. It installs into a
// clean, project-scoped virtualenv so the subsequent `pip inspect` sees only
// the declared dependencies, not whatever tooling lives in the ambient
// site-packages.
func (d PipDetector) Install(ctx context.Context, req sdk.DetectionRequest) error {
	_, err := d.installIsolatedPipEnvironment(ctx, req)
	if err != nil {
		return fmt.Errorf("pip detector: prepare isolated Python environment: %w", err)
	}
	return nil
}

func (d PipDetector) ensureIsolatedPipEnvironment(ctx context.Context, req sdk.DetectionRequest) ([]string, error) {
	if req.InstallFirst {
		command := pipReconstructedInstallCommand(req, d.base().workingDir(req.ProjectPath))
		if len(command) > 0 {
			return command, nil
		}
	}
	return d.installIsolatedPipEnvironment(ctx, req)
}

func (d PipDetector) installIsolatedPipEnvironment(ctx context.Context, req sdk.DetectionRequest) ([]string, error) {
	workingDir := d.base().workingDir(req.ProjectPath)
	requirementsFile, err := installRequirementsPath(workingDir)
	if err != nil {
		return nil, err
	}
	venvPython, err := createPythonVenv(ctx, d.base(), req, "pip detector", pythonVenvDir(workingDir))
	if err != nil {
		return nil, err
	}
	command := []string{venvPython, "-m", "pip", "install", "-r", requirementsFile}
	if err := d.base().install(ctx, req, "pip detector", command); err != nil {
		return nil, err
	}
	// Also install requirements-dev.txt when present alongside the primary file.
	devReqPath := filepath.Join(workingDir, "requirements-dev.txt")
	if exists, _ := system.FileExists(devReqPath); pipShouldInstallDevRequirements(req.ScopeFilter, requirementsFile, exists) {
		devCommand := []string{venvPython, "-m", "pip", "install", "-r", "requirements-dev.txt"}
		if err := d.base().install(ctx, req, "pip detector (dev)", devCommand); err != nil {
			return nil, err
		}
	}
	return append(append([]string{}, command...), req.InstallArgs...), nil
}

func pipReconstructedInstallCommand(req sdk.DetectionRequest, workingDir string) []string {
	if !req.InstallFirst {
		return nil
	}
	venvPython := venvPythonPath(pythonVenvDir(workingDir))
	if venvPython == "" {
		return nil
	}
	requirementsFile, err := installRequirementsPath(workingDir)
	if err != nil {
		return nil
	}
	command := []string{venvPython, "-m", "pip", "install", "-r", requirementsFile}
	return append(command, req.InstallArgs...)
}

func pipShouldInstallDevRequirements(scopeFilter sdk.Scope, requirementsFile string, devRequirementsExist bool) bool {
	return devRequirementsExist && requirementsFile != "requirements-dev.txt" && scopeFilter != sdk.ScopeRuntime
}
