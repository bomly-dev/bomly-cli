package python

import (
	"context"
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
func (d PipDetector) Ready() bool {
	_, err := pythonCommand()
	return err == nil
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
func (d PipDetector) ResolveGraph(_ context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	workingDir := d.base().workingDir(req.ProjectPath)

	// Fast-path: a committed requirements.lock carries the full transitive tree
	// and pinned versions, so we can build the graph without installing into
	// (and inspecting) the ambient Python environment.
	if lockPath := pipLockFilePath(workingDir); lockPath != "" {
		if depsGraph, err := depGraphFromRequirementsLock(lockPath, workingDir); err == nil {
			attachDeclaredPositions(depsGraph, workingDir)
			attachLoosePythonPositions(depsGraph, workingDir)
			return sdk.DetectionResult{
				Graphs: sdk.SingleGraphContainer(depsGraph, detectors.InferManifestMetadata(req, pipEvidencePatterns)),
			}, nil
		}
	}

	command, err := pipInspectCommandForProject(workingDir)
	if err != nil {
		return sdk.DetectionResult{}, err
	}
	depsGraph, err := d.base().resolveGraph(req.Stderr, req.ProjectPath, req.Verbose, "pip detector", command)
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
		Graphs: sdk.SingleGraphContainer(depsGraph, detectors.InferManifestMetadata(req, pipEvidencePatterns)),
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
	workingDir := d.base().workingDir(req.ProjectPath)
	requirementsFile, err := installRequirementsPath(workingDir)
	if err != nil {
		return err
	}
	venvPython, err := createPythonVenv(ctx, d.base(), req, "pip detector", pythonVenvDir(workingDir))
	if err != nil {
		return err
	}
	command := []string{venvPython, "-m", "pip", "install", "-r", requirementsFile}
	if err := d.base().install(ctx, req, "pip detector", command); err != nil {
		return err
	}
	// Also install requirements-dev.txt when present alongside the primary file.
	devReqPath := filepath.Join(workingDir, "requirements-dev.txt")
	if exists, _ := system.FileExists(devReqPath); pipShouldInstallDevRequirements(req.ScopeFilter, requirementsFile, exists) {
		devCommand := []string{venvPython, "-m", "pip", "install", "-r", "requirements-dev.txt"}
		if err := d.base().install(ctx, req, "pip detector (dev)", devCommand); err != nil {
			return err
		}
	}
	return nil
}

func pipShouldInstallDevRequirements(scopeFilter sdk.Scope, requirementsFile string, devRequirementsExist bool) bool {
	return devRequirementsExist && requirementsFile != "requirements-dev.txt" && scopeFilter != sdk.ScopeRuntime
}
