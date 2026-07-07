package python

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/system"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// PipenvDetector resolves Python dependencies through Pipenv.
type PipenvDetector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   sdk.Detector
}

var pipenvEvidencePatterns = []string{"Pipfile", "Pipfile.lock"}

// PackageManagerSupport returns Pipenv package-manager discovery metadata.
func (d PipenvDetector) PackageManagerSupport() []sdk.PackageManagerSupport {
	return []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerPipenv, pipenvEvidencePatterns...)}
}

// Ready reports whether Pipenv is available.
func (d PipenvDetector) Ready(context.Context, sdk.DetectionRequest) error {
	_, err := system.LookPath("pipenv")
	return detectors.CommandNotReadyError("pipenv", err)
}

// Applicable reports whether Pipenv manifests are present.
func (d PipenvDetector) Applicable(ctx context.Context, req sdk.DetectionRequest) (bool, error) {
	return d.base().applicable(ctx, req, "Pipfile", "Pipfile.lock")
}

// Descriptor describes the Pipenv detector.
func (d PipenvDetector) Descriptor() sdk.DetectorDescriptor {
	return sdk.DetectorDescriptor{
		Name:                 detectors.NamePipenv,
		Technique:            sdk.BuildToolTechnique,
		SupportedEcosystems:  []sdk.Ecosystem{sdk.EcosystemPython},
		SupportedManagers:    []sdk.PackageManager{sdk.PackageManagerPipenv},
		Tags:                 []string{"graph-resolution", "component-targeting"},
		SupportsInstallFirst: true,
	}
}

// ResolveGraph resolves a Python dependency graph through Pipenv.
func (d PipenvDetector) ResolveGraph(ctx context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	workingDir := d.base().workingDir(req.ProjectPath)
	base := d.base()
	logger := base.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	// Try pip inspect first: it can build a full transitive tree via RequiresDist.
	// Pipfile.lock is flat (no parent-child edges), so the build tool wins here.
	// Only attempt pip inspect when a venv is already populated; otherwise `pipenv run`
	// silently creates an empty venv and pip inspect returns only bootstrap packages.
	if pipenvVenvExists(workingDir) {
		command, err := pipInspectCommand("pipenv", "run")
		if err == nil {
			if depsGraph, err := base.resolveGraph(req.Stderr, req.ProjectPath, req.Verbose, "Pipenv detector", command); err == nil {
				resolution := resolutionMetadata(sdk.ResolutionMethodProjectEnvironment, false, nil, workingDir)
				logResolution(base.Logger, "Pipenv detector", workingDir, resolution)
				annotateGraphScopes(depsGraph, workingDir)
				attachDeclaredPositions(depsGraph, workingDir)
				attachLoosePythonPositions(depsGraph, workingDir)
				return sdk.DetectionResult{
					Graphs: sdk.SingleGraphContainer(depsGraph, manifestWithResolution(req, pipenvEvidencePatterns, resolution)),
				}, nil
			}
		}
	}

	if lockPath := filepath.Join(workingDir, "Pipfile.lock"); fileExists(lockPath) {
		installCommand := pipenvSyncCommand(req)
		if err := base.install(ctx, req, "Pipenv detector", installCommand); err == nil && pipenvVenvExists(workingDir) {
			if command, err := pipInspectCommand("pipenv", "run"); err == nil {
				if depsGraph, err := base.resolveGraph(req.Stderr, req.ProjectPath, req.Verbose, "Pipenv detector", command); err == nil {
					annotateGraphScopes(depsGraph, workingDir)
					attachDeclaredPositions(depsGraph, workingDir)
					attachLoosePythonPositions(depsGraph, workingDir)
					resolution := resolutionMetadata(sdk.ResolutionMethodProjectEnvironment, true, append(installCommand, req.InstallArgs...), workingDir)
					logResolution(base.Logger, "Pipenv detector", workingDir, resolution)
					return sdk.DetectionResult{
						Graphs: sdk.SingleGraphContainer(depsGraph, manifestWithResolution(req, pipenvEvidencePatterns, resolution)),
					}, nil
				}
			}
		} else if err != nil {
			logger.Warn("Pipenv detector could not prepare project virtualenv; falling back to Pipfile.lock", zap.Error(err))
		}
	}

	// Fallback: parse Pipfile.lock (flat graph, but always available offline).
	if depsGraph, err := depGraphFromPipfileLock(filepath.Join(workingDir, "Pipfile.lock")); err == nil {
		annotateGraphScopes(depsGraph, workingDir)
		attachDeclaredPositions(depsGraph, workingDir)
		attachLoosePythonPositions(depsGraph, workingDir)
		resolution := resolutionMetadata(sdk.ResolutionMethodManifestOnly, false, nil, workingDir)
		logResolution(base.Logger, "Pipenv detector", workingDir, resolution)
		return sdk.DetectionResult{
			Graphs: sdk.SingleGraphContainer(depsGraph, manifestWithResolution(req, pipenvEvidencePatterns, resolution)),
		}, nil
	}

	return sdk.DetectionResult{}, fmt.Errorf("pipenv detector: unable to resolve dependency graph")
}

// FallbackDetector returns the configured fallback detector.
func (d PipenvDetector) FallbackDetector() sdk.Detector {
	return d.Fallback
}

func (d PipenvDetector) base() baseDetector {
	return baseDetector{
		Logger:     d.Logger,
		WorkingDir: d.WorkingDir,
	}
}

// Install prepares Pipenv dependencies before graph resolution.
func (d PipenvDetector) Install(ctx context.Context, req sdk.DetectionRequest) error {
	return d.base().install(ctx, req, "Pipenv detector", pipenvInstallCommand(d.base().workingDir(req.ProjectPath), req))
}

// pipenvVenvExists checks whether a pipenv virtual environment has been created
// for the given working directory. It avoids triggering lazy venv creation.
func pipenvVenvExists(workingDir string) bool {
	cmd := system.Command("pipenv", "--venv")
	cmd.Dir = workingDir
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	venvPath := strings.TrimSpace(string(out))
	if venvPath == "" {
		return false
	}
	ok, err := system.FileExists(venvPath)
	return err == nil && ok
}

func pipenvInstallCommand(workingDir string, req sdk.DetectionRequest) []string {
	if fileExists(filepath.Join(workingDir, "Pipfile.lock")) {
		return pipenvSyncCommand(req)
	}
	return []string{"pipenv", "install"}
}

func pipenvSyncCommand(req sdk.DetectionRequest) []string {
	command := []string{"pipenv", "sync"}
	if req.ScopeFilter != sdk.ScopeRuntime {
		command = append(command, "--dev")
	}
	return command
}

func pipenvReconstructedInstallCommand(req sdk.DetectionRequest, workingDir string) []string {
	if !req.InstallFirst {
		return nil
	}
	return append(pipenvInstallCommand(workingDir, req), req.InstallArgs...)
}

func fileExists(path string) bool {
	ok, err := system.FileExists(path)
	return err == nil && ok
}

type pipfileLock struct {
	Default map[string]pipfileLockPackage `json:"default"`
	Develop map[string]pipfileLockPackage `json:"develop"`
}

type pipfileLockPackage struct {
	Version string `json:"version"`
}

func depGraphFromPipfileLock(path string) (*sdk.Graph, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read Pipfile.lock: %w", err)
	}
	var lock pipfileLock
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, fmt.Errorf("parse Pipfile.lock: %w", err)
	}
	if len(lock.Default) == 0 && len(lock.Develop) == 0 {
		return nil, fmt.Errorf("pipfile.lock does not contain dependencies")
	}
	depsGraph := sdk.New()
	root := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemPython,
		PackageManager: sdk.PackageManagerPipenv,
		Name:           "root",
		Type:           sdk.PackageTypeProject},
	})

	if err := depsGraph.AddNode(root); err != nil {
		return nil, fmt.Errorf("add root package: %w", err)
	}
	if err := addPipfileLockPackages(depsGraph, root, lock.Default, sdk.ScopeRuntime); err != nil {
		return nil, err
	}
	if err := addPipfileLockPackages(depsGraph, root, lock.Develop, sdk.ScopeDevelopment); err != nil {
		return nil, err
	}
	return depsGraph, nil
}

func addPipfileLockPackages(depsGraph *sdk.Graph, root *sdk.Dependency, packages map[string]pipfileLockPackage, scope sdk.Scope) error {
	for name, pkg := range packages {
		normalizedName := normalizePythonName(name)
		node := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemPython,
			PackageManager: sdk.PackageManagerPipenv,
			Name:           normalizedName,
			Version:        strings.TrimPrefix(pkg.Version, "==")}, Scopes: sdk.ScopesOf(scope),
		})

		if _, exists := depsGraph.Node(node.ID); !exists {
			if err := depsGraph.AddNode(node); err != nil {
				return fmt.Errorf("add Pipfile.lock package %q: %w", normalizedName, err)
			}
		}
		if err := depsGraph.AddEdge(root.ID, node.ID); err != nil {
			return fmt.Errorf("add Pipfile.lock dependency %q: %w", normalizedName, err)
		}
	}
	return nil
}
