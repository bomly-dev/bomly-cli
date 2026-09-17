package python

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	detectorkit "github.com/bomly-dev/bomly-sdk/detectorkit"
	logging "github.com/bomly-dev/bomly-sdk/logkit"
	"github.com/bomly-dev/bomly-sdk/system"
	"go.uber.org/zap"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

// PipenvDetector resolves Python dependencies through Pipenv.
type PipenvDetector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   plugin.Detector
}

var pipenvEvidencePatterns = []string{"Pipfile", "Pipfile.lock"}

// PackageManagerSupport returns Pipenv package-manager discovery metadata.
func (d PipenvDetector) PackageManagerSupport() []plugin.PackageManagerSupport {
	return []plugin.PackageManagerSupport{plugin.Support(model.PackageManagerPipenv, pipenvEvidencePatterns...)}
}

// Ready reports whether Pipenv is available.
func (d PipenvDetector) Ready(context.Context, plugin.DetectionRequest) error {
	_, err := system.LookPath("pipenv")
	return detectorkit.CommandNotReadyError("pipenv", err)
}

// Applicable reports whether Pipenv manifests are present.
func (d PipenvDetector) Applicable(ctx context.Context, req plugin.DetectionRequest) (bool, error) {
	return d.base().applicable(ctx, req, "Pipfile", "Pipfile.lock")
}

// Descriptor describes the Pipenv detector.
func (d PipenvDetector) Descriptor() plugin.DetectorDescriptor {
	return plugin.DetectorDescriptor{
		IgnoredDirectories:      []string{"__pycache__"},
		IgnoredDirectoryMarkers: []string{"pyvenv.cfg"},
		Name:                    detectors.NamePipenv,
		RemediationCapabilities: pipenvRemediationCapabilities(),
		Technique:               plugin.BuildToolTechnique,
		SupportedEcosystems:     []model.Ecosystem{model.EcosystemPython},
		SupportedManagers:       []model.PackageManager{model.PackageManagerPipenv},
		Tags:                    []string{"graph-resolution", "component-targeting"},
		SupportsInstallFirst:    true,
	}
}

// ResolveGraph resolves a Python dependency graph through Pipenv.
func (d PipenvDetector) ResolveGraph(ctx context.Context, req plugin.DetectionRequest) (plugin.DetectionResult, error) {
	// Prefer the request-scoped logger (bound to this subproject) so
	// concurrent per-subproject resolution stays attributable in logs.
	d.Logger = req.DetectorLogger(d.Logger)
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
	if pipenvVenvExists(workingDir, logger, req.Stderr, req.Verbose) {
		command, err := pipInspectCommand("pipenv", "run")
		if err == nil {
			if depsGraph, err := base.resolveGraph(req, "Pipenv detector", command); err == nil {
				resolution := resolutionMetadata(model.ResolutionMethodProjectEnvironment, false, nil, workingDir)
				logResolution(base.Logger, "Pipenv detector", workingDir, resolution)
				annotateGraphScopes(depsGraph, workingDir)
				attachDeclaredPositions(depsGraph, workingDir)
				attachLoosePythonPositions(depsGraph, workingDir)
				return detectors.Attributed(plugin.DetectionResult{
					Graphs: model.SingleGraphContainer(depsGraph, manifestWithResolution(req, pipenvEvidencePatterns, resolution)),
				}), nil
			}
		}
	}

	if lockPath := filepath.Join(workingDir, "Pipfile.lock"); fileExists(lockPath) {
		installCommand := pipenvSyncCommand(req)
		if err := base.install(ctx, req, "Pipenv detector", installCommand); err == nil && pipenvVenvExists(workingDir, logger, req.Stderr, req.Verbose) {
			if command, err := pipInspectCommand("pipenv", "run"); err == nil {
				if depsGraph, err := base.resolveGraph(req, "Pipenv detector", command); err == nil {
					annotateGraphScopes(depsGraph, workingDir)
					attachDeclaredPositions(depsGraph, workingDir)
					attachLoosePythonPositions(depsGraph, workingDir)
					resolution := resolutionMetadata(model.ResolutionMethodProjectEnvironment, true, append(installCommand, req.InstallArgs...), workingDir)
					logResolution(base.Logger, "Pipenv detector", workingDir, resolution)
					return detectors.Attributed(plugin.DetectionResult{
						Graphs: model.SingleGraphContainer(depsGraph, manifestWithResolution(req, pipenvEvidencePatterns, resolution)),
					}), nil
				}
			}
		} else if err != nil {
			logger.Warn("Pipenv detector could not prepare project virtualenv; falling back to Pipfile.lock", zap.Error(err))
		}
	}

	// Fallback: parse Pipfile.lock (flat graph, but always available offline).
	if depsGraph, err := depGraphFromPipfileLock(filepath.Join(workingDir, "Pipfile.lock"), pythonRootName(req, workingDir)); err == nil {
		annotateGraphScopes(depsGraph, workingDir)
		attachDeclaredPositions(depsGraph, workingDir)
		attachLoosePythonPositions(depsGraph, workingDir)
		resolution := resolutionMetadata(model.ResolutionMethodManifestOnly, false, nil, workingDir)
		logResolution(base.Logger, "Pipenv detector", workingDir, resolution)
		return detectors.Attributed(plugin.DetectionResult{
			Graphs: model.SingleGraphContainer(depsGraph, manifestWithResolution(req, pipenvEvidencePatterns, resolution)),
		}), nil
	}

	return plugin.DetectionResult{}, fmt.Errorf("pipenv detector: unable to resolve dependency graph")
}

// FallbackDetector returns the configured fallback detector.
func (d PipenvDetector) FallbackDetector() plugin.Detector {
	return d.Fallback
}

func (d PipenvDetector) base() baseDetector {
	return baseDetector{
		Logger:     d.Logger,
		WorkingDir: d.WorkingDir,
		Manager:    model.PackageManagerPipenv,
	}
}

// Install prepares Pipenv dependencies before graph resolution.
func (d PipenvDetector) Install(ctx context.Context, req plugin.DetectionRequest) error {
	return d.base().install(ctx, req, "Pipenv detector", pipenvInstallCommand(d.base().workingDir(req.ProjectPath), req))
}

// pipenvVenvExists checks whether a pipenv virtual environment has been created
// for the given working directory. It avoids triggering lazy venv creation.
func pipenvVenvExists(workingDir string, logger *zap.Logger, stderr io.Writer, debug bool) bool {
	executable := "pipenv"
	args := []string{"--venv"}
	cmd := system.Command(executable, args...)
	cmd.Dir = workingDir
	cmd.Stderr = logging.NewCommandStderr(stderr, debug)
	logger.Debug("checking Pipenv virtualenv", logging.CommandFields(executable, args, workingDir)...)
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

func pipenvInstallCommand(workingDir string, req plugin.DetectionRequest) []string {
	if fileExists(filepath.Join(workingDir, "Pipfile.lock")) {
		return pipenvSyncCommand(req)
	}
	return []string{"pipenv", "install"}
}

func pipenvSyncCommand(req plugin.DetectionRequest) []string {
	command := []string{"pipenv", "sync"}
	if req.ScopeFilter != model.ScopeRuntime {
		command = append(command, "--dev")
	}
	return command
}

func pipenvReconstructedInstallCommand(req plugin.DetectionRequest, workingDir string) []string {
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
	Git     string `json:"git"`
	Path    string `json:"path"`
	File    string `json:"file"`
	Index   string `json:"index"`
	Ref     string `json:"ref"`
}

func depGraphFromPipfileLock(path, rootName string) (*model.Graph, error) {
	raw, err := system.ReadRepositoryFile(path)
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
	depsGraph := model.New()
	root, err := pythonModuleRoot(model.Coordinates{
		Ecosystem:      model.EcosystemPython,
		PackageManager: model.PackageManagerPipenv,
		Name:           pythonRootNameOrDefault(rootName, filepath.Dir(path)),
		Type:           model.PackageTypeProject,
	})
	if err != nil {
		return nil, fmt.Errorf("build root node: %w", err)
	}
	if err := depsGraph.AddNode(root); err != nil {
		return nil, fmt.Errorf("add root package: %w", err)
	}
	if err := addPipfileLockPackages(depsGraph, root, lock.Default, model.ScopeRuntime); err != nil {
		return nil, err
	}
	if err := addPipfileLockPackages(depsGraph, root, lock.Develop, model.ScopeDevelopment); err != nil {
		return nil, err
	}
	return depsGraph, nil
}

func addPipfileLockPackages(depsGraph *model.Graph, root model.GraphNode, packages map[string]pipfileLockPackage, scope model.Scope) error {
	for name, pkg := range packages {
		normalizedName := normalizePythonName(name)
		node, err := model.NewDependencyNode(model.Coordinates{Ecosystem: model.EcosystemPython,
			PackageManager: model.PackageManagerPipenv,
			Name:           normalizedName,
			Version:        strings.TrimPrefix(pkg.Version, "==")})
		if err != nil {
			return fmt.Errorf("build dependency node: %w", err)
		}
		node.Source = pipfileDependencySource(pkg)
		node.ResolvedURL = pipfileResolvedURL(pkg)
		node.Metadata = sourceRevisionMetadata(pkg.Ref)
		node.Scopes = model.ScopesOf(scope)
		setPipenvOrigin(node, pkg)

		// One package can be listed in both groups; they are one node, and the
		// shared helper settles what it claims.
		if _, err := detectorkit.EnsureNode(depsGraph, node); err != nil {
			return fmt.Errorf("add Pipfile.lock package %q: %w", normalizedName, err)
		}
		if err := depsGraph.AddEdge(root.NodeID(), node.NodeID()); err != nil {
			return fmt.Errorf("add Pipfile.lock dependency %q: %w", normalizedName, err)
		}
	}
	return nil
}

func pipfileDependencySource(pkg pipfileLockPackage) model.DependencySource {
	switch {
	case strings.TrimSpace(pkg.Git) != "":
		return model.DependencySourceGit
	case strings.TrimSpace(pkg.Path) != "", strings.HasPrefix(strings.ToLower(strings.TrimSpace(pkg.File)), "file:"):
		return model.DependencySourceFile
	case strings.TrimSpace(pkg.File) != "":
		if strings.Contains(strings.TrimSpace(pkg.File), "://") {
			return model.DependencySourceURL
		}
		return model.DependencySourceFile
	case strings.TrimSpace(pkg.Index) != "", strings.TrimSpace(pkg.Version) != "":
		return model.DependencySourceRegistry
	default:
		return ""
	}
}

func pipfileResolvedURL(pkg pipfileLockPackage) string {
	for _, value := range []string{pkg.Git, pkg.Path, pkg.File} {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
