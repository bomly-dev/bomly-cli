package python

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/logging"
	"github.com/bomly-dev/bomly-cli/internal/system"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

var pythonExecutables = []string{"python", "python3", "py"}
var requirementNamePattern = regexp.MustCompile(`^[A-Za-z0-9._-]+`)
var pythonToolPackageNames = map[string]struct{}{
	"pip":        {},
	"setuptools": {},
	"wheel":      {},
	"uv":         {},
	"poetry":     {},
	"pipenv":     {},
}

type baseDetector struct {
	Logger     *zap.Logger
	WorkingDir string
}

type pipInspectReport struct {
	Installed []pipInspectPackage `json:"installed"`
}

type pipInspectPackage struct {
	Metadata         pipInspectMetadata `json:"metadata"`
	Requested        bool               `json:"requested"`
	RequestedBy      []string           `json:"requested_by"`
	DirectURL        map[string]any     `json:"direct_url"`
	Installer        string             `json:"installer"`
	MetadataLocation string             `json:"metadata_location"`
}

type pipInspectMetadata struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	RequiresDist []string `json:"requires_dist"`
}

func (d baseDetector) workingDir(projectPath string) string {
	if d.WorkingDir != "" {
		return d.WorkingDir
	}
	return projectPath
}

func (d baseDetector) applicable(ctx context.Context, req sdk.DetectionRequest, names ...string) (bool, error) {
	_ = ctx
	workingDir := d.workingDir(req.ProjectPath)
	for _, name := range names {
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

func (d baseDetector) resolveGraph(stderr io.Writer, projectPath string, verbose bool, detectorName string, command []string) (*sdk.Graph, error) {
	logger := d.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	if len(command) == 0 {
		return nil, errors.New("python detector command is empty")
	}

	cmd := system.Command(command[0], command[1:]...)
	cmd.Dir = d.workingDir(projectPath)
	cmd.Env = pythonCommandEnv()
	var out bytes.Buffer
	cmd.Stdout = &out
	commandStderr := logging.NewCommandStderr(stderr, verbose)
	cmd.Stderr = commandStderr

	started := time.Now()
	sanitizedCommand := sanitizeCommand(command)
	logger.Debug("running external dependency detector", zap.String("detector", detectorName), zap.String("working_dir", cmd.Dir), zap.String("executable", sanitizedCommand[0]), zap.Strings("args", sanitizedCommand[1:]))
	if err := cmd.Run(); err != nil {
		logger.Warn(fmt.Sprintf("%s failed: %v", detectorName, err))
		fields := []zap.Field{zap.Error(err), zap.String("detector", detectorName)}
		if commandStderr.String() != "" {
			fields = append(fields, zap.String("stderr", commandStderr.String()))
		}
		logger.Debug("external dependency detector failure details", fields...)
		return nil, fmt.Errorf("run %s: %w", detectorName, err)
	}

	depsGraph, err := depGraphFromPipInspect(out.Bytes())
	if err != nil {
		logger.Warn(fmt.Sprintf("Failed to map %s output to a dependency graph: %v", detectorName, err))
		logger.Debug("dependency detector output mapping failed", zap.String("detector", detectorName), zap.Error(err))
		return nil, err
	}

	logger.Info(fmt.Sprintf("%s found %d dependencies in %s", detectorName, depsGraph.Size(), logging.FormatDuration(time.Since(started))))
	return depsGraph, nil
}

func (d baseDetector) install(ctx context.Context, req sdk.DetectionRequest, detectorName string, command []string) error {
	logger := d.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	if len(command) == 0 {
		return errors.New("python install command is empty")
	}
	_ = ctx
	command = append(append([]string{}, command...), req.InstallArgs...)
	cmd := system.Command(command[0], command[1:]...)
	cmd.Dir = d.workingDir(req.ProjectPath)
	cmd.Env = pythonCommandEnv()
	commandStderr := logging.NewCommandStderr(req.Stderr, req.Verbose)
	cmd.Stderr = commandStderr
	started := time.Now()
	logger.Info(fmt.Sprintf("%s running install-first step", detectorName))
	sanitizedCommand := sanitizeCommand(command)
	logger.Debug("running python detector install-first", zap.String("detector", detectorName), zap.String("working_dir", cmd.Dir), zap.String("executable", sanitizedCommand[0]), zap.Strings("args", sanitizedCommand[1:]))
	if err := cmd.Run(); err != nil {
		fields := []zap.Field{zap.Error(err)}
		if commandStderr.String() != "" {
			fields = append(fields, zap.String("stderr", commandStderr.String()))
		}
		logger.Debug("python detector install-first failure details", fields...)
		return fmt.Errorf("run %s install step: %w", detectorName, err)
	}
	logger.Info(fmt.Sprintf("%s install-first completed in %s", detectorName, logging.FormatDuration(time.Since(started))))
	return nil
}

func pythonCommandEnv() []string {
	env := os.Environ()
	env = append(env, "PYTHONIOENCODING=utf-8", "PYTHONUTF8=1")
	return env
}

func pythonCommand() ([]string, error) {
	for _, executable := range pythonExecutables {
		if _, err := system.LookPath(executable); err == nil {
			return []string{executable}, nil
		}
	}
	return nil, errors.New("resolve python executable: executable not found")
}

func pipInspectCommand(prefix ...string) ([]string, error) {
	pythonCmd, err := pythonCommand()
	if err != nil {
		return nil, err
	}
	command := make([]string, 0, len(prefix)+len(pythonCmd)+4)
	command = append(command, prefix...)
	command = append(command, pythonCmd...)
	command = append(command, "-m", "pip", "inspect", "--local")
	return command, nil
}

func depGraphFromPipInspect(raw []byte) (*sdk.Graph, error) {
	var report pipInspectReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, fmt.Errorf("parse pip inspect json: %w", err)
	}
	if len(report.Installed) == 0 {
		return nil, errors.New("pip inspect output is empty")
	}

	depsGraph := sdk.New()
	rootNode := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemPython,
		Name: "root",
		// Synthetic root for the scanned environment; "root" is also a real
		// PyPI package name, so enrichment must never query it.
		FirstParty: true},
	})

	if err := depsGraph.AddNode(rootNode); err != nil {
		return nil, fmt.Errorf("add root node: %w", err)
	}

	nodesByName := make(map[string]*sdk.Dependency, len(report.Installed))
	for _, pkg := range report.Installed {
		if pkg.Metadata.Name == "" {
			continue
		}
		node := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemPython,
			Name:    normalizePythonName(pkg.Metadata.Name),
			Version: pkg.Metadata.Version},
		})

		if _, exists := nodesByName[node.Name]; !exists {
			nodesByName[node.Name] = node
		}
		if err := addNodeIfMissing(depsGraph, node); err != nil {
			return nil, err
		}
	}

	for _, pkg := range report.Installed {
		parent := nodesByName[normalizePythonName(pkg.Metadata.Name)]
		if parent == nil {
			continue
		}
		if pkg.Requested || len(pkg.RequestedBy) == 0 {
			if err := depsGraph.AddEdge(rootNode.ID, parent.ID); err != nil {
				return nil, fmt.Errorf("add direct dependency %q: %w", parent.ID, err)
			}
		}
		for _, requirement := range pkg.Metadata.RequiresDist {
			// Skip extras-conditional requirements (e.g. "pytest; extra == 'test'").
			// These are optional and should not create graph edges that override
			// explicitly-scoped dev dependencies.
			if isExtrasRequirement(requirement) {
				continue
			}
			dependencyName := requirementName(requirement)
			if dependencyName == "" {
				continue
			}
			child := nodesByName[dependencyName]
			if child == nil {
				continue
			}
			if err := depsGraph.AddEdge(parent.ID, child.ID); err != nil {
				return nil, fmt.Errorf("add dependency %q -> %q: %w", parent.ID, child.ID, err)
			}
		}
	}

	return depsGraph, nil
}

func filterPythonToolPackages(depsGraph *sdk.Graph, projectPath string) (*sdk.Graph, error) {
	if depsGraph == nil {
		return depsGraph, nil
	}
	declared, err := declaredPythonDependencies(projectPath)
	if err != nil {
		return nil, err
	}
	for _, pkg := range depsGraph.Nodes() {
		if pkg == nil {
			continue
		}
		name := normalizePythonName(pkg.Name)
		if _, isTool := pythonToolPackageNames[name]; !isTool {
			continue
		}
		if _, keep := declared[name]; keep {
			continue
		}
		depsGraph.RemoveNode(pkg.ID)
	}
	return depsGraph, nil
}

func declaredPythonDependencies(projectPath string) (map[string]struct{}, error) {
	declared := make(map[string]struct{})
	if projectPath == "" {
		return declared, nil
	}
	for _, name := range []string{"requirements.txt", "requirements-dev.txt", "requirements.in", "requirements.lock"} {
		if err := collectRequirementFileDependencies(filepath.Join(projectPath, name), declared); err != nil {
			return nil, err
		}
	}
	for _, name := range []string{"pyproject.toml", "poetry.lock", "uv.lock", "Pipfile.lock", "Pipfile"} {
		if err := collectLoosePythonManifestDependencies(filepath.Join(projectPath, name), declared); err != nil {
			return nil, err
		}
	}
	return declared, nil
}

func collectRequirementFileDependencies(path string, declared map[string]struct{}) error {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read Python requirements %q: %w", path, err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" || strings.HasPrefix(line, "-") {
			continue
		}
		addDeclaredPythonName(requirementName(line), declared)
	}
	return nil
}

// declaredPythonPositions walks every requirements*.txt file in
// projectPath and returns a map from normalized package name to the
// declaration site (file + line). Used to attach
// PackageLocation.Position to graph packages so SARIF / explain
// output can deep-link into the user's lockfile. Loose manifests
// (pyproject.toml, poetry.lock, etc.) are not handled here yet —
// they need a positional decoder per format.
func declaredPythonPositions(projectPath string) map[string]*sdk.SourcePosition {
	positions := make(map[string]*sdk.SourcePosition)
	if projectPath == "" {
		return positions
	}
	for _, name := range []string{"requirements.txt", "requirements-dev.txt", "requirements.in", "requirements.lock"} {
		collectRequirementFilePositions(filepath.Join(projectPath, name), name, positions)
	}
	return positions
}

func collectRequirementFilePositions(path, relPath string, positions map[string]*sdk.SourcePosition) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for i, raw := range strings.Split(string(raw), "\n") {
		line := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
		if line == "" || strings.HasPrefix(line, "-") {
			continue
		}
		name := requirementName(line)
		if name == "" {
			continue
		}
		normalized := normalizePythonName(name)
		if normalized == "" {
			continue
		}
		// Don't overwrite an earlier file's match (requirements.txt
		// wins over requirements-dev.txt for the same package).
		if _, exists := positions[normalized]; exists {
			continue
		}
		positions[normalized] = &sdk.SourcePosition{File: relPath, Line: i + 1}
	}
}

// attachDeclaredPositions populates PackageLocation.Position on
// graph packages whose normalized name appears in a requirements
// file. Transitive deps that are not declared anywhere get no
// Locations entry from this pass.
func attachDeclaredPositions(depsGraph *sdk.Graph, projectPath string) {
	if depsGraph == nil {
		return
	}
	positions := declaredPythonPositions(projectPath)
	if len(positions) == 0 {
		return
	}
	for _, pkg := range depsGraph.Nodes() {
		if pkg == nil {
			continue
		}
		pos, ok := positions[normalizePythonName(pkg.Name)]
		if !ok {
			continue
		}
		// Avoid duplicating if a Location with the same RealPath
		// already exists.
		duplicate := false
		for _, loc := range pkg.Locations {
			if loc.RealPath == pos.File {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		pkg.Locations = append(pkg.Locations, sdk.PackageLocation{
			RealPath:   pos.File,
			AccessPath: pos.File,
			Position:   pos,
		})
	}
}

func collectLoosePythonManifestDependencies(path string, declared map[string]struct{}) error {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read Python manifest %q: %w", path, err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "name = ") {
			value := strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "name = ")), `"'`)
			addDeclaredPythonName(value, declared)
			continue
		}
		addDeclaredPythonName(requirementName(strings.Trim(line, `"',[]{} `)), declared)
	}
	return nil
}

func addDeclaredPythonName(name string, declared map[string]struct{}) {
	name = normalizePythonName(name)
	if name == "" {
		return
	}
	declared[name] = struct{}{}
}

func requirementName(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	match := requirementNamePattern.FindString(trimmed)
	return normalizePythonName(match)
}

// isExtrasRequirement reports whether a PEP 508 requirement string is gated
// behind an extras marker (e.g. `pytest; extra == "test"`). Such requirements
// are optional and should not create transitive graph edges.
func isExtrasRequirement(requirement string) bool {
	if idx := strings.Index(requirement, ";"); idx >= 0 {
		marker := strings.ToLower(requirement[idx+1:])
		return strings.Contains(marker, "extra")
	}
	return false
}

func installRequirementsPath(projectPath string) (string, error) {
	for _, name := range []string{"requirements.txt", "requirements-dev.txt", "requirements.in", "requirements.lock"} {
		candidate := filepath.Join(projectPath, name)
		exists, err := system.FileExists(candidate)
		if err != nil {
			return "", err
		}
		if exists {
			return name, nil
		}
	}
	return "", fmt.Errorf("no supported requirements file found")
}

func normalizePythonName(value string) string {
	return strings.ToLower(strings.ReplaceAll(value, "_", "-"))
}

func addNodeIfMissing(depsGraph *sdk.Graph, node *sdk.Dependency) error {
	if _, ok := depsGraph.Node(node.ID); ok {
		return nil
	}
	if err := depsGraph.AddNode(node); err != nil {
		return fmt.Errorf("add node %q: %w", node.ID, err)
	}
	return nil
}

// annotateGraphScopes assigns runtime/development scope to packages in a pip-inspect-built
// graph. All non-root packages default to ScopeRuntime; packages declared as dev dependencies
// in pyproject.toml (Poetry / UV) or Pipfile are marked ScopeDevelopment. Scope is propagated
// transitively: a package reachable from a runtime path is always runtime.
func annotateGraphScopes(depsGraph *sdk.Graph, projectPath string) {
	if depsGraph == nil {
		return
	}
	roots := depsGraph.Roots()
	if len(roots) == 0 {
		return
	}
	rootID := ""
	for _, root := range roots {
		if root != nil {
			rootID = root.ID
			break
		}
	}
	if rootID == "" {
		return
	}

	devDeps := collectPythonDevDependencies(projectPath)

	directDeps, err := depsGraph.DirectDependencies(rootID)
	if err != nil || len(directDeps) == 0 {
		// Fall back: graph has no edges from root — use devDeps by name for best-effort scoping.
		for _, pkg := range depsGraph.Nodes() {
			if pkg == nil || pkg.ID == rootID {
				continue
			}
			name := normalizePythonName(pkg.Name)
			if _, isDev := devDeps[name]; isDev {
				pkg.AddScope(sdk.ScopeDevelopment)
			} else if pkg.PrimaryScope() == sdk.ScopeUnknown {
				pkg.AddScope(sdk.ScopeRuntime)
			}
		}
		return
	}

	directScopes := make(map[string]sdk.Scope, len(directDeps))
	for _, dep := range directDeps {
		if dep == nil {
			continue
		}
		name := normalizePythonName(dep.Name)
		scope := sdk.ScopeRuntime
		if _, isDev := devDeps[name]; isDev {
			scope = sdk.ScopeDevelopment
		}
		directScopes[dep.Name] = scope
		directScopes[name] = scope
	}

	// BFS from root, propagating scopes. Runtime always wins over development.
	propagated := make(map[string]sdk.Scope, depsGraph.Size())
	queue := make([]*sdk.Dependency, 0, len(directDeps))
	for _, dep := range directDeps {
		if dep == nil {
			continue
		}
		scope := directScopes[dep.Name]
		if scope == sdk.ScopeUnknown {
			scope = sdk.ScopeRuntime
		}
		dep.AddScope(scope)
		propagated[dep.ID] = sdk.MergeScope(propagated[dep.ID], scope)
		queue = append(queue, dep)
	}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		scope := propagated[current.ID]
		if scope == sdk.ScopeUnknown {
			continue
		}
		children, err := depsGraph.DirectDependencies(current.ID)
		if err != nil {
			continue
		}
		for _, child := range children {
			if child == nil || child.ID == rootID {
				continue
			}
			nextScope := sdk.MergeScope(propagated[child.ID], scope)
			if nextScope == propagated[child.ID] && child.PrimaryScope() == nextScope {
				continue
			}
			propagated[child.ID] = nextScope
			child.AddScope(nextScope)
			queue = append(queue, child)
		}
	}
	// Any remaining unscoped non-root packages get runtime.
	for _, pkg := range depsGraph.Nodes() {
		if pkg != nil && pkg.ID != rootID && pkg.PrimaryScope() == sdk.ScopeUnknown {
			pkg.AddScope(sdk.ScopeRuntime)
		}
	}
}

// collectPythonDevDependencies returns the normalized names of packages declared as
// development dependencies in pyproject.toml (Poetry/UV) or Pipfile.
func collectPythonDevDependencies(projectPath string) map[string]struct{} {
	devDeps := make(map[string]struct{})
	if projectPath == "" {
		return devDeps
	}

	// poetry / uv via pyproject.toml
	if raw, err := os.ReadFile(filepath.Join(projectPath, "pyproject.toml")); err == nil {
		section := ""
		inDevArray := false
		for _, line := range strings.Split(string(raw), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "[") {
				section = strings.ToLower(strings.Trim(trimmed, "[]"))
				inDevArray = false
				continue
			}
			// Poetry: [tool.poetry.dev-dependencies] and [tool.poetry.group.dev.dependencies]
			if strings.Contains(section, "dev-dependencies") || strings.Contains(section, "group.dev") {
				name := requirementName(strings.SplitN(trimmed, "=", 2)[0])
				if name != "" {
					devDeps[name] = struct{}{}
				}
				continue
			}
			// UV: [tool.uv] dev-dependencies = [...] multiline array
			if section == "tool.uv" {
				if strings.HasPrefix(trimmed, "dev-dependencies") {
					inDevArray = true
					// handle inline items after "="
					if idx := strings.Index(trimmed, "["); idx >= 0 {
						parseDevArrayItems(trimmed[idx:], devDeps)
					}
					continue
				}
			}
			// PEP 735 [dependency-groups] dev = [...]
			if section == "dependency-groups" {
				if strings.HasPrefix(trimmed, "dev") {
					inDevArray = true
					if idx := strings.Index(trimmed, "["); idx >= 0 {
						parseDevArrayItems(trimmed[idx:], devDeps)
					}
					continue
				}
			}
			if inDevArray {
				if strings.HasSuffix(trimmed, "]") {
					parseDevArrayItems(trimmed, devDeps)
					inDevArray = false
					continue
				}
				parseDevArrayItems(trimmed, devDeps)
			}
		}
	}

	// Pipfile [dev-packages]
	if raw, err := os.ReadFile(filepath.Join(projectPath, "Pipfile")); err == nil {
		inDev := false
		for _, line := range strings.Split(string(raw), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "[") {
				inDev = strings.ToLower(strings.Trim(trimmed, "[]")) == "dev-packages"
				continue
			}
			if inDev {
				name := requirementName(strings.SplitN(trimmed, "=", 2)[0])
				if name != "" {
					devDeps[name] = struct{}{}
				}
			}
		}
	}

	// pip: requirements-dev.txt (plain list of dev packages)
	if raw, err := os.ReadFile(filepath.Join(projectPath, "requirements-dev.txt")); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "-") {
				continue
			}
			name := requirementName(trimmed)
			if name != "" {
				devDeps[name] = struct{}{}
			}
		}
	}

	return devDeps
}

func parseDevArrayItems(text string, devDeps map[string]struct{}) {
	// Extract quoted package names from a TOML array fragment like ["pytest>=7", "black"]
	for _, part := range strings.FieldsFunc(text, func(r rune) bool {
		return r == '[' || r == ']' || r == ',' || r == '"' || r == '\''
	}) {
		name := requirementName(strings.TrimSpace(part))
		if name != "" {
			devDeps[name] = struct{}{}
		}
	}
}
