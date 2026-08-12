package python

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/bomly-dev/bomly-cli/internal/logging"
	"github.com/bomly-dev/bomly-sdk"
	logkit "github.com/bomly-dev/bomly-sdk/logkit"
	"github.com/bomly-dev/bomly-sdk/system"
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
	Metadata pipInspectMetadata `json:"metadata"`
	// Requested mirrors the installer's REQUESTED marker: true when the
	// package was named on an install command line (or in the requirements
	// file) rather than pulled in as someone else's dependency. `pip inspect`
	// does not report the inverse relation, so a package's parents come from
	// every other package's requires_dist.
	Requested        bool           `json:"requested"`
	DirectURL        map[string]any `json:"direct_url"`
	Installer        string         `json:"installer"`
	MetadataLocation string         `json:"metadata_location"`
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

func (d baseDetector) resolveGraph(req sdk.DetectionRequest, detectorName string, command []string) (*sdk.Graph, error) {
	logger := d.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	if len(command) == 0 {
		return nil, errors.New("python detector command is empty")
	}

	cmd := system.Command(command[0], command[1:]...)
	cmd.Dir = d.workingDir(req.ProjectPath)
	cmd.Env = pythonCommandEnv()
	var out bytes.Buffer
	cmd.Stdout = &out
	commandStderr := logkit.NewCommandStderr(req.Stderr, req.Verbose)
	cmd.Stderr = commandStderr

	started := time.Now()
	logger.Debug("running external dependency detector",
		append([]zap.Field{zap.String("detector", detectorName)}, logkit.CommandFields(command[0], command[1:], cmd.Dir)...)...)
	if err := cmd.Run(); err != nil {
		logger.Warn(fmt.Sprintf("%s failed: %v", detectorName, err))
		fields := []zap.Field{zap.Error(err), zap.String("detector", detectorName)}
		if commandStderr.ByteCount() > 0 {
			fields = append(fields, zap.Int64("stderr_bytes", commandStderr.ByteCount()))
		}
		logger.Debug("external dependency detector failure details", fields...)
		return nil, fmt.Errorf("run %s: %w", detectorName, err)
	}

	declared, err := directPythonDeclarations(cmd.Dir)
	if err != nil {
		return nil, fmt.Errorf("collect declared dependencies for %s: %w", detectorName, err)
	}
	depsGraph, err := depGraphFromPipInspect(out.Bytes(), pythonSyntheticRoot(pythonRootName(req, cmd.Dir)), declared)
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
	commandStderr := logkit.NewCommandStderr(req.Stderr, req.Verbose)
	cmd.Stderr = commandStderr
	started := time.Now()
	logger.Info(fmt.Sprintf("%s running install-first step", detectorName))
	logger.Debug("running python detector install-first",
		append([]zap.Field{zap.String("detector", detectorName)}, logkit.CommandFields(command[0], command[1:], cmd.Dir)...)...)
	if err := cmd.Run(); err != nil {
		fields := []zap.Field{zap.Error(err)}
		if commandStderr.ByteCount() > 0 {
			fields = append(fields, zap.Int64("stderr_bytes", commandStderr.ByteCount()))
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

// depGraphFromPipInspect maps a `pip inspect --local` report onto a dependency
// graph rooted at rootNode. An installed environment is a flat list, so the
// tree is reconstructed from each distribution's requires_dist metadata;
// declared holds the normalized names the project asks for by name (its
// requirements files / manifests) and decides, together with each package's
// REQUESTED marker, which packages hang off the root as direct dependencies.
func depGraphFromPipInspect(raw []byte, rootNode *sdk.Dependency, declared map[string]struct{}) (*sdk.Graph, error) {
	var report pipInspectReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, fmt.Errorf("parse pip inspect json: %w", err)
	}
	if len(report.Installed) == 0 {
		return nil, errors.New("pip inspect output is empty")
	}

	depsGraph := sdk.New()
	if rootNode == nil {
		rootNode = pythonSyntheticRoot("")
	}
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
			Version: pkg.Metadata.Version}, Source: pipInspectDependencySource(pkg.DirectURL), ResolvedURL: pipInspectResolvedURL(pkg.DirectURL), Metadata: sourceRevisionMetadata(pipInspectRevision(pkg.DirectURL)),
		})

		if _, exists := nodesByName[node.Name]; !exists {
			nodesByName[node.Name] = node
		}
		if err := addNodeIfMissing(depsGraph, node); err != nil {
			return nil, err
		}
	}

	// Transitive edges first, so the direct/orphan passes below can tell a
	// package nobody depends on from one that already has a parent.
	for _, pkg := range report.Installed {
		parent := nodesByName[normalizePythonName(pkg.Metadata.Name)]
		if parent == nil {
			continue
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
			if child == nil || child.ID == parent.ID {
				continue
			}
			if err := depsGraph.AddEdge(parent.ID, child.ID); err != nil {
				return nil, fmt.Errorf("add dependency %q -> %q: %w", parent.ID, child.ID, err)
			}
		}
	}

	for _, pkg := range report.Installed {
		node := nodesByName[normalizePythonName(pkg.Metadata.Name)]
		if node == nil || !pipDirectDependency(pkg, declared) {
			continue
		}
		if err := depsGraph.AddEdge(rootNode.ID, node.ID); err != nil {
			return nil, fmt.Errorf("add direct dependency %q: %w", node.ID, err)
		}
	}

	if err := attachOrphansToRoot(depsGraph, rootNode.ID); err != nil {
		return nil, err
	}

	return depsGraph, nil
}

func pipInspectDependencySource(directURL map[string]any) sdk.DependencySource {
	if len(directURL) == 0 {
		return sdk.DependencySourceRegistry
	}
	if _, ok := directURL["dir_info"]; ok {
		return sdk.DependencySourceFile
	}
	if vcsInfo, ok := directURL["vcs_info"].(map[string]any); ok {
		if vcs, _ := vcsInfo["vcs"].(string); strings.EqualFold(strings.TrimSpace(vcs), "git") {
			return sdk.DependencySourceGit
		}
		return sdk.DependencySourceURL
	}
	resolved := pipInspectResolvedURL(directURL)
	if strings.HasPrefix(strings.ToLower(resolved), "file:") {
		return sdk.DependencySourceFile
	}
	if resolved != "" {
		return sdk.DependencySourceURL
	}
	return ""
}

func pipInspectResolvedURL(directURL map[string]any) string {
	value, _ := directURL["url"].(string)
	return strings.TrimSpace(value)
}

func pipInspectRevision(directURL map[string]any) string {
	vcsInfo, _ := directURL["vcs_info"].(map[string]any)
	for _, key := range []string{"commit_id", "requested_revision"} {
		if value, _ := vcsInfo[key].(string); strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func sourceRevisionMetadata(revision string) map[string]any {
	revision = strings.TrimSpace(revision)
	if revision == "" {
		return nil
	}
	return map[string]any{"source_revision": revision}
}

// pipDirectDependency reports whether an installed distribution is something
// the project asked for by name. The project's own requirements files are the
// authority; the installer's REQUESTED marker covers what they cannot name
// (packages pulled in through `-r other.txt` includes, or environments
// populated by another front-end). Everything else is a transitive dependency
// and reaches the graph through its parents' requires_dist edges.
func pipDirectDependency(pkg pipInspectPackage, declared map[string]struct{}) bool {
	if pkg.Requested {
		return true
	}
	_, isDeclared := declared[normalizePythonName(pkg.Metadata.Name)]
	return isDeclared
}

// attachOrphansToRoot wires every package the root cannot reach back to the
// root, so a distribution whose parent metadata is missing (or whose only
// parent was filtered out) stays in the tree instead of dangling as a second
// graph root. Reachability is what matters, not parent count: `requires_dist`
// cycles are legal, and a mutually-dependent pair has parents while still
// being unreachable from the root.
func attachOrphansToRoot(depsGraph *sdk.Graph, rootID string) error {
	if depsGraph == nil {
		return nil
	}
	reachable := make(map[string]struct{}, depsGraph.Size())
	markReachable := func(fromID string) {
		queue := []string{fromID}
		reachable[fromID] = struct{}{}
		for len(queue) > 0 {
			current := queue[0]
			queue = queue[1:]
			children, err := depsGraph.DirectDependencies(current)
			if err != nil {
				continue
			}
			for _, child := range children {
				if child == nil {
					continue
				}
				if _, seen := reachable[child.ID]; seen {
					continue
				}
				reachable[child.ID] = struct{}{}
				queue = append(queue, child.ID)
			}
		}
	}

	markReachable(rootID)
	for _, node := range depsGraph.Nodes() {
		if node == nil {
			continue
		}
		if _, ok := reachable[node.ID]; ok {
			continue
		}
		if err := depsGraph.AddEdge(rootID, node.ID); err != nil {
			return fmt.Errorf("add direct dependency %q: %w", node.ID, err)
		}
		// The newly attached package brings its own subtree back with it.
		markReachable(node.ID)
	}
	return nil
}

// pythonSyntheticRoot builds the node that represents the scanned project
// itself, named by pythonRootName. "root" survives only as the last resort:
// it told the user nothing and collides with a real PyPI package name, which
// is why the node stays FirstParty and is never enriched.
func pythonSyntheticRoot(rootName string) *sdk.Dependency {
	if strings.TrimSpace(rootName) == "" {
		rootName = "root"
	}
	return sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{
		Ecosystem:  sdk.EcosystemPython,
		Name:       rootName,
		Type:       sdk.PackageTypeApplication,
		FirstParty: true,
	}})
}

// pythonRootName names a Python project root. requirements.txt and
// Pipfile.lock projects declare no name of their own, so the closest stable
// thing is used instead, in descending order of specificity: the name in
// pyproject.toml, the subproject directory, the scanned repository, and
// finally the project directory on disk. Bomly's own temp clone directories
// are skipped — they are random per run and mean nothing to the user.
func pythonRootName(req sdk.DetectionRequest, projectPath string) string {
	if name := pyprojectProjectName(projectPath); name != "" {
		return name
	}
	if name := pathBaseName(req.Subproject.RelativePath); name != "" {
		return name
	}
	for _, target := range []sdk.ExecutionTarget{req.Subproject.ExecutionTarget, req.ExecutionTarget} {
		if name := repositoryBaseName(target.RepositoryURL); name != "" {
			return name
		}
	}
	if name := projectDirectoryName(projectPath); name != "" && !strings.HasPrefix(name, "bomly-git-") {
		return name
	}
	return "root"
}

// pythonProjectName derives a display name for a Python project root when no
// detection request is at hand (lockfile parsers reached directly from tests).
func pythonProjectName(projectPath string) string {
	return pythonRootName(sdk.DetectionRequest{}, projectPath)
}

// pythonRootNameOrDefault lets a lockfile parser accept the name its caller
// already derived from the detection request, falling back to what the project
// directory alone can tell us.
func pythonRootNameOrDefault(rootName, projectPath string) string {
	if strings.TrimSpace(rootName) != "" {
		return rootName
	}
	return pythonProjectName(projectPath)
}

// pathBaseName returns the last element of a relative subproject path, or ""
// for the target root.
func pathBaseName(relativePath string) string {
	cleaned := strings.Trim(strings.ReplaceAll(strings.TrimSpace(relativePath), "\\", "/"), "/")
	if cleaned == "" || cleaned == "." {
		return ""
	}
	return path.Base(cleaned)
}

// repositoryBaseName returns the repository name from a remote target URL
// ("https://github.com/acme/billing-service.git" → "billing-service").
func repositoryBaseName(repositoryURL string) string {
	trimmed := strings.TrimSuffix(strings.Trim(strings.TrimSpace(repositoryURL), "/"), ".git")
	if trimmed == "" {
		return ""
	}
	base := path.Base(trimmed)
	if base == "." || base == "/" {
		return ""
	}
	return base
}

// pyprojectProjectName reads the project name from pyproject.toml, covering
// both PEP 621 ([project]) and Poetry 1.x ([tool.poetry]) layouts.
func pyprojectProjectName(projectPath string) string {
	if projectPath == "" {
		return ""
	}
	raw, err := system.ReadRepositoryFile(filepath.Join(projectPath, "pyproject.toml"))
	if err != nil {
		return ""
	}
	var doc struct {
		Project struct {
			Name string `toml:"name"`
		} `toml:"project"`
		Tool struct {
			Poetry struct {
				Name string `toml:"name"`
			} `toml:"poetry"`
		} `toml:"tool"`
	}
	if _, err := toml.Decode(string(raw), &doc); err != nil {
		return ""
	}
	if name := strings.TrimSpace(doc.Project.Name); name != "" {
		return name
	}
	return strings.TrimSpace(doc.Tool.Poetry.Name)
}

// projectDirectoryName returns the project directory's base name, or "" when
// that is not a usable name (the filesystem root, a relative ".", etc.).
func projectDirectoryName(projectPath string) string {
	if strings.TrimSpace(projectPath) == "" {
		return ""
	}
	abs, err := filepath.Abs(projectPath)
	if err != nil {
		abs = projectPath
	}
	base := filepath.Base(filepath.Clean(abs))
	switch base {
	case ".", "..", "/", "\\":
		return ""
	}
	return base
}

func filterPythonToolPackages(depsGraph *sdk.Graph, projectPath, rootName string) (*sdk.Graph, error) {
	if depsGraph == nil {
		return depsGraph, nil
	}
	declared, err := declaredPythonDependencies(projectPath)
	if err != nil {
		return nil, err
	}
	removed := false
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
		removed = true
	}
	// Dropping a tool package can strand the packages it pulled in; re-parent
	// them so the graph keeps a single root.
	if removed {
		if root, ok := depsGraph.Node(pythonSyntheticRoot(rootName).ID); ok {
			if err := attachOrphansToRoot(depsGraph, root.ID); err != nil {
				return nil, err
			}
		}
	}
	return depsGraph, nil
}

// directPythonDeclarations returns the normalized names a project declares as
// its own dependencies. Only hand-authored declarations count: requirements
// files the user writes, the dependency tables of pyproject.toml, and the
// Pipfile.
//
// Lockfiles are deliberately excluded, including `requirements.lock`. They
// record the resolved closure — every transitive package appears as a record
// just like a direct one — so counting them as declarations would mark the
// whole environment direct, which is the bug this set exists to fix. Note this
// differs from declaredPythonDependencies, which answers the looser question
// of whether a package belongs to the project at all.
func directPythonDeclarations(projectPath string) (map[string]struct{}, error) {
	declared := make(map[string]struct{})
	if projectPath == "" {
		return declared, nil
	}
	for _, name := range []string{"requirements.txt", "requirements-dev.txt", "requirements.in"} {
		if err := collectRequirementFileDependencies(filepath.Join(projectPath, name), declared); err != nil {
			return nil, err
		}
	}
	collectPyprojectDeclarations(filepath.Join(projectPath, "pyproject.toml"), declared)
	collectPipfileDeclarations(filepath.Join(projectPath, "Pipfile"), declared)
	return declared, nil
}

// collectPyprojectDeclarations reads the dependency tables of pyproject.toml:
// PEP 621 ([project] dependencies / optional-dependencies), PEP 735
// ([dependency-groups]), Poetry ([tool.poetry] dependencies, dev-dependencies,
// group.*.dependencies), and uv ([tool.uv] dev-dependencies). Parse failures
// are non-fatal — a project with an unreadable manifest still gets a graph,
// just without the declaration hint.
func collectPyprojectDeclarations(path string, declared map[string]struct{}) {
	raw, err := system.ReadRepositoryFile(path)
	if err != nil {
		return
	}
	var doc map[string]any
	if _, err := toml.Decode(string(raw), &doc); err != nil {
		return
	}

	if project, ok := doc["project"].(map[string]any); ok {
		addRequirementList(project["dependencies"], declared)
		if optional, ok := project["optional-dependencies"].(map[string]any); ok {
			for _, group := range optional {
				addRequirementList(group, declared)
			}
		}
	}
	if groups, ok := doc["dependency-groups"].(map[string]any); ok {
		for _, group := range groups {
			addRequirementList(group, declared)
		}
	}

	tool, _ := doc["tool"].(map[string]any)
	if poetry, ok := tool["poetry"].(map[string]any); ok {
		addDependencyTableKeys(poetry["dependencies"], declared)
		addDependencyTableKeys(poetry["dev-dependencies"], declared)
		if groups, ok := poetry["group"].(map[string]any); ok {
			for _, group := range groups {
				groupTable, _ := group.(map[string]any)
				addDependencyTableKeys(groupTable["dependencies"], declared)
			}
		}
	}
	if uv, ok := tool["uv"].(map[string]any); ok {
		addRequirementList(uv["dev-dependencies"], declared)
	}
}

// collectPipfileDeclarations reads a Pipfile's [packages] and [dev-packages]
// tables. Pipfile.lock is not read here: it is a lockfile.
func collectPipfileDeclarations(path string, declared map[string]struct{}) {
	raw, err := system.ReadRepositoryFile(path)
	if err != nil {
		return
	}
	var doc map[string]any
	if _, err := toml.Decode(string(raw), &doc); err != nil {
		return
	}
	addDependencyTableKeys(doc["packages"], declared)
	addDependencyTableKeys(doc["dev-packages"], declared)
}

// addRequirementList records the package names in an array of PEP 508
// requirement strings, skipping non-string entries such as PEP 735
// `{include-group = "..."}` tables.
func addRequirementList(value any, declared map[string]struct{}) {
	items, ok := value.([]any)
	if !ok {
		return
	}
	for _, item := range items {
		if requirement, ok := item.(string); ok {
			addDeclaredPythonName(requirementName(requirement), declared)
		}
	}
}

// addDependencyTableKeys records the keys of a name-to-constraint dependency
// table, dropping Poetry's "python" interpreter-version marker.
func addDependencyTableKeys(value any, declared map[string]struct{}) {
	table, ok := value.(map[string]any)
	if !ok {
		return
	}
	for name := range table {
		if strings.EqualFold(strings.TrimSpace(name), "python") {
			continue
		}
		addDeclaredPythonName(name, declared)
	}
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
	raw, err := system.ReadRepositoryFile(path)
	if errors.Is(err, os.ErrNotExist) {
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
	raw, err := system.ReadRepositoryFile(path)
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
	raw, err := system.ReadRepositoryFile(path)
	if errors.Is(err, os.ErrNotExist) {
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
	if raw, err := system.ReadRepositoryFile(filepath.Join(projectPath, "pyproject.toml")); err == nil {
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
	if raw, err := system.ReadRepositoryFile(filepath.Join(projectPath, "Pipfile")); err == nil {
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
	if raw, err := system.ReadRepositoryFile(filepath.Join(projectPath, "requirements-dev.txt")); err == nil {
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
