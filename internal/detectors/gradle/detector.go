package gradle

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/logging"
	"github.com/bomly-dev/bomly-cli/internal/system"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// Detector resolves Gradle dependency graphs using the Gradle wrapper when present,
// or a globally installed Gradle binary otherwise.
type Detector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   sdk.Detector
}

var evidencePatterns = []string{"build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts", "gradle.lockfile*"}

// PackageManagerSupport returns Gradle package-manager discovery metadata.
func (d Detector) PackageManagerSupport() []sdk.PackageManagerSupport {
	return []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerGradle, evidencePatterns...).WithMultiModule()}
}

// Ready returns nil when a Gradle wrapper is present for the request's working
// directory (or gradle is on PATH) and a usable Java runtime is available.
func (d Detector) Ready(ctx context.Context, req sdk.DetectionRequest) error {
	const executableName = "gradle"
	workingDir := d.WorkingDir
	if workingDir == "" {
		workingDir = detectors.RequestWorkingDir(req)
	}
	if workingDir == "" {
		if _, err := system.LookPath(executableName); err != nil {
			return detectors.CommandNotReadyError(executableName, err)
		}
	} else if _, _, err := d.commandSpec(workingDir, nil); err != nil {
		return detectors.CommandNotReadyError(executableName, err)
	}
	return detectors.JavaReady(ctx)
}

// Applicable returns true when the project looks like a Gradle build.
func (d Detector) Applicable(ctx context.Context, req sdk.DetectionRequest) (bool, error) {
	_ = ctx

	workingDir := d.WorkingDir
	if workingDir == "" {
		workingDir = req.ProjectPath
	}

	for _, candidate := range []string{"build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"} {
		exists, err := system.FileExists(filepath.Join(workingDir, candidate))
		if err != nil {
			return false, err
		}
		if exists {
			return true, nil
		}
	}

	return false, nil
}

// Descriptor describes the Gradle graph detector.
func (d Detector) Descriptor() sdk.DetectorDescriptor {
	return sdk.DetectorDescriptor{
		IgnoredDirectories:   []string{"build"},
		Name:                 detectors.NameGradle,
		Technique:            sdk.BuildToolTechnique,
		SupportedEcosystems:  []sdk.Ecosystem{sdk.EcosystemMaven},
		SupportedManagers:    []sdk.PackageManager{sdk.PackageManagerGradle},
		Tags:                 []string{"graph-resolution", "component-targeting"},
		SupportsInstallFirst: true,
	}
}

// ResolveGraph resolves a Gradle dependency graph for the scan engine. For a
// multi-project build (settings script with includes), each subproject seen
// in the dependency report becomes its own manifest entry, mirroring the
// maven reactor split; single-project builds keep one entry.
func (d Detector) ResolveGraph(ctx context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	// Prefer the request-scoped logger (bound to this subproject) so
	// concurrent per-subproject resolution stays attributable in logs.
	d.Logger = req.DetectorLogger(d.Logger)
	logger := d.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	parsed, err := d.resolveGraph(ctx, req.Stderr, req.ProjectPath, req.Verbose, req.ScopeFilter)
	if err != nil {
		return sdk.DetectionResult{}, err
	}

	workingDir := d.WorkingDir
	if workingDir == "" {
		workingDir = req.ProjectPath
	}

	rootManifest := detectors.InferManifestMetadata(req, evidencePatterns)
	if len(parsed.modules) == 0 {
		AttachGradlePositions(parsed.graph, workingDir)
		return sdk.DetectionResult{
			Graphs: sdk.SingleGraphContainer(parsed.graph, rootManifest),
		}, nil
	}

	entries, err := subprojectGraphEntries(parsed, rootManifest, workingDir)
	if err != nil {
		logger.Warn("gradle subproject split failed; emitting a single manifest", zap.Error(err))
		AttachGradlePositions(parsed.graph, workingDir)
		return sdk.DetectionResult{
			Graphs: sdk.SingleGraphContainer(parsed.graph, rootManifest),
		}, nil
	}
	logger.Info("gradle detector resolved subprojects", zap.Int("subprojects", len(parsed.modules)))
	return sdk.DetectionResult{
		Graphs: &sdk.GraphContainer{Entries: entries},
	}, nil
}

// subprojectGraphEntries splits the merged multi-project graph into a root
// entry (the root project node and its own subtree) plus one entry per
// subproject seen in the dependency report, each rooted at the subproject's
// synthesized application node.
func subprojectGraphEntries(parsed gradleParseResult, rootManifest sdk.ManifestMetadata, workingDir string) ([]sdk.GraphEntry, error) {
	rootGraph, err := detectors.SubgraphFrom(parsed.graph, parsed.rootID)
	if err != nil {
		return nil, fmt.Errorf("extract root project subgraph: %w", err)
	}
	AttachGradlePositions(rootGraph, workingDir)
	entries := []sdk.GraphEntry{{Graph: rootGraph, Manifest: rootManifest}}

	for _, moduleRoot := range parsed.modules {
		moduleGraph, err := detectors.SubgraphFrom(parsed.graph, moduleRoot.rootID)
		if err != nil {
			return nil, fmt.Errorf("extract subgraph for %s: %w", moduleRoot.module.ProjectPath, err)
		}
		AttachGradlePositions(moduleGraph, filepath.Join(workingDir, filepath.FromSlash(moduleRoot.module.Dir)))
		entries = append(entries, sdk.GraphEntry{
			Graph:    moduleGraph,
			Manifest: sdk.ManifestMetadata{Path: moduleRoot.module.Dir + "/" + moduleRoot.module.ManifestFile, Kind: sdk.ManifestKind(moduleRoot.module.ManifestFile)},
		})
	}
	return entries, nil
}

// FallbackDetector returns the configured fallback detector.
func (d Detector) FallbackDetector() sdk.Detector {
	return d.Fallback
}

func (d Detector) resolveGraph(ctx context.Context, stderr io.Writer, projectPath string, verbose bool, scopeFilter sdk.Scope) (gradleParseResult, error) {
	logger := d.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	workingDir := d.WorkingDir
	if workingDir == "" {
		workingDir = projectPath
	}

	modules, walkErr := walkGradleSettingsModules(workingDir)
	if walkErr != nil {
		logger.Warn("gradle settings module walk failed; resolving the root project only", zap.Error(walkErr))
		modules = nil
	}
	if len(modules) > 0 {
		logger.Debug("gradle settings declared subprojects", zap.Int("count", len(modules)))
	}

	executable, args, err := d.commandSpec(workingDir, dependencyReportTasks(modules))
	if err != nil {
		return gradleParseResult{}, fmt.Errorf("resolve gradle command: %w", err)
	}

	if scopedArgs := gradleScopedDependenciesArgs(args, scopeFilter); len(scopedArgs) > 0 {
		parsed, err := d.runDependencies(ctx, stderr, workingDir, verbose, executable, scopedArgs, modules)
		if err == nil {
			return parsed, nil
		}
		logger.Debug("gradle scoped dependencies detector failed; retrying full graph",
			zap.String("working_dir", workingDir),
			zap.String("executable", executable),
			zap.Strings("args", scopedArgs),
			zap.Error(err),
		)
	}

	parsed, err := d.runDependencies(ctx, stderr, workingDir, verbose, executable, args, modules)
	if err == nil || len(modules) == 0 {
		return parsed, err
	}
	// A settings parse can name subprojects the build no longer has (or a
	// composite/scripted layout the regex walk misread), failing the whole
	// multi-task invocation. Degrade to the root-only report.
	logger.Warn("gradle multi-project dependency report failed; retrying the root project only", zap.Error(err))
	executable, args, cmdErr := d.commandSpec(workingDir, nil)
	if cmdErr != nil {
		return gradleParseResult{}, fmt.Errorf("resolve gradle command: %w", cmdErr)
	}
	return d.runDependencies(ctx, stderr, workingDir, verbose, executable, args, nil)
}

// dependencyReportTasks builds the task list for one gradle invocation that
// covers every subproject: the root `dependencies` task plus a
// `:<project>:dependencies` task path per settings-declared subproject.
func dependencyReportTasks(modules []gradleModule) []string {
	tasks := []string{"dependencies"}
	for _, module := range modules {
		tasks = append(tasks, module.ProjectPath+":dependencies")
	}
	return tasks
}

func (d Detector) runDependencies(ctx context.Context, stderr io.Writer, workingDir string, verbose bool, executable string, args []string, modules []gradleModule) (gradleParseResult, error) {
	logger := d.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	cmd := system.CommandContext(ctx, executable, args...)
	cmd.Dir = workingDir
	commandStderr := logging.NewCommandStderr(stderr, verbose)
	cmd.Stderr = commandStderr

	var gradleOut bytes.Buffer
	cmd.Stdout = &gradleOut

	started := time.Now()
	logger.Debug("running gradle dependencies detector", zap.String("working_dir", workingDir), zap.String("executable", executable), zap.Strings("args", args))
	if err := cmd.Run(); err != nil {
		logger.Warn(fmt.Sprintf("Gradle dependencies detector failed: %v", err))
		fields := []zap.Field{zap.Error(err)}
		if commandStderr.String() != "" {
			fields = append(fields, zap.String("stderr", commandStderr.String()))
		}
		logger.Debug("gradle dependencies detector failure details", fields...)
		return gradleParseResult{}, fmt.Errorf("run gradle dependencies: %w", err)
	}

	parsed, err := depGraphFromGradleOutput(gradleOut.Bytes(), gradleRootName(workingDir), modules)
	if err != nil {
		logger.Warn(fmt.Sprintf("Failed to map Gradle output to a dependency graph: %v", err))
		logger.Debug("gradle output mapping failed", zap.Error(err))
		return gradleParseResult{}, err
	}
	duration := time.Since(started)
	logger.Info(fmt.Sprintf("Gradle dependencies detector found %d dependencies in %s", parsed.graph.Size(), logging.FormatDuration(duration)))

	return parsed, nil
}

func gradleScopedDependenciesArgs(baseArgs []string, scopeFilter sdk.Scope) []string {
	configuration := ""
	switch scopeFilter {
	case sdk.ScopeRuntime:
		configuration = "runtimeClasspath"
	case sdk.ScopeDevelopment:
		configuration = "testRuntimeClasspath"
	default:
		return nil
	}
	args := append([]string(nil), baseArgs...)
	return append(args, "--configuration", configuration)
}

// commandSpec resolves the gradle executable (wrapper preferred) and the
// argument list for the given tasks; nil tasks default to the root
// `dependencies` report.
func (d Detector) commandSpec(workingDir string, tasks []string) (string, []string, error) {
	if len(tasks) == 0 {
		tasks = []string{"dependencies"}
	}
	args := append(append([]string(nil), tasks...), "--console=plain")
	if wrapperPath, ok := gradleWrapperPath(workingDir); ok {
		if runtime.GOOS == "windows" && isBatchFile(wrapperPath) {
			return "cmd", append([]string{"/c", wrapperPath}, args...), nil
		}
		if err := ensureExecutableGradleWrapper(wrapperPath); err != nil {
			return "", nil, err
		}
		return wrapperPath, args, nil
	}

	gradlePath, err := system.LookPath("gradle")
	if err != nil {
		return "", nil, err
	}
	return gradlePath, args, nil
}

func gradleWrapperPath(workingDir string) (string, bool) {
	if workingDir == "" {
		return "", false
	}

	for _, candidate := range wrapperCandidates() {
		path := filepath.Join(workingDir, candidate)
		exists, err := system.FileExists(path)
		if err == nil && exists {
			return path, true
		}
	}

	return "", false
}

func wrapperCandidates() []string {
	if runtime.GOOS == "windows" {
		return []string{"gradlew.bat", "gradlew.cmd", "gradlew.exe", "gradlew"}
	}
	return []string{"gradlew"}
}

func isBatchFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".bat" || ext == ".cmd"
}

func ensureExecutableGradleWrapper(path string) error {
	if runtime.GOOS == "windows" || isBatchFile(path) {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat gradle wrapper: %w", err)
	}
	mode := info.Mode()
	if mode&0o111 != 0 {
		return nil
	}
	if err := os.Chmod(path, mode|0o755); err != nil {
		return fmt.Errorf("chmod gradle wrapper executable: %w", err)
	}
	return nil
}

// gradleParseResult is the outcome of mapping a gradle dependency report:
// the merged graph, the root project's node ID, and — for multi-project
// builds — every settings-declared subproject actually seen in the report
// (via its `Project ':x'` banner or a `project :x` dependency token), each
// with its synthesized root node ID.
type gradleParseResult struct {
	graph   *sdk.Graph
	rootID  string
	modules []gradleModuleRoot
}

type gradleModuleRoot struct {
	module gradleModule
	rootID string
}

var (
	gradleRootProjectBanner = regexp.MustCompile(`^Root project '([^']+)'`)
	gradleSubprojectBanner  = regexp.MustCompile(`^Project '([^']+)'`)
)

func depGraphFromGradleOutput(raw []byte, rootName string, modules []gradleModule) (gradleParseResult, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return gradleParseResult{}, errors.New("gradle dependencies output is empty")
	}

	if rootName == "" {
		rootName = "root"
	}

	depsGraph := sdk.New()
	rootNode := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemMaven,
		Name:           rootName,
		PackageManager: sdk.PackageManagerGradle},
	})

	if err := depsGraph.AddNode(rootNode); err != nil {
		return gradleParseResult{}, fmt.Errorf("add root node: %w", err)
	}

	moduleByPath := make(map[string]gradleModule, len(modules))
	for _, module := range modules {
		moduleByPath[module.ProjectPath] = module
	}
	roots := &gradleModuleRoots{graph: depsGraph, byPath: moduleByPath}

	stack := []string{rootNode.ID}
	currentScope := sdk.ScopeUnknown
	for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		// Per-project banners in a multi-project report switch which root the
		// following configuration sections attach to.
		if gradleRootProjectBanner.MatchString(trimmed) {
			stack = []string{rootNode.ID}
			currentScope = sdk.ScopeUnknown
			continue
		}
		if match := gradleSubprojectBanner.FindStringSubmatch(trimmed); match != nil {
			if moduleRootID, err := roots.ensure(match[1]); err != nil {
				return gradleParseResult{}, err
			} else if moduleRootID != "" {
				stack = []string{moduleRootID}
				currentScope = sdk.ScopeUnknown
			}
			continue
		}
		if isGradleConfigurationHeader(trimmed) {
			stack = stack[:1]
			currentScope = scopeFromGradleConfiguration(trimmed)
			continue
		}

		token, depth, ok := gradleDependencyLineToken(line)
		if !ok {
			continue
		}
		if depth+1 > len(stack) {
			continue
		}
		// `project :x` tokens (colon-less in declared-only listings) become
		// edges to the subproject's own root node when the settings walk
		// knows the project, so inter-module dependencies stay real edges
		// instead of placeholder leaves.
		if projectPath, isProject := gradleProjectRef(token); isProject {
			if moduleRootID, err := roots.ensure(projectPath); err != nil {
				return gradleParseResult{}, err
			} else if moduleRootID != "" {
				stack = stack[:depth+1]
				if err := depsGraph.AddEdge(stack[len(stack)-1], moduleRootID); err != nil {
					return gradleParseResult{}, fmt.Errorf("add dependency %q -> %q: %w", stack[len(stack)-1], moduleRootID, err)
				}
				stack = append(stack, moduleRootID)
				continue
			}
		}

		node, ok := gradleNodeFromToken(token, currentScope)
		if !ok {
			continue
		}
		stack = stack[:depth+1]
		parentID := stack[len(stack)-1]
		if existing, ok := depsGraph.Node(node.ID); ok {
			existing.AddScope(node.PrimaryScope())
		} else if err := depsGraph.AddNode(node); err != nil && !errors.Is(err, sdk.ErrNodeAlreadyExist) {
			return gradleParseResult{}, fmt.Errorf("add node %q: %w", node.ID, err)
		}
		if err := depsGraph.AddEdge(parentID, node.ID); err != nil {
			return gradleParseResult{}, fmt.Errorf("add dependency %q -> %q: %w", parentID, node.ID, err)
		}

		stack = append(stack, node.ID)
	}

	return gradleParseResult{graph: depsGraph, rootID: rootNode.ID, modules: roots.seen}, nil
}

// gradleModuleRoots lazily synthesizes one application-typed root node per
// subproject the report actually mentions, so settings entries that never
// appear in the output add no orphan nodes.
type gradleModuleRoots struct {
	graph  *sdk.Graph
	byPath map[string]gradleModule
	seen   []gradleModuleRoot
	ids    map[string]string
}

// ensure returns the root node ID for a gradle project path, creating the
// node on first sight. Unknown project paths (not declared in settings, e.g.
// composite builds) return "" so the caller falls back to a placeholder node.
func (r *gradleModuleRoots) ensure(projectPath string) (string, error) {
	module, ok := r.byPath[projectPath]
	if !ok {
		return "", nil
	}
	if id, ok := r.ids[projectPath]; ok {
		return id, nil
	}
	node := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{
		Ecosystem:      sdk.EcosystemMaven,
		Org:            module.Group,
		Name:           module.Name,
		PackageManager: sdk.PackageManagerGradle,
		// Subprojects are the build's own applications: enrichment skips
		// them and views treat their direct dependencies as top-level.
		Type:       sdk.PackageTypeApplication,
		FirstParty: true,
	}})
	if err := r.graph.AddNode(node); err != nil && !errors.Is(err, sdk.ErrNodeAlreadyExist) {
		return "", fmt.Errorf("add subproject root %q: %w", module.ProjectPath, err)
	}
	if r.ids == nil {
		r.ids = map[string]string{}
	}
	r.ids[projectPath] = node.ID
	r.seen = append(r.seen, gradleModuleRoot{module: module, rootID: node.ID})
	return node.ID, nil
}

// gradleProjectRef reports whether a dependency token is an inter-project
// reference and returns its normalized gradle project path. Resolved listings
// print `project :app`; declared-only listings (the `(n)` entries) print
// `project app` without the leading colon.
func gradleProjectRef(token string) (string, bool) {
	if !strings.HasPrefix(token, "project ") {
		return "", false
	}
	path := strings.TrimSpace(strings.TrimPrefix(token, "project "))
	if path == "" {
		return "", false
	}
	if !strings.HasPrefix(path, ":") {
		path = ":" + path
	}
	return path, true
}

var gradleRootProjectNamePattern = regexp.MustCompile(`(?m)\brootProject\.name\s*=\s*["']([^"']+)["']`)

func gradleRootName(workingDir string) string {
	for _, name := range []string{"settings.gradle", "settings.gradle.kts"} {
		raw, err := os.ReadFile(filepath.Join(workingDir, name))
		if err != nil {
			continue
		}
		matches := gradleRootProjectNamePattern.FindSubmatch(raw)
		if len(matches) == 2 {
			if value := strings.TrimSpace(string(matches[1])); value != "" {
				return value
			}
		}
	}
	return filepath.Base(workingDir)
}

func isGradleConfigurationHeader(line string) bool {
	if strings.HasPrefix(line, "Root project") || strings.HasPrefix(line, "Project '") {
		return false
	}
	if strings.Contains(line, " - ") {
		return true
	}
	return strings.HasSuffix(line, "Classpath")
}

// gradleDependencyLineToken extracts the dependency token and tree depth from
// one report line (`|    +--- group:artifact:version`).
func gradleDependencyLineToken(line string) (string, int, bool) {
	idx := strings.Index(line, "+--- ")
	if idx < 0 {
		idx = strings.Index(line, "\\--- ")
	}
	if idx < 0 {
		return "", 0, false
	}

	depth := gradleTreeDepth(line[:idx])
	token := gradleDependencyToken(strings.TrimSpace(line[idx+5:]))
	if token == "" {
		return "", 0, false
	}
	return token, depth, true
}

func gradleTreeDepth(prefix string) int {
	depth := 0
	for len(prefix) >= 5 {
		segment := prefix[:5]
		if segment != "|    " && segment != "     " {
			break
		}
		depth++
		prefix = prefix[5:]
	}
	return depth
}

func gradleDependencyToken(value string) string {
	if strings.HasPrefix(value, "project ") {
		if idx := strings.Index(value, " ("); idx >= 0 {
			value = value[:idx]
		}
		return strings.TrimSpace(value)
	}

	fields := strings.Fields(value)
	if len(fields) == 0 {
		return ""
	}

	token := fields[0]
	if len(fields) >= 3 && fields[1] == "->" {
		if idx := strings.LastIndex(token, ":"); idx >= 0 {
			return token[:idx+1] + fields[2]
		}
	}

	return token
}

func gradleNodeFromToken(token string, scope sdk.Scope) (*sdk.Dependency, bool) {
	if strings.HasPrefix(token, "project ") {
		name := strings.TrimSpace(strings.TrimPrefix(token, "project "))
		if name == "" {
			return nil, false
		}
		return sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemMaven,
				Name: name,

				PackageManager: sdk.PackageManagerGradle}, Scopes: sdk.ScopesOf(scope),
			}),

			true
	}

	parts := strings.Split(token, ":")
	if len(parts) < 3 {
		return nil, false
	}

	version := parts[len(parts)-1]
	name := strings.Join(parts[1:len(parts)-1], ":")
	return sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemMaven,
			Name:    name,
			Version: version,

			Org:            parts[0],
			PackageManager: sdk.PackageManagerGradle}, Scopes: sdk.ScopesOf(scope),
		}),

		true
}

func scopeFromGradleConfiguration(value string) sdk.Scope {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch {
	case strings.Contains(normalized, "test"):
		return sdk.ScopeDevelopment
	case strings.Contains(normalized, "runtime"),
		strings.Contains(normalized, "compile"),
		strings.Contains(normalized, "implementation"),
		strings.Contains(normalized, "api"),
		strings.Contains(normalized, "classpath"),
		strings.Contains(normalized, "annotationprocessor"):
		return sdk.ScopeRuntime
	default:
		return sdk.ScopeUnknown
	}
}

// Install prepares Gradle dependencies before graph resolution.
func (d Detector) Install(ctx context.Context, req sdk.DetectionRequest) error {
	logger := d.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	workingDir := d.WorkingDir
	if workingDir == "" {
		workingDir = req.ProjectPath
	}
	executable, args, err := d.commandSpec(workingDir, nil)
	if err != nil {
		return fmt.Errorf("resolve gradle command: %w", err)
	}
	args = append(args, req.InstallArgs...)
	cmd := system.CommandContext(ctx, executable, args...)
	cmd.Dir = workingDir
	commandStderr := logging.NewCommandStderr(req.Stderr, req.Verbose)
	cmd.Stderr = commandStderr
	started := time.Now()
	logger.Info("Gradle detector running install-first step")
	logger.Debug("running gradle detector install-first", zap.String("working_dir", workingDir), zap.String("executable", executable), zap.Strings("args", args))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("run gradle install step: %w", err)
	}
	logger.Info(fmt.Sprintf("Gradle detector install-first completed in %s", logging.FormatDuration(time.Since(started))))
	return nil
}
