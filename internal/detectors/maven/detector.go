package maven

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/logging"
	"github.com/bomly-dev/bomly-cli/internal/system"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

var execLookPath = system.LookPath

// maxTGFTokenSize caps the per-line buffer the TGF scanner will grow to. It is
// far above any realistic single line of `mvn dependency:tree` TGF output while
// still bounding memory use on pathological input.
const maxTGFTokenSize = 10 << 20 // 10 MiB

var mavenScopes = map[string]struct{}{
	"compile":  {},
	"provided": {},
	"runtime":  {},
	"system":   {},
	"test":     {},
	"import":   {},
}

// Detector resolves dependency graphs by invoking a Maven wrapper or Maven itself.
type Detector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   sdk.Detector
}

var evidencePatterns = []string{"pom.xml", "*pom.xml"}

// PackageManagerSupport returns Maven package-manager discovery metadata.
func (d Detector) PackageManagerSupport() []sdk.PackageManagerSupport {
	return []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerMaven, evidencePatterns...).WithMultiModule()}
}

// Ready reports whether a Maven wrapper is present or Maven is installed and a
// usable Java runtime is available for the request's working directory.
func (d Detector) Ready(ctx context.Context, req sdk.DetectionRequest) error {
	if _, _, err := d.resolveRunner(detectors.RequestWorkingDir(req)); err != nil {
		return detectors.CommandNotReadyError("mvn", err)
	}
	return detectors.JavaReady(ctx)
}

// Applicable reports whether the project looks like a Maven project.
func (d Detector) Applicable(ctx context.Context, req sdk.DetectionRequest) (bool, error) {
	_ = ctx

	workingDir := d.WorkingDir
	if workingDir == "" {
		workingDir = req.ProjectPath
	}

	pomPath := filepath.Join(workingDir, "pom.xml")
	return system.FileExists(pomPath)
}

// Descriptor describes the Maven graph detector.
func (d Detector) Descriptor() sdk.DetectorDescriptor {
	return sdk.DetectorDescriptor{
		IgnoredDirectories:   []string{"target"},
		Name:                 detectors.NameMaven,
		Technique:            sdk.BuildToolTechnique,
		SupportedEcosystems:  []sdk.Ecosystem{sdk.EcosystemMaven},
		SupportedManagers:    []sdk.PackageManager{sdk.PackageManagerMaven},
		Tags:                 []string{"graph-resolution", "component-targeting", "wrapper-detection"},
		SupportsInstallFirst: true,
	}
}

// ResolveGraph resolves a Maven dependency graph for the scan engine. A
// multi-module reactor yields one manifest entry per module (the module's
// pom.xml plus its reachable dependency subtree) alongside the root entry;
// single-module projects keep exactly one entry.
func (d Detector) ResolveGraph(ctx context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	// Prefer the request-scoped logger (bound to this subproject) so
	// concurrent per-subproject resolution stays attributable in logs.
	d.Logger = req.DetectorLogger(d.Logger)
	logger := d.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	depsGraph, err := d.resolveGraph(ctx, req.Stderr, req.ProjectPath, req.Verbose, req.ScopeFilter)
	if err != nil {
		return sdk.DetectionResult{}, err
	}

	workingDir := d.WorkingDir
	if workingDir == "" {
		workingDir = req.ProjectPath
	}
	AttachPomPositions(depsGraph, workingDir)

	rootManifest := detectors.InferManifestMetadata(req, evidencePatterns)
	modules, err := walkPomModules(workingDir)
	if err != nil || len(modules) == 0 {
		if err != nil {
			logger.Warn("maven module walk failed; emitting a single reactor manifest", zap.Error(err))
		}
		return sdk.DetectionResult{
			Graphs: sdk.SingleGraphContainer(depsGraph, rootManifest),
		}, nil
	}

	entries, matched := d.reactorGraphEntries(depsGraph, modules, rootManifest, workingDir)
	if matched == 0 {
		// No TGF root matched a pom-declared module (e.g. the reactor was
		// resolved for a subset); keep the merged single entry.
		return sdk.DetectionResult{
			Graphs: sdk.SingleGraphContainer(depsGraph, rootManifest),
		}, nil
	}
	logger.Info("maven detector resolved reactor modules", zap.Int("modules", matched))
	return sdk.DetectionResult{
		Graphs: &sdk.GraphContainer{Entries: entries},
	}, nil
}

// reactorGraphEntries partitions a merged reactor graph into per-module
// manifest entries by matching graph roots against pom-declared module
// coordinates. Unmatched graph roots (including the aggregator root pom's own
// node) stay in the root entry, so blocks that cannot be mapped to a module
// directory are never dropped.
func (d Detector) reactorGraphEntries(depsGraph *sdk.Graph, modules []mavenModule, rootManifest sdk.ManifestMetadata, workingDir string) ([]sdk.GraphEntry, int) {
	moduleByKey := make(map[string]mavenModule, len(modules))
	for _, module := range modules {
		moduleByKey[module.moduleKey()] = module
	}

	type moduleEntry struct {
		module mavenModule
		rootID string
	}
	// Match module coordinates against every node, not only graph roots: a
	// module consumed by a sibling (web -> core) has inbound edges and is no
	// longer a root, yet still needs its own manifest entry.
	matchedModules := make([]moduleEntry, 0, len(modules))
	matchedIDs := map[string]struct{}{}
	for _, pkg := range depsGraph.Nodes() {
		if pkg == nil {
			continue
		}
		if module, ok := moduleByKey[graphNodeModuleKey(pkg)]; ok {
			if _, seen := matchedIDs[pkg.ID]; seen {
				continue
			}
			matchedIDs[pkg.ID] = struct{}{}
			// Reactor modules are the project's own applications; typing them
			// lets downstream views treat their direct dependencies as
			// top-level even when a sibling module depends on them, and the
			// first-party mark keeps enrichment from querying them.
			if pkg.Type == "" {
				pkg.Type = sdk.PackageTypeApplication
			}
			pkg.FirstParty = true
			matchedModules = append(matchedModules, moduleEntry{module: module, rootID: pkg.ID})
		}
	}
	rootIDs := make([]string, 0)
	for _, root := range depsGraph.Roots() {
		if root == nil {
			continue
		}
		if _, ok := matchedIDs[root.ID]; ok {
			continue
		}
		rootIDs = append(rootIDs, root.ID)
	}
	if len(matchedModules) == 0 {
		return nil, 0
	}
	sort.Slice(matchedModules, func(i, j int) bool { return matchedModules[i].module.Dir < matchedModules[j].module.Dir })

	entries := make([]sdk.GraphEntry, 0, len(matchedModules)+1)
	rootGraph := sdk.New()
	for _, rootID := range rootIDs {
		subgraph, err := detectors.SubgraphFrom(depsGraph, rootID)
		if err != nil {
			continue
		}
		if err := sdk.MergeGraph(rootGraph, subgraph); err != nil {
			continue
		}
	}
	if rootGraph.Size() > 0 {
		entries = append(entries, sdk.GraphEntry{Graph: rootGraph, Manifest: rootManifest})
	}
	for _, matched := range matchedModules {
		moduleGraph, err := detectors.SubgraphFrom(depsGraph, matched.rootID)
		if err != nil {
			continue
		}
		AttachPomPositions(moduleGraph, filepath.Join(workingDir, filepath.FromSlash(matched.module.Dir)))
		entries = append(entries, sdk.GraphEntry{
			Graph:    moduleGraph,
			Manifest: sdk.ManifestMetadata{Path: matched.module.Dir + "/pom.xml", Kind: sdk.ManifestKind("pom.xml")},
		})
	}
	return entries, len(matchedModules)
}

// FallbackDetector returns the configured fallback detector.
func (d Detector) FallbackDetector() sdk.Detector {
	return d.Fallback
}

func (d Detector) resolveGraph(ctx context.Context, stderr io.Writer, projectPath string, verbose bool, scopeFilter sdk.Scope) (*sdk.Graph, error) {
	logger := d.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	executable, prefixArgs, err := d.resolveRunner(projectPath)
	if err != nil {
		return nil, fmt.Errorf("resolve maven runner: %w", err)
	}

	args := mavenDependencyTreeArgs(prefixArgs, scopeFilter)
	cmd := system.CommandContext(ctx, executable, args...)
	cmd.Dir = projectPath
	if d.WorkingDir != "" {
		cmd.Dir = d.WorkingDir
	}
	commandStderr := logging.NewCommandStderr(stderr, verbose)
	cmd.Stderr = commandStderr

	started := time.Now()
	logger.Debug("running maven dependencies detector", zap.String("working_dir", cmd.Dir), zap.String("executable", executable), zap.Strings("args", args))
	raw, err := cmd.Output()
	if err != nil {
		logger.Warn(fmt.Sprintf("Maven dependencies detector failed: %v", err))
		fields := []zap.Field{zap.Error(err)}
		if commandStderr.String() != "" {
			fields = append(fields, zap.String("stderr", commandStderr.String()))
		}
		logger.Debug("maven dependencies detector failure details", fields...)
		return nil, fmt.Errorf("run maven dependency tree: %w", err)
	}

	depsGraph, err := depGraphFromMavenTGF(raw)
	if err != nil {
		logger.Warn(fmt.Sprintf("Failed to map Maven output to a dependency graph: %v", err))
		logger.Debug("maven output mapping failed", zap.Error(err))
		return nil, err
	}
	duration := time.Since(started)
	logger.Info(fmt.Sprintf("Maven dependencies detector found %d dependencies in %s", depsGraph.Size(), logging.FormatDuration(duration)))
	return depsGraph, nil
}

func mavenDependencyTreeArgs(prefixArgs []string, scopeFilter sdk.Scope) []string {
	args := append(append([]string(nil), prefixArgs...), "-B", "dependency:tree", "-DoutputType=tgf")
	switch scopeFilter {
	case sdk.ScopeRuntime:
		args = append(args, "-Dscope=runtime")
	case sdk.ScopeDevelopment:
		args = append(args, "-Dscope=test")
	}
	return args
}

func (d Detector) resolveRunner(projectPath ...string) (string, []string, error) {
	workingDir := d.WorkingDir
	if workingDir == "" && len(projectPath) > 0 {
		workingDir = projectPath[0]
	}
	if workingDir != "" {
		wrapperPath, ok, err := findWrapper(workingDir)
		if err != nil {
			return "", nil, err
		}
		if ok {
			return wrapCommand(wrapperPath)
		}
	}

	if _, err := execLookPath("mvn"); err != nil {
		return "", nil, err
	}
	return "mvn", nil, nil
}

func wrapCommand(path string) (string, []string, error) {
	ext := strings.ToLower(filepath.Ext(path))
	if runtime.GOOS == "windows" && (ext == ".cmd" || ext == ".bat") {
		return "cmd", []string{"/c", path}, nil
	}
	if err := ensureExecutableMavenWrapper(path); err != nil {
		return "", nil, err
	}
	return path, nil, nil
}

func ensureExecutableMavenWrapper(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat maven wrapper: %w", err)
	}
	mode := info.Mode()
	if mode&0o111 != 0 {
		return nil
	}
	if err := os.Chmod(path, mode|0o755); err != nil {
		return fmt.Errorf("chmod maven wrapper executable: %w", err)
	}
	return nil
}

func findWrapper(workingDir string) (string, bool, error) {
	for _, name := range wrapperCandidates() {
		candidate := filepath.Join(workingDir, name)
		exists, err := system.FileExists(candidate)
		if err != nil {
			return "", false, err
		}
		if exists {
			return candidate, true, nil
		}
	}
	return "", false, nil
}

func wrapperCandidates() []string {
	if runtime.GOOS == "windows" {
		return []string{"mvnw.cmd", "mvnw.bat", "mvnw"}
	}
	return []string{"mvnw"}
}

func depGraphFromMavenTGF(raw []byte) (*sdk.Graph, error) {
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	// bufio.Scanner defaults to a 64KB max token size. Large multi-module
	// dependency trees (or single nodes with very long coordinate strings)
	// routinely exceed that and fail with "token too long", so raise the cap.
	scanner.Buffer(make([]byte, 0, 64*1024), maxTGFTokenSize)

	tgfPackages := make(map[string]*sdk.Dependency)
	tgfGraph := sdk.New()
	type edge struct {
		from string
		to   string
	}
	relationships := make([]edge, 0, 16)

	// `mvn dependency:tree -DoutputType=tgf` on a multi-module reactor emits
	// ONE TGF block per module (nodes, then a `#` separator, then edges),
	// all concatenated on stdout. Node ids are global object hashcodes,
	// unique across the whole reactor — verified against a real 13-module
	// reactor: zero id was reused for a different coordinate across blocks.
	// So we classify each line by its SHAPE — a node line ("<id> <coords>")
	// or an edge line ("<from> <to> <scope>") — instead of relying on a
	// single nodes→edges transition. The previous single `#` flag flipped to
	// "edges" on the first module and never reset, so every later block's
	// node lines were dropped and their edges then referenced ids that were
	// never registered ("maven tgf references unknown package"). Node and
	// edge lines are unambiguous (a node's second field is a coordinate with
	// colons; an edge's second field is a numeric id), and nodes are checked
	// first, so a shape check is safe.
	for scanner.Scan() {
		line, ok := normalizeMavenTGFLine(scanner.Text())
		if !ok {
			continue
		}
		switch {
		case line == "#":
			// Block/section separator; classification is by shape, so there
			// is nothing to track across it.
			continue
		case looksLikeTGFNodeLine(line):
			id, node, err := parseTGFNodeLine(line)
			if err != nil {
				return nil, err
			}
			tgfPackages[id] = node
			if existing, ok := tgfGraph.Node(node.ID); ok {
				existing.AddScope(node.PrimaryScope())
			} else if err := tgfGraph.AddNode(node); err != nil && !errors.Is(err, sdk.ErrNodeAlreadyExist) {
				return nil, fmt.Errorf("add maven package %q: %w", node.ID, err)
			}
		case looksLikeTGFEdgeLine(line):
			fields := strings.Fields(line)
			relationships = append(relationships, edge{from: fields[0], to: fields[1]})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan maven tgf: %w", err)
	}
	if len(tgfPackages) == 0 {
		return nil, errors.New("maven tgf contains no packages")
	}

	for _, item := range relationships {
		fromNode, ok := tgfPackages[item.from]
		if !ok {
			return nil, fmt.Errorf("maven tgf references unknown package %q", item.from)
		}
		toNode, ok := tgfPackages[item.to]
		if !ok {
			return nil, fmt.Errorf("maven tgf references unknown package %q", item.to)
		}
		if err := tgfGraph.AddEdge(fromNode.ID, toNode.ID); err != nil {
			return nil, fmt.Errorf("add maven dependency %q -> %q: %w", fromNode.ID, toNode.ID, err)
		}
	}

	return tgfGraph, nil
}

func normalizeMavenTGFLine(line string) (string, bool) {
	trimmed := strings.TrimSpace(stripMavenANSI(line))
	if trimmed == "" {
		return "", false
	}

	if strings.HasPrefix(trimmed, "[INFO]") {
		trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "[INFO]"))
		if trimmed == "" {
			return "", false
		}
	}

	return trimmed, true
}

func stripMavenANSI(value string) string {
	var out strings.Builder
	inEscape := false
	for idx := 0; idx < len(value); idx++ {
		ch := value[idx]
		if inEscape {
			if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') {
				inEscape = false
			}
			continue
		}
		if ch == 0x1b && idx+1 < len(value) && value[idx+1] == '[' {
			inEscape = true
			idx++
			continue
		}
		out.WriteByte(ch)
	}
	return out.String()
}

func looksLikeTGFNodeLine(line string) bool {
	fields := strings.Fields(line)
	if len(fields) < 2 || !isTGFIdentifier(fields[0]) {
		return false
	}
	return looksLikeMavenCoords(fields[1])
}

func looksLikeTGFEdgeLine(line string) bool {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return false
	}
	return isTGFIdentifier(fields[0]) && isTGFIdentifier(fields[1])
}

func isTGFIdentifier(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func looksLikeMavenCoords(coords string) bool {
	return strings.Count(coords, ":") >= 3
}

func parseTGFNodeLine(line string) (string, *sdk.Dependency, error) {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return "", nil, fmt.Errorf("parse maven tgf package %q: expected identifier and coordinates", line)
	}

	node, err := nodeFromMavenCoords(parts[1])
	if err != nil {
		return "", nil, err
	}
	return parts[0], node, nil
}

func nodeFromMavenCoords(coords string) (*sdk.Dependency, error) {
	parts := strings.Split(coords, ":")
	if len(parts) < 4 {
		return nil, fmt.Errorf("parse maven coordinates %q: expected at least 4 segments", coords)
	}

	groupID := parts[0]
	artifactID := parts[1]
	versionIndex := len(parts) - 1
	scope := sdk.ScopeUnknown
	if _, ok := mavenScopes[parts[versionIndex]]; ok {
		scope = scopeFromMavenScope(parts[versionIndex])
		versionIndex--
	}
	if versionIndex < 3 {
		return nil, fmt.Errorf("parse maven coordinates %q: missing version", coords)
	}

	name := artifactID
	if versionIndex == 4 {
		classifier := parts[3]
		if classifier != "" {
			name += ":" + classifier
		}
	}

	return sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemMaven,
		Name:    name,
		Version: parts[versionIndex],

		Org:            groupID,
		PackageManager: sdk.PackageManagerMaven}, Scopes: sdk.ScopesOf(scope),
	}), nil
}

func scopeFromMavenScope(value string) sdk.Scope {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "test":
		return sdk.ScopeDevelopment
	case "compile", "provided", "runtime", "system", "import":
		return sdk.ScopeRuntime
	default:
		return sdk.ScopeUnknown
	}
}

// Install prepares Maven dependencies before graph resolution.
func (d Detector) Install(ctx context.Context, req sdk.DetectionRequest) error {
	logger := d.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	executable, prefixArgs, err := d.resolveRunner(req.ProjectPath)
	if err != nil {
		return fmt.Errorf("resolve maven runner: %w", err)
	}
	args := append(prefixArgs, "dependency:resolve")
	args = append(args, req.InstallArgs...)
	cmd := system.CommandContext(ctx, executable, args...)
	cmd.Dir = req.ProjectPath
	if d.WorkingDir != "" {
		cmd.Dir = d.WorkingDir
	}
	commandStderr := logging.NewCommandStderr(req.Stderr, req.Verbose)
	cmd.Stderr = commandStderr
	started := time.Now()
	logger.Info("Maven detector running install-first step")
	logger.Debug("running maven detector install-first", zap.String("working_dir", cmd.Dir), zap.String("executable", executable), zap.Strings("args", args))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("run maven dependency resolve: %w", err)
	}
	logger.Info(fmt.Sprintf("Maven detector install-first completed in %s", logging.FormatDuration(time.Since(started))))
	return nil
}
