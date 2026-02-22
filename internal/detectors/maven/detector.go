package maven

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode"

	"github.com/bomly/bomly-cli/internal/detectors"
	"github.com/bomly/bomly-cli/internal/logging"
	"github.com/bomly/bomly-cli/internal/model"
	"github.com/bomly/bomly-cli/internal/system"
	"go.uber.org/zap"
)

var execLookPath = system.LookPath

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
	Fallback   detectors.Detector
}

// Ready reports whether a Maven wrapper is present or Maven is installed.
func (d Detector) Ready() bool {
	if d.WorkingDir == "" {
		return true
	}
	_, _, err := d.resolveRunner()
	return err == nil
}

// Applicable reports whether the project looks like a Maven project.
func (d Detector) Applicable(ctx context.Context, req detectors.ResolveGraphRequest) (bool, error) {
	_ = ctx

	workingDir := d.WorkingDir
	if workingDir == "" {
		workingDir = req.ProjectPath
	}

	pomPath := filepath.Join(workingDir, "pom.xml")
	return system.FileExists(pomPath)
}

// Descriptor describes the Maven graph detector.
func (d Detector) Descriptor() detectors.DetectorDescriptor {
	return detectors.DetectorDescriptor{
		Name:                "maven-detector",
		ImplementationType:  detectors.NativeDetector,
		SupportedEcosystems: []detectors.Ecosystem{detectors.EcosystemMaven},
		SupportedManagers:   []detectors.PackageManager{detectors.PackageManagerMaven},
		SupportedModes:      []detectors.TargetMode{detectors.TargetModeFullGraph, detectors.TargetModeComponent},
		Capabilities:        []string{"graph-resolution", "component-targeting", "wrapper-detection"},
	}
}

// ResolveGraph resolves a Maven dependency graph for the scan engine.
func (d Detector) ResolveGraph(_ context.Context, req detectors.ResolveGraphRequest) (detectors.ResolveGraphResult, error) {
	depsGraph, err := d.resolveGraph(req.Stderr, req.ProjectPath, req.Verbose)
	if err != nil {
		return detectors.ResolveGraphResult{}, err
	}

	return detectors.ResolveGraphResult{
		Graphs: detectors.SingleGraphContainer(depsGraph, detectors.InferManifestMetadata(req)),
	}, nil
}

// FallbackDetector returns the configured fallback detector.
func (d Detector) FallbackDetector() detectors.Detector {
	return d.Fallback
}

func (d Detector) resolveGraph(stderr io.Writer, projectPath string, verbose bool) (*model.Graph, error) {
	logger := d.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	executable, prefixArgs, err := d.resolveRunner(projectPath)
	if err != nil {
		return nil, fmt.Errorf("resolve maven runner: %w", err)
	}

	args := append(prefixArgs, "dependency:tree", "-DoutputType=tgf")
	cmd := system.Command(executable, args...)
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
		logger.Error(fmt.Sprintf("Maven dependencies detector failed: %v", err))
		fields := []zap.Field{zap.Error(err)}
		if commandStderr.String() != "" {
			fields = append(fields, zap.String("stderr", commandStderr.String()))
		}
		logger.Debug("maven dependencies detector failure details", fields...)
		return nil, fmt.Errorf("run maven dependency tree: %w", err)
	}

	depsGraph, err := depGraphFromMavenTGF(raw)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to map Maven output to a dependency graph: %v", err))
		logger.Debug("maven output mapping failed", zap.Error(err))
		return nil, err
	}
	duration := time.Since(started)
	logger.Info(fmt.Sprintf("Maven dependencies detector found %d dependencies in %s", depsGraph.Size(), logging.FormatDuration(duration)))
	return depsGraph, nil
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
	return path, nil, nil
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

func depGraphFromMavenTGF(raw []byte) (*model.Graph, error) {
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	inEdges := false

	tgfPackages := make(map[string]*model.Package)
	tgfGraph := model.New()
	type edge struct {
		from string
		to   string
	}
	relationships := make([]edge, 0, 16)

	for scanner.Scan() {
		line, ok := normalizeMavenTGFLine(scanner.Text())
		if !ok {
			continue
		}
		if line == "#" {
			inEdges = true
			continue
		}

		if !inEdges {
			if !looksLikeTGFNodeLine(line) {
				continue
			}
			id, node, err := parseTGFNodeLine(line)
			if err != nil {
				return nil, err
			}
			tgfPackages[id] = node
			if existing, ok := tgfGraph.Package(node.ID); ok {
				detectors.MergePackageScope(existing, detectors.Scope(node.Scope))
			} else if err := tgfGraph.AddPackage(node); err != nil && !errors.Is(err, model.ErrPackageAlreadyExist) {
				return nil, fmt.Errorf("add maven package %q: %w", node.ID, err)
			}
			continue
		}

		if !looksLikeTGFEdgeLine(line) {
			continue
		}
		fields := strings.Fields(line)
		relationships = append(relationships, edge{from: fields[0], to: fields[1]})
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
		if err := tgfGraph.AddDependency(fromNode.ID, toNode.ID); err != nil {
			return nil, fmt.Errorf("add maven dependency %q -> %q: %w", fromNode.ID, toNode.ID, err)
		}
	}

	return tgfGraph, nil
}

func normalizeMavenTGFLine(line string) (string, bool) {
	trimmed := strings.TrimSpace(line)
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

func parseTGFNodeLine(line string) (string, *model.Package, error) {
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

func nodeFromMavenCoords(coords string) (*model.Package, error) {
	parts := strings.Split(coords, ":")
	if len(parts) < 4 {
		return nil, fmt.Errorf("parse maven coordinates %q: expected at least 4 segments", coords)
	}

	groupID := parts[0]
	artifactID := parts[1]
	versionIndex := len(parts) - 1
	scope := detectors.ScopeUnknown
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

	return model.NewPackage(model.Package{
		Ecosystem:   string(detectors.EcosystemMaven),
		Name:        name,
		Version:     parts[versionIndex],
		Scope:       string(scope),
		Org:         groupID,
		BuildSystem: detectors.PackageManagerMaven.Name(),
	}), nil
}

func scopeFromMavenScope(value string) detectors.Scope {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "test":
		return detectors.ScopeDevelopment
	case "compile", "provided", "runtime", "system", "import":
		return detectors.ScopeRuntime
	default:
		return detectors.ScopeUnknown
	}
}

// Install prepares Maven dependencies before graph resolution.
func (d Detector) Install(_ context.Context, req detectors.ResolveGraphRequest) error {
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
	cmd := system.Command(executable, args...)
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
