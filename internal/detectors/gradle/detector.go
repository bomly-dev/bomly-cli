package gradle

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/bomly/bomly-cli/internal/detectors"
	"github.com/bomly/bomly-cli/internal/logging"
	"github.com/bomly/bomly-cli/internal/model"
	"github.com/bomly/bomly-cli/internal/system"
	"go.uber.org/zap"
)

// Detector resolves Gradle dependency graphs using the Gradle wrapper when present,
// or a globally installed Gradle binary otherwise.
type Detector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   detectors.Detector
}

// Ready returns true if a Gradle wrapper is present for the project or gradle is on PATH.
func (d Detector) Ready() bool {
	if d.WorkingDir == "" {
		return true
	}
	_, _, err := d.commandSpec(d.WorkingDir)
	return err == nil
}

// Applicable returns true when the project looks like a Gradle build.
func (d Detector) Applicable(ctx context.Context, req detectors.ResolveGraphRequest) (bool, error) {
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
func (d Detector) Descriptor() detectors.DetectorDescriptor {
	return detectors.DetectorDescriptor{
		Name:                "gradle-detector",
		ImplementationType:  detectors.NativeDetector,
		SupportedEcosystems: []detectors.Ecosystem{detectors.EcosystemMaven},
		SupportedManagers:   []detectors.PackageManager{detectors.PackageManagerGradle},
		SupportedModes:      []detectors.TargetMode{detectors.TargetModeFullGraph, detectors.TargetModeComponent},
		Capabilities:        []string{"graph-resolution", "component-targeting"},
	}
}

// ResolveGraph resolves a Gradle dependency graph for the scan engine.
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

	workingDir := d.WorkingDir
	if workingDir == "" {
		workingDir = projectPath
	}

	executable, args, err := d.commandSpec(workingDir)
	if err != nil {
		return nil, fmt.Errorf("resolve gradle command: %w", err)
	}

	cmd := system.Command(executable, args...)
	cmd.Dir = workingDir
	commandStderr := logging.NewCommandStderr(stderr, verbose)
	cmd.Stderr = commandStderr

	var gradleOut bytes.Buffer
	cmd.Stdout = &gradleOut

	started := time.Now()
	logger.Debug("running gradle dependencies detector", zap.String("working_dir", workingDir), zap.String("executable", executable), zap.Strings("args", args))
	if err := cmd.Run(); err != nil {
		logger.Error(fmt.Sprintf("Gradle dependencies detector failed: %v", err))
		fields := []zap.Field{zap.Error(err)}
		if commandStderr.String() != "" {
			fields = append(fields, zap.String("stderr", commandStderr.String()))
		}
		logger.Debug("gradle dependencies detector failure details", fields...)
		return nil, fmt.Errorf("run gradle dependencies: %w", err)
	}

	depsGraph, err := depGraphFromGradleOutput(gradleOut.Bytes(), filepath.Base(workingDir))
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to map Gradle output to a dependency graph: %v", err))
		logger.Debug("gradle output mapping failed", zap.Error(err))
		return nil, err
	}
	duration := time.Since(started)
	logger.Info(fmt.Sprintf("Gradle dependencies detector found %d dependencies in %s", depsGraph.Size(), logging.FormatDuration(duration)))

	return depsGraph, nil
}

func (d Detector) commandSpec(workingDir string) (string, []string, error) {
	if wrapperPath, ok := gradleWrapperPath(workingDir); ok {
		args := []string{"dependencies", "--console=plain"}
		if runtime.GOOS == "windows" && isBatchFile(wrapperPath) {
			return "cmd", append([]string{"/c", wrapperPath}, args...), nil
		}
		return wrapperPath, args, nil
	}

	gradlePath, err := system.LookPath("gradle")
	if err != nil {
		return "", nil, err
	}
	return gradlePath, []string{"dependencies", "--console=plain"}, nil
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

func depGraphFromGradleOutput(raw []byte, rootName string) (*model.Graph, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, errors.New("gradle dependencies output is empty")
	}

	if rootName == "" {
		rootName = "root"
	}

	depsGraph := model.New()
	rootNode := model.NewPackage(model.Package{
		Ecosystem:   string(detectors.EcosystemMaven),
		Name:        rootName,
		BuildSystem: detectors.PackageManagerGradle.Name(),
	})
	if err := depsGraph.AddPackage(rootNode); err != nil {
		return nil, fmt.Errorf("add root node: %w", err)
	}

	stack := []string{rootNode.ID}
	currentScope := detectors.ScopeUnknown
	for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if isGradleConfigurationHeader(trimmed) {
			stack = stack[:1]
			currentScope = scopeFromGradleConfiguration(trimmed)
			continue
		}

		node, depth, ok := parseGradleDependencyLine(line, currentScope)
		if !ok {
			continue
		}
		if depth+1 > len(stack) {
			continue
		}

		stack = stack[:depth+1]
		parentID := stack[len(stack)-1]
		if existing, ok := depsGraph.Package(node.ID); ok {
			detectors.MergePackageScope(existing, detectors.Scope(node.Scope))
		} else if err := depsGraph.AddPackage(node); err != nil && !errors.Is(err, model.ErrPackageAlreadyExist) {
			return nil, fmt.Errorf("add node %q: %w", node.ID, err)
		}
		if err := depsGraph.AddDependency(parentID, node.ID); err != nil {
			return nil, fmt.Errorf("add dependency %q -> %q: %w", parentID, node.ID, err)
		}

		stack = append(stack, node.ID)
	}

	return depsGraph, nil
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

func parseGradleDependencyLine(line string, scope detectors.Scope) (*model.Package, int, bool) {
	idx := strings.Index(line, "+--- ")
	if idx < 0 {
		idx = strings.Index(line, "\\--- ")
	}
	if idx < 0 {
		return nil, 0, false
	}

	depth := gradleTreeDepth(line[:idx])
	token := gradleDependencyToken(strings.TrimSpace(line[idx+5:]))
	if token == "" {
		return nil, 0, false
	}

	node, ok := gradleNodeFromToken(token, scope)
	return node, depth, ok
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

func gradleNodeFromToken(token string, scope detectors.Scope) (*model.Package, bool) {
	if strings.HasPrefix(token, "project ") {
		name := strings.TrimSpace(strings.TrimPrefix(token, "project "))
		if name == "" {
			return nil, false
		}
		return model.NewPackage(model.Package{
			Ecosystem:   string(detectors.EcosystemMaven),
			Name:        name,
			Scope:       string(scope),
			BuildSystem: detectors.PackageManagerGradle.Name(),
		}), true
	}

	parts := strings.Split(token, ":")
	if len(parts) < 3 {
		return nil, false
	}

	version := parts[len(parts)-1]
	name := strings.Join(parts[1:len(parts)-1], ":")
	return model.NewPackage(model.Package{
		Ecosystem:   string(detectors.EcosystemMaven),
		Name:        name,
		Version:     version,
		Scope:       string(scope),
		Org:         parts[0],
		BuildSystem: detectors.PackageManagerGradle.Name(),
	}), true
}

func scopeFromGradleConfiguration(value string) detectors.Scope {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch {
	case strings.Contains(normalized, "test"):
		return detectors.ScopeDevelopment
	case strings.Contains(normalized, "runtime"),
		strings.Contains(normalized, "compile"),
		strings.Contains(normalized, "implementation"),
		strings.Contains(normalized, "api"),
		strings.Contains(normalized, "classpath"),
		strings.Contains(normalized, "annotationprocessor"):
		return detectors.ScopeRuntime
	default:
		return detectors.ScopeUnknown
	}
}

// Install prepares Gradle dependencies before graph resolution.
func (d Detector) Install(_ context.Context, req detectors.ResolveGraphRequest) error {
	logger := d.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	workingDir := d.WorkingDir
	if workingDir == "" {
		workingDir = req.ProjectPath
	}
	executable, args, err := d.commandSpec(workingDir)
	if err != nil {
		return fmt.Errorf("resolve gradle command: %w", err)
	}
	args = append(args, req.InstallArgs...)
	cmd := system.Command(executable, args...)
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
