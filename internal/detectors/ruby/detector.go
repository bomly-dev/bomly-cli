package ruby

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/logging"
	"github.com/bomly-dev/bomly-cli/internal/system"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

var gemDeclarationPattern = regexp.MustCompile(`\bgem\s+["']([^"']+)["']`)
var groupDeclarationPattern = regexp.MustCompile(`^\s*group\s+(.+)\s+do\s*$`)
var symbolPattern = regexp.MustCompile(`:([A-Za-z0-9_]+)`)

type lockSpec struct {
	Name         string
	Version      string
	Dependencies []string
}

// Detector resolves Bundler dependency graphs from Gemfile.lock.
type Detector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   sdk.Detector
}

var evidencePatterns = []string{"Gemfile.lock", "Gemfile.next.lock"}

// PackageManagerSupport returns Bundler package-manager discovery metadata.
func (d Detector) PackageManagerSupport() []sdk.PackageManagerSupport {
	return []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerBundler, evidencePatterns...)}
}

// Ready reports whether the detector can run in the current environment.
func (d Detector) Ready() bool {
	return true
}

// Applicable reports whether a Bundler lockfile is present.
func (d Detector) Applicable(ctx context.Context, req sdk.DetectionRequest) (bool, error) {
	_ = ctx
	for _, name := range []string{"Gemfile.lock", "Gemfile.next.lock"} {
		exists, err := system.FileExists(filepath.Join(d.workingDir(req.ProjectPath), name))
		if err != nil {
			return false, err
		}
		if exists {
			return true, nil
		}
	}
	return false, nil
}

// Descriptor describes the Bundler detector.
func (d Detector) Descriptor() sdk.DetectorDescriptor {
	return sdk.DetectorDescriptor{
		Name:                 detectors.NameBundler,
		Enabled:              true,
		Origin:               sdk.CoreOrigin,
		Technique:            sdk.LockfileTechnique,
		SupportedEcosystems:  []sdk.Ecosystem{sdk.EcosystemRuby},
		SupportedManagers:    []sdk.PackageManager{sdk.PackageManagerBundler},
		SupportedModes:       []sdk.TargetMode{sdk.TargetModeFullGraph, sdk.TargetModeComponent},
		Capabilities:         []string{"graph-resolution", "component-targeting", "lockfile-parsing", "best-effort-scope"},
		SupportsInstallFirst: true,
	}
}

// ResolveGraph resolves a Bundler dependency graph from Gemfile.lock.
func (d Detector) ResolveGraph(_ context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	workingDir := d.workingDir(req.ProjectPath)
	lockPath, err := findBundlerLockfile(workingDir)
	if err != nil {
		return sdk.DetectionResult{}, err
	}
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("read bundler lockfile: %w", err)
	}

	directScopes, err := parseGemfileScopes(filepath.Join(workingDir, "Gemfile"))
	if err != nil {
		return sdk.DetectionResult{}, err
	}

	depsGraph, err := depGraphFromLock(data, directScopes)
	if err != nil {
		return sdk.DetectionResult{}, err
	}

	AttachGemfileLockPositions(depsGraph, lockPath, workingDir)

	return sdk.DetectionResult{
		Graphs: sdk.SingleGraphContainer(depsGraph, detectors.InferManifestMetadata(req, evidencePatterns)),
	}, nil
}

// FallbackDetector returns the configured fallback detector.
func (d Detector) FallbackDetector() sdk.Detector {
	return d.Fallback
}

// Install prepares Bundler dependencies before graph resolution.
func (d Detector) Install(_ context.Context, req sdk.DetectionRequest) error {
	logger := d.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	bundlePath, err := system.LookPath("bundle")
	if err != nil {
		return fmt.Errorf("resolve bundle executable: %w", err)
	}

	args := append([]string{"install"}, req.InstallArgs...)
	cmd := system.Command(bundlePath, args...)
	cmd.Dir = d.workingDir(req.ProjectPath)
	commandStderr := logging.NewCommandStderr(req.Stderr, req.Verbose)
	cmd.Stderr = commandStderr

	started := time.Now()
	logger.Info("Bundler detector running install-first step")
	logger.Debug("running bundler detector install-first", zap.String("working_dir", cmd.Dir), zap.String("executable", bundlePath), zap.Strings("args", args))
	if err := cmd.Run(); err != nil {
		fields := []zap.Field{zap.Error(err)}
		if commandStderr.String() != "" {
			fields = append(fields, zap.String("stderr", commandStderr.String()))
		}
		logger.Debug("bundler detector install-first failure details", fields...)
		return fmt.Errorf("run bundle install: %w", err)
	}
	logger.Info(fmt.Sprintf("Bundler detector install-first completed in %s", logging.FormatDuration(time.Since(started))))
	return nil
}

func (d Detector) workingDir(projectPath string) string {
	if d.WorkingDir != "" {
		return d.WorkingDir
	}
	return projectPath
}

func findBundlerLockfile(projectPath string) (string, error) {
	for _, name := range []string{"Gemfile.lock", "Gemfile.next.lock"} {
		candidate := filepath.Join(projectPath, name)
		exists, err := system.FileExists(candidate)
		if err != nil {
			return "", err
		}
		if exists {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("no supported Bundler lockfile found")
}

func depGraphFromLock(raw []byte, directScopes map[string]sdk.Scope) (*sdk.Graph, error) {
	specs, directDependencies, err := parseBundlerLockfile(string(raw))
	if err != nil {
		return nil, err
	}
	if len(specs) == 0 {
		return nil, fmt.Errorf("bundler lockfile does not contain any specs")
	}

	depsGraph := sdk.New()
	rootNode := sdk.NewDependency(sdk.Dependency{
		Ecosystem:   string(sdk.EcosystemRuby),
		Name:        "root",
		BuildSystem: sdk.PackageManagerBundler.Name(),
		Type:        "application",
		Language:    "ruby",
	})

	if err := depsGraph.AddNode(rootNode); err != nil {
		return nil, fmt.Errorf("add root node: %w", err)
	}

	for _, spec := range specs {
		node := gemNode(spec.Name, spec.Version)
		if err := addGemNodeIfMissing(depsGraph, node); err != nil {
			return nil, err
		}
	}

	for _, spec := range specs {
		parent := gemNode(spec.Name, spec.Version)
		for _, dependencyName := range spec.Dependencies {
			childSpec, ok := specs[dependencyName]
			if !ok {
				continue
			}
			child := gemNode(childSpec.Name, childSpec.Version)
			if err := depsGraph.AddEdge(parent.ID, child.ID); err != nil {
				return nil, fmt.Errorf("add dependency %q -> %q: %w", parent.ID, child.ID, err)
			}
		}
	}

	for _, dependencyName := range directDependencies {
		spec, ok := specs[dependencyName]
		if !ok {
			spec = lockSpec{Name: dependencyName}
			specs[dependencyName] = spec
			node := gemNode(spec.Name, spec.Version)
			if err := addGemNodeIfMissing(depsGraph, node); err != nil {
				return nil, err
			}
		}
		node := gemNode(spec.Name, spec.Version)
		scope := directScopes[dependencyName]
		if scope == sdk.ScopeUnknown {
			scope = sdk.ScopeRuntime
		}
		if existing, ok := depsGraph.Node(node.ID); ok {
			existing.AddScope(scope)
		}
		if err := depsGraph.AddEdge(rootNode.ID, node.ID); err != nil {
			return nil, fmt.Errorf("add root dependency %q: %w", node.ID, err)
		}
	}

	for _, dependencyName := range directDependencies {
		visited := make(map[string]struct{}, len(specs))
		var walk func(string, sdk.Scope)
		walk = func(name string, scope sdk.Scope) {
			if _, ok := visited[name]; ok {
				return
			}
			visited[name] = struct{}{}
			spec, ok := specs[name]
			if !ok {
				return
			}
			node := gemNode(spec.Name, spec.Version)
			if existing, ok := depsGraph.Node(node.ID); ok {
				existing.AddScope(scope)
			}
			for _, child := range spec.Dependencies {
				walk(child, scope)
			}
		}

		scope := directScopes[dependencyName]
		if scope == sdk.ScopeUnknown {
			scope = sdk.ScopeRuntime
		}
		walk(dependencyName, scope)
	}

	return depsGraph, nil
}

func parseBundlerLockfile(raw string) (map[string]lockSpec, []string, error) {
	specs := make(map[string]lockSpec)
	directDependencies := make([]string, 0, 8)
	section := ""
	inSpecs := false
	currentName := ""

	scanner := bufio.NewScanner(strings.NewReader(strings.ReplaceAll(raw, "\r\n", "\n")))
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
			section = trimmed
			inSpecs = false
			currentName = ""
			continue
		}

		switch section {
		case "GEM", "GIT", "PATH":
			if trimmed == "specs:" {
				inSpecs = true
				currentName = ""
				continue
			}
			if !inSpecs {
				continue
			}
			indent := len(line) - len(strings.TrimLeft(line, " "))
			switch {
			case indent == 4:
				name, version := parseLockSpecHeader(trimmed)
				if name == "" {
					continue
				}
				currentName = name
				spec := specs[name]
				spec.Name = name
				spec.Version = version
				specs[name] = spec
			case indent >= 6 && currentName != "":
				dependencyName := parseDependencyName(trimmed)
				if dependencyName == "" {
					continue
				}
				spec := specs[currentName]
				spec.Dependencies = appendUnique(spec.Dependencies, dependencyName)
				specs[currentName] = spec
			}
		case "DEPENDENCIES":
			if strings.HasPrefix(line, "  ") {
				dependencyName := parseDependencyName(trimmed)
				if dependencyName != "" {
					directDependencies = appendUnique(directDependencies, dependencyName)
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("scan bundler lockfile: %w", err)
	}
	return specs, directDependencies, nil
}

func parseLockSpecHeader(value string) (string, string) {
	open := strings.Index(value, " (")
	close := strings.LastIndex(value, ")")
	if open <= 0 || close <= open {
		return strings.TrimSpace(value), ""
	}
	return strings.TrimSpace(value[:open]), strings.TrimSpace(value[open+2 : close])
}

func parseDependencyName(value string) string {
	value = strings.TrimSpace(strings.TrimSuffix(value, "!"))
	if value == "" {
		return ""
	}
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return ""
	}
	return strings.TrimSpace(fields[0])
}

func parseGemfileScopes(path string) (map[string]sdk.Scope, error) {
	scopes := make(map[string]sdk.Scope)
	exists, err := system.FileExists(path)
	if err != nil {
		return nil, err
	}
	if !exists {
		return scopes, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read Gemfile: %w", err)
	}

	groupStack := make([]sdk.Scope, 0, 4)
	scanner := bufio.NewScanner(strings.NewReader(strings.ReplaceAll(string(data), "\r\n", "\n")))
	for scanner.Scan() {
		line := stripGemfileComment(scanner.Text())
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if matches := groupDeclarationPattern.FindStringSubmatch(trimmed); len(matches) == 2 {
			labels := extractSymbols(matches[1])
			groupStack = append(groupStack, scopeForGroupLabels(labels))
			continue
		}
		if trimmed == "end" {
			if len(groupStack) > 0 {
				groupStack = groupStack[:len(groupStack)-1]
			}
			continue
		}

		matches := gemDeclarationPattern.FindStringSubmatch(trimmed)
		if len(matches) != 2 {
			continue
		}

		gemName := strings.TrimSpace(matches[1])
		if gemName == "" {
			continue
		}

		labels := extractSymbols(trimmed)
		scope := sdk.ScopeUnknown
		if strings.Contains(trimmed, "group:") || strings.Contains(trimmed, "groups:") {
			scope = scopeForGroupLabels(labels)
		} else if len(groupStack) > 0 {
			scope = groupStack[len(groupStack)-1]
		}
		if scope == sdk.ScopeUnknown {
			scope = sdk.ScopeRuntime
		}
		scopes[gemName] = scope
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan Gemfile: %w", err)
	}

	return scopes, nil
}

func stripGemfileComment(line string) string {
	if idx := strings.Index(line, "#"); idx >= 0 {
		return line[:idx]
	}
	return line
}

func extractSymbols(value string) []string {
	matches := symbolPattern.FindAllStringSubmatch(value, -1)
	labels := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) == 2 {
			labels = append(labels, strings.ToLower(strings.TrimSpace(match[1])))
		}
	}
	return labels
}

func scopeForGroupLabels(labels []string) sdk.Scope {
	if len(labels) == 0 {
		return sdk.ScopeUnknown
	}
	for _, label := range labels {
		switch label {
		case "default", "production", "runtime":
			return sdk.ScopeRuntime
		}
	}
	return sdk.ScopeDevelopment
}

func gemNode(name, version string) *sdk.Dependency {
	return sdk.NewDependency(sdk.Dependency{
		Ecosystem:   string(sdk.EcosystemRuby),
		Name:        strings.TrimSpace(name),
		Version:     strings.TrimSpace(version),
		BuildSystem: sdk.PackageManagerBundler.Name(),
		Type:        "gem",
		Language:    "ruby",
	})

}

func addGemNodeIfMissing(depsGraph *sdk.Graph, node *sdk.Dependency) error {
	if _, ok := depsGraph.Node(node.ID); ok {
		return nil
	}
	if err := depsGraph.AddNode(node); err != nil {
		return fmt.Errorf("add node %q: %w", node.ID, err)
	}
	return nil
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
