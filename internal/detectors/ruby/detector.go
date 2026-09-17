package ruby

import (
	"bufio"
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/logging"
	detectorkit "github.com/bomly-dev/bomly-sdk/detectorkit"
	logkit "github.com/bomly-dev/bomly-sdk/logkit"
	"github.com/bomly-dev/bomly-sdk/system"
	"go.uber.org/zap"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

var gemDeclarationPattern = regexp.MustCompile(`\bgem\s+["']([^"']+)["']`)
var groupDeclarationPattern = regexp.MustCompile(`^\s*group\s+(.+)\s+do\s*$`)
var symbolPattern = regexp.MustCompile(`:([A-Za-z0-9_]+)`)

type lockSpec struct {
	Name         string
	Version      string
	Source       model.DependencySource
	ResolvedURL  string
	Revision     string
	Dependencies []string
}

// Detector resolves Bundler dependency graphs from Gemfile.lock.
type Detector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   plugin.Detector
}

var evidencePatterns = []string{"Gemfile.lock", "Gemfile.next.lock"}

// PackageManagerSupport returns Bundler package-manager discovery metadata.
func (d Detector) PackageManagerSupport() []plugin.PackageManagerSupport {
	return []plugin.PackageManagerSupport{plugin.Support(model.PackageManagerBundler, evidencePatterns...)}
}

// Ready reports whether the detector can run in the current environment.
func (d Detector) Ready(context.Context, plugin.DetectionRequest) error {
	return nil
}

// Applicable reports whether a Bundler lockfile is present.
func (d Detector) Applicable(ctx context.Context, req plugin.DetectionRequest) (bool, error) {
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
func (d Detector) Descriptor() plugin.DetectorDescriptor {
	return plugin.DetectorDescriptor{
		IgnoredDirectories:      []string{"vendor"},
		Name:                    detectors.NameBundler,
		RemediationCapabilities: bundlerRemediationCapabilities(),
		Technique:               plugin.LockfileTechnique,
		SupportedEcosystems:     []model.Ecosystem{model.EcosystemRuby},
		SupportedManagers:       []model.PackageManager{model.PackageManagerBundler},
		Tags:                    []string{"graph-resolution", "component-targeting", "lockfile-parsing", "best-effort-scope"},
		SupportsInstallFirst:    true,
	}
}

// ResolveGraph resolves a Bundler dependency graph from Gemfile.lock.
func (d Detector) ResolveGraph(_ context.Context, req plugin.DetectionRequest) (plugin.DetectionResult, error) {
	// Prefer the request-scoped logger (bound to this subproject) so
	// concurrent per-subproject resolution stays attributable in logs.
	d.Logger = req.DetectorLogger(d.Logger)
	workingDir := d.workingDir(req.ProjectPath)
	lockPath, err := findBundlerLockfile(workingDir)
	if err != nil {
		return plugin.DetectionResult{}, err
	}
	data, err := system.ReadRepositoryFile(lockPath)
	if err != nil {
		return plugin.DetectionResult{}, fmt.Errorf("read bundler lockfile: %w", err)
	}

	directScopes, err := parseGemfileScopes(filepath.Join(workingDir, "Gemfile"))
	if err != nil {
		return plugin.DetectionResult{}, err
	}

	depsGraph, err := depGraphFromLock(data, directScopes)
	if err != nil {
		return plugin.DetectionResult{}, err
	}

	AttachGemfileLockPositions(depsGraph, lockPath, workingDir)

	return detectors.Attributed(plugin.DetectionResult{
		Graphs: model.SingleGraphContainer(depsGraph, detectorkit.InferManifestMetadata(req, evidencePatterns)),
	}), nil
}

// FallbackDetector returns the configured fallback detector.
func (d Detector) FallbackDetector() plugin.Detector {
	return d.Fallback
}

// Install prepares Bundler dependencies before graph resolution.
func (d Detector) Install(_ context.Context, req plugin.DetectionRequest) error {
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
	commandStderr := logkit.NewCommandStderr(req.Stderr, req.Verbose)
	cmd.Stderr = commandStderr

	started := time.Now()
	logger.Info("Bundler detector running install-first step")
	logger.Debug("running bundler detector install-first", logkit.CommandFields(bundlePath, args, cmd.Dir)...)
	if err := cmd.Run(); err != nil {
		fields := []zap.Field{zap.Error(err)}
		if commandStderr.ByteCount() > 0 {
			fields = append(fields, zap.Int64("stderr_bytes", commandStderr.ByteCount()))
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

func depGraphFromLock(raw []byte, directScopes map[string]model.Scope) (*model.Graph, error) {
	specs, directDependencies, err := parseBundlerLockfile(string(raw))
	if err != nil {
		return nil, err
	}
	if len(specs) == 0 {
		return nil, fmt.Errorf("bundler lockfile does not contain any specs")
	}

	depsGraph := model.New()
	rootNode, err := model.NewModuleNode("Gemfile", model.Coordinates{Ecosystem: model.EcosystemRuby,
		Name:           "root",
		PackageManager: model.PackageManagerBundler,
		Type:           model.PackageTypeApplication,
		Language:       "ruby"})
	if err != nil {
		return nil, fmt.Errorf("build root node: %w", err)
	}
	if err := depsGraph.AddNode(rootNode); err != nil {
		return nil, fmt.Errorf("add root node: %w", err)
	}

	for _, spec := range specs {
		node, err := gemNode(spec)
		if err != nil {
			return nil, err
		}
		if err := addGemNodeIfMissing(depsGraph, node); err != nil {
			return nil, err
		}
	}

	for _, spec := range specs {
		parent, err := gemNode(spec)
		if err != nil {
			return nil, err
		}
		for _, dependencyName := range spec.Dependencies {
			childSpec, ok := specs[dependencyName]
			if !ok {
				continue
			}
			child, err := gemNode(childSpec)
			if err != nil {
				return nil, err
			}
			if err := depsGraph.AddEdge(parent.NodeID(), child.NodeID()); err != nil {
				return nil, fmt.Errorf("add dependency %q -> %q: %w", parent.NodeID(), child.NodeID(), err)
			}
		}
	}

	for _, dependencyName := range directDependencies {
		spec, ok := specs[dependencyName]
		if !ok {
			spec = lockSpec{Name: dependencyName}
			specs[dependencyName] = spec
			node, err := gemNode(spec)
			if err != nil {
				return nil, err
			}
			if err := addGemNodeIfMissing(depsGraph, node); err != nil {
				return nil, err
			}
		}
		node, err := gemNode(spec)
		if err != nil {
			return nil, err
		}
		scope := directScopes[dependencyName]
		if scope == model.ScopeUnknown {
			scope = model.ScopeRuntime
		}
		if existingNode, ok := depsGraph.Node(node.NodeID()); ok {
			if existing, isDep := model.AsDependencyNode(existingNode); isDep {
				existing.AddScope(scope)
			}
		}
		if err := depsGraph.AddEdge(rootNode.NodeID(), node.NodeID()); err != nil {
			return nil, fmt.Errorf("add root dependency %q: %w", node.NodeID(), err)
		}
	}

	for _, dependencyName := range directDependencies {
		visited := make(map[string]struct{}, len(specs))
		var walk func(string, model.Scope)
		walk = func(name string, scope model.Scope) {
			if _, ok := visited[name]; ok {
				return
			}
			visited[name] = struct{}{}
			spec, ok := specs[name]
			if !ok {
				return
			}
			// walk only visits names present in specs, and every spec was
			// built once already in the loop above -- an error here would
			// have returned there, so there is nothing to report from a
			// closure with no error channel.
			node, err := gemNode(spec)
			if err != nil {
				return
			}
			if existingNode, ok := depsGraph.Node(node.NodeID()); ok {
				if existing, isDep := model.AsDependencyNode(existingNode); isDep {
					existing.AddScope(scope)
				}
			}
			for _, child := range spec.Dependencies {
				walk(child, scope)
			}
		}

		scope := directScopes[dependencyName]
		if scope == model.ScopeUnknown {
			scope = model.ScopeRuntime
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
	sectionSource := model.DependencySource("")
	sectionRemote := ""
	sectionRevision := ""

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
			sectionSource = bundlerSectionSource(section)
			sectionRemote = ""
			sectionRevision = ""
			continue
		}

		switch section {
		case "GEM", "GIT", "PATH":
			if !inSpecs && strings.HasPrefix(trimmed, "remote:") {
				sectionRemote = strings.TrimSpace(strings.TrimPrefix(trimmed, "remote:"))
				continue
			}
			if !inSpecs && strings.HasPrefix(trimmed, "revision:") {
				sectionRevision = strings.TrimSpace(strings.TrimPrefix(trimmed, "revision:"))
				continue
			}
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
				spec.Source = sectionSource
				spec.ResolvedURL = sectionRemote
				spec.Revision = sectionRevision
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

func bundlerSectionSource(section string) model.DependencySource {
	switch section {
	case "GEM":
		return model.DependencySourceRegistry
	case "GIT":
		return model.DependencySourceGit
	case "PATH":
		return model.DependencySourceFile
	default:
		return ""
	}
}

func parseLockSpecHeader(value string) (string, string) {
	open := strings.Index(value, " (")
	closeIdx := strings.LastIndex(value, ")")
	if open <= 0 || closeIdx <= open {
		return strings.TrimSpace(value), ""
	}
	return strings.TrimSpace(value[:open]), strings.TrimSpace(value[open+2 : closeIdx])
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

func parseGemfileScopes(path string) (map[string]model.Scope, error) {
	scopes := make(map[string]model.Scope)
	exists, err := system.FileExists(path)
	if err != nil {
		return nil, err
	}
	if !exists {
		return scopes, nil
	}

	data, err := system.ReadRepositoryFile(path)
	if err != nil {
		return nil, fmt.Errorf("read Gemfile: %w", err)
	}

	groupStack := make([]model.Scope, 0, 4)
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
		scope := model.ScopeUnknown
		if strings.Contains(trimmed, "group:") || strings.Contains(trimmed, "groups:") {
			scope = scopeForGroupLabels(labels)
		} else if len(groupStack) > 0 {
			scope = groupStack[len(groupStack)-1]
		}
		if scope == model.ScopeUnknown {
			scope = model.ScopeRuntime
		}
		scopes[gemName] = scope
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan Gemfile: %w", err)
	}

	return scopes, nil
}

func stripGemfileComment(line string) string {
	if before, _, ok := strings.Cut(line, "#"); ok {
		return before
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

func scopeForGroupLabels(labels []string) model.Scope {
	if len(labels) == 0 {
		return model.ScopeUnknown
	}
	for _, label := range labels {
		switch label {
		case "default", "production", "runtime":
			return model.ScopeRuntime
		}
	}
	return model.ScopeDevelopment
}

func gemNode(spec lockSpec) (*model.DependencyNode, error) {
	var metadata map[string]any
	if revision := strings.TrimSpace(spec.Revision); revision != "" {
		metadata = map[string]any{"source_revision": revision}
	}
	node, err := model.NewDependencyNode(model.Coordinates{Ecosystem: model.EcosystemRuby,
		Name:           strings.TrimSpace(spec.Name),
		Version:        strings.TrimSpace(spec.Version),
		PackageManager: model.PackageManagerBundler,
		Type:           "gem",
		Language:       "ruby"})
	if err != nil {
		return nil, fmt.Errorf("build dependency node: %w", err)
	}
	node.Source = spec.Source
	node.ResolvedURL = strings.TrimSpace(spec.ResolvedURL)
	node.Metadata = metadata
	if spec.Source == model.DependencySourceGit {
		// A GIT section names the repository and the commit Bundler locked.
		// A GEM section's remote is the gem server, and PATH is local.
		if origin := model.RepositoryOrigin(spec.ResolvedURL, spec.Revision); origin != nil {
			node.Origins = model.MergeOrigins(node.Origins, []model.DependencyOrigin{*origin})
		}
	}
	return node, nil
}

func addGemNodeIfMissing(depsGraph *model.Graph, node *model.DependencyNode) error {
	_, err := detectorkit.EnsureNode(depsGraph, node)
	return err
}

func appendUnique(values []string, value string) []string {
	if slices.Contains(values, value) {
		return values
	}
	return append(values, value)
}
