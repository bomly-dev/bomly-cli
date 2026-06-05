package gomod

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/logging"
	"github.com/bomly-dev/bomly-cli/internal/system"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

var goExecLookPath = system.LookPath
var goExecCommand = system.Command
var goLookupEnv = os.LookupEnv

type moduleRef struct {
	Path    string
	Version string
	// Line is the 1-based line number in go.mod where this require
	// directive appears. 0 means the line was not captured (e.g.
	// the module is a transitive dep go.mod does not declare).
	Line int
}

type goListPackage struct {
	ImportPath   string        `json:"ImportPath"`
	Imports      []string      `json:"Imports"`
	TestImports  []string      `json:"TestImports"`
	XTestImports []string      `json:"XTestImports"`
	Standard     bool          `json:"Standard"`
	DepOnly      bool          `json:"DepOnly"`
	ForTest      string        `json:"ForTest"`
	Module       *goListModule `json:"Module"`
}

type goListModule struct {
	Path    string        `json:"Path"`
	Version string        `json:"Version"`
	Main    bool          `json:"Main"`
	Replace *goListModule `json:"Replace"`
}

type moduleNode struct {
	Path    string
	Version string
	Main    bool
}

type queuedPackage struct {
	pkg   goListPackage
	scope sdk.Scope
}

// Detector resolves Go module dependency graphs by invoking the Go CLI.
type Detector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   sdk.Detector
}

var evidencePatterns = []string{"go.mod"}

// PackageManagerSupport returns Go module package-manager discovery metadata.
func (d Detector) PackageManagerSupport() []sdk.PackageManagerSupport {
	return []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerGoMod, evidencePatterns...)}
}

// Ready reports whether the Go CLI is available.
func (d Detector) Ready() bool {
	_, err := goExecLookPath("go")
	return err == nil
}

// Applicable reports whether the target project contains a go.mod file.
func (d Detector) Applicable(ctx context.Context, req sdk.DetectionRequest) (bool, error) {
	_ = ctx

	workingDir := d.WorkingDir
	if workingDir == "" {
		workingDir = req.ProjectPath
	}

	return system.FileExists(filepath.Join(workingDir, "go.mod"))
}

// Descriptor describes the Go CLI-backed detector.
func (d Detector) Descriptor() sdk.DetectorDescriptor {
	return sdk.DetectorDescriptor{
		Name:                 detectors.NameGoMod,
		Enabled:              true,
		Origin:               sdk.CoreOrigin,
		Technique:            sdk.BuildToolTechnique,
		SupportedEcosystems:  []sdk.Ecosystem{sdk.EcosystemGo},
		SupportedManagers:    []sdk.PackageManager{sdk.PackageManagerGoMod},
		SupportedModes:       []sdk.TargetMode{sdk.TargetModeFullGraph, sdk.TargetModeComponent},
		Capabilities:         []string{"graph-resolution", "component-targeting", "module-graph"},
		SupportsInstallFirst: true,
	}
}

// ResolveGraph resolves a Go module dependency graph for the scan engine.
func (d Detector) ResolveGraph(_ context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	depsGraph, err := d.resolveGraph(req.Stderr, req.ProjectPath, req.Verbose, req.ScopeFilter)
	if err != nil {
		return sdk.DetectionResult{}, err
	}

	return sdk.DetectionResult{
		Graphs: sdk.SingleGraphContainer(depsGraph, detectors.InferManifestMetadata(req, evidencePatterns)),
	}, nil
}

// FallbackDetector returns the configured fallback detector.
func (d Detector) FallbackDetector() sdk.Detector {
	return d.Fallback
}

func (d Detector) resolveGraph(stderr io.Writer, projectPath string, verbose bool, scopeFilter sdk.Scope) (*sdk.Graph, error) {
	logger := d.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	workingDir := d.WorkingDir
	if workingDir == "" {
		workingDir = projectPath
	}

	modulePath, directRequires, err := parseGoModFile(filepath.Join(workingDir, "go.mod"))
	if err != nil {
		return nil, err
	}

	goPath, err := goExecLookPath("go")
	if err != nil {
		return nil, fmt.Errorf("resolve go executable: %w", err)
	}

	args := buildGoListArgs()
	cmd := goExecCommand(goPath, args...)
	cmd.Dir = workingDir
	commandStderr := logging.NewCommandStderr(stderr, verbose)
	cmd.Stderr = commandStderr

	started := time.Now()
	logger.Debug("running go module detector", zap.String("working_dir", workingDir), zap.String("executable", goPath), zap.Strings("args", args))
	raw, err := cmd.Output()
	if err != nil {
		logger.Error(fmt.Sprintf("Go module detector failed: %v", err))
		fields := []zap.Field{zap.Error(err)}
		if commandStderr.String() != "" {
			fields = append(fields, zap.String("stderr", commandStderr.String()))
		}
		logger.Debug("go module detector failure details", fields...)
		return nil, fmt.Errorf("run go list -deps -json all: %w", err)
	}

	depsGraph, err := depGraphFromGoListWithScope(raw, modulePath, directRequires, scopeFilter)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to map Go module output to a dependency graph: %v", err))
		logger.Debug("go module output mapping failed", zap.Error(err))
		return nil, err
	}
	duration := time.Since(started)
	logger.Info(fmt.Sprintf("Go module detector found %d dependencies in %s", depsGraph.Size(), logging.FormatDuration(duration)))

	return depsGraph, nil
}

func buildGoListArgs() []string {
	args := []string{"list", "-deps", "-json"}
	if tags, ok := goLookupEnv("BOMLY_GO_TAGS"); ok {
		tags = strings.TrimSpace(tags)
		if tags != "" {
			args = append(args, "-tags="+tags)
		}
	}
	return append(args, "all")
}

func depGraphFromGoList(raw []byte, rootModule string, directRequires []moduleRef) (*sdk.Graph, error) {
	return depGraphFromGoListWithScope(raw, rootModule, directRequires, sdk.ScopeUnknown)
}

func depGraphFromGoListWithScope(raw []byte, rootModule string, directRequires []moduleRef, scopeFilter sdk.Scope) (*sdk.Graph, error) {
	if strings.TrimSpace(rootModule) == "" {
		return nil, errors.New("go module path is empty")
	}
	packages, err := parseGoListPackages(raw)
	if err != nil {
		return nil, err
	}
	// Build a module-path -> go.mod line index so packageFromModuleNode
	// can attach a SourcePosition to direct deps. Transitive deps that
	// don't appear in go.mod get nil Position (their Line is 0).
	directLines := make(map[string]int, len(directRequires))
	for _, ref := range directRequires {
		if ref.Path != "" && ref.Line > 0 {
			directLines[ref.Path] = ref.Line
		}
	}
	if len(packages) == 0 {
		return nil, errors.New("go list output is empty")
	}

	depsGraph := sdk.New()
	rootNode := sdk.NewDependency(sdk.Dependency{
		Ecosystem: string(sdk.EcosystemGo),
		Name:      rootModule,
	})
	if err := depsGraph.AddNode(rootNode); err != nil {
		return nil, fmt.Errorf("add root node: %w", err)
	}

	packageModules := make(map[string]moduleNode, len(packages))
	packageRecords := make(map[string]goListPackage, len(packages))
	for _, pkg := range packages {
		module, ok := moduleNodeFromPackage(pkg, rootModule)
		if !ok {
			continue
		}
		if _, exists := packageModules[pkg.ImportPath]; exists && strings.TrimSpace(pkg.ForTest) != "" {
			continue
		}
		packageModules[pkg.ImportPath] = module
		packageRecords[pkg.ImportPath] = pkg
	}

	queue := make([]queuedPackage, 0, len(packages))
	for _, pkg := range packages {
		module, ok := moduleNodeFromPackage(pkg, rootModule)
		if !ok || !module.Main {
			continue
		}

		baseScope := sdk.ScopeRuntime
		if strings.TrimSpace(pkg.ForTest) != "" {
			baseScope = sdk.ScopeDevelopment
		}
		queue = append(queue, queuedPackage{pkg: pkg, scope: baseScope})
	}

	visited := make(map[string]sdk.Scope, len(packages))
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		visitKey := current.pkg.ImportPath + "|" + current.pkg.ForTest
		mergedScope := sdk.MergeScope(visited[visitKey], current.scope)
		if visited[visitKey] == mergedScope {
			continue
		}
		visited[visitKey] = mergedScope

		currentModule, ok := moduleNodeFromPackage(current.pkg, rootModule)
		if !ok {
			continue
		}
		if !currentModule.Main {
			currentNode := packageFromModuleNode(currentModule, mergedScope, directLines)
			if err := addOrMergeModuleNode(depsGraph, currentNode, mergedScope); err != nil {
				return nil, err
			}
		}

		if err := enqueueImportedPackages(depsGraph, rootNode.ID, currentModule, mergedScope, current.pkg.Imports, packageRecords, packageModules, directLines, &queue); err != nil {
			return nil, err
		}
		if scopeFilter != sdk.ScopeRuntime {
			if err := enqueueImportedPackages(depsGraph, rootNode.ID, currentModule, sdk.ScopeDevelopment, current.pkg.TestImports, packageRecords, packageModules, directLines, &queue); err != nil {
				return nil, err
			}
			if err := enqueueImportedPackages(depsGraph, rootNode.ID, currentModule, sdk.ScopeDevelopment, current.pkg.XTestImports, packageRecords, packageModules, directLines, &queue); err != nil {
				return nil, err
			}
		}
	}

	return depsGraph, nil
}

func parseGoListPackages(raw []byte) ([]goListPackage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	packages := make([]goListPackage, 0, 64)
	for {
		var pkg goListPackage
		if err := decoder.Decode(&pkg); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("decode go list output: %w", err)
		}
		packages = append(packages, pkg)
	}
	return packages, nil
}

func moduleNodeFromPackage(pkg goListPackage, rootModule string) (moduleNode, bool) {
	if pkg.Standard || strings.TrimSpace(pkg.ImportPath) == "" || pkg.Module == nil {
		return moduleNode{}, false
	}
	path := strings.TrimSpace(pkg.Module.Path)
	if path == "" {
		return moduleNode{}, false
	}
	return moduleNode{
		Path:    path,
		Version: strings.TrimSpace(pkg.Module.Version),
		Main:    pkg.Module.Main || path == rootModule,
	}, true
}

func enqueueImportedPackages(depsGraph *sdk.Graph, rootID string, from moduleNode, scope sdk.Scope, imports []string, packageRecords map[string]goListPackage, packageModules map[string]moduleNode, directLines map[string]int, queue *[]queuedPackage) error {
	fromID := rootID
	if !from.Main {
		fromID = moduleNodeID(from)
	}

	for _, imported := range imports {
		toPkg, ok := packageRecords[imported]
		if !ok {
			continue
		}
		to, ok := packageModules[imported]
		if !ok {
			continue
		}
		if !to.Main {
			pkg := packageFromModuleNode(to, scope, directLines)
			if err := addOrMergeModuleNode(depsGraph, pkg, scope); err != nil {
				return err
			}
			if from.Path != to.Path || from.Version != to.Version {
				if err := depsGraph.AddEdge(fromID, pkg.ID); err != nil {
					return fmt.Errorf("add go dependency %q -> %q: %w", fromID, pkg.ID, err)
				}
			}
		}
		*queue = append(*queue, queuedPackage{pkg: toPkg, scope: scope})
	}
	return nil
}

func packageFromModuleNode(node moduleNode, scope sdk.Scope, directLines map[string]int) *sdk.Dependency {
	dep := sdk.Dependency{
		Ecosystem: string(sdk.EcosystemGo),
		Name:      node.Path,
		Version:   node.Version,
	}
	if scope != sdk.ScopeUnknown {
		dep.Scopes = []sdk.Scope{scope}
	}
	if line, ok := directLines[node.Path]; ok && line > 0 {
		dep.Locations = []sdk.PackageLocation{
			{
				RealPath:   "go.mod",
				AccessPath: "go.mod",
				Position:   &sdk.SourcePosition{File: "go.mod", Line: line},
			},
		}
	}
	return sdk.NewDependency(dep)
}

func moduleNodeID(node moduleNode) string {
	return sdk.NewDependency(sdk.Dependency{
		Ecosystem: string(sdk.EcosystemGo),
		Name:      node.Path,
		Version:   node.Version,
	}).ID
}

func parseGoModFile(path string) (string, []moduleRef, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil, fmt.Errorf("read %q: %w", path, err)
	}

	var modulePath string
	requires := make([]moduleRef, 0, 8)
	inRequireBlock := false
	seen := make(map[string]struct{})

	scanner := bufio.NewScanner(strings.NewReader(strings.ReplaceAll(string(data), "\r\n", "\n")))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		raw := scanner.Text()
		line := stripLineComment(raw)
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		switch {
		case strings.HasPrefix(line, "module "):
			fields := strings.Fields(line)
			if len(fields) < 2 {
				return "", nil, fmt.Errorf("parse module directive %q: expected module path", line)
			}
			modulePath = trimQuoted(fields[1])
		case strings.HasPrefix(line, "require ("):
			inRequireBlock = true
		case inRequireBlock && line == ")":
			inRequireBlock = false
		case strings.HasPrefix(line, "require "):
			ref, ok, err := parseRequireDirective(strings.TrimSpace(strings.TrimPrefix(line, "require ")))
			if err != nil {
				return "", nil, err
			}
			if ok {
				ref.Line = lineNum
				requires = appendUniqueModule(requires, seen, ref)
			}
		case inRequireBlock:
			ref, ok, err := parseRequireDirective(line)
			if err != nil {
				return "", nil, err
			}
			if ok {
				ref.Line = lineNum
				requires = appendUniqueModule(requires, seen, ref)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return "", nil, fmt.Errorf("scan %q: %w", path, err)
	}
	if modulePath == "" {
		return "", nil, fmt.Errorf("parse %q: missing module directive", path)
	}

	return modulePath, requires, nil
}

// Install prepares Go module dependencies before graph resolution.
func (d Detector) Install(_ context.Context, req sdk.DetectionRequest) error {
	logger := d.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	workingDir := d.WorkingDir
	if workingDir == "" {
		workingDir = req.ProjectPath
	}
	goPath, err := goExecLookPath("go")
	if err != nil {
		return fmt.Errorf("resolve go executable: %w", err)
	}
	args := append([]string{"mod", "download"}, req.InstallArgs...)
	cmd := goExecCommand(goPath, args...)
	cmd.Dir = workingDir
	commandStderr := logging.NewCommandStderr(req.Stderr, req.Verbose)
	cmd.Stderr = commandStderr
	started := time.Now()
	logger.Info("Go detector running install-first step")
	logger.Debug("running go detector install-first", zap.String("working_dir", workingDir), zap.String("executable", goPath), zap.Strings("args", args))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("run go mod download: %w", err)
	}
	logger.Info(fmt.Sprintf("Go detector install-first completed in %s", logging.FormatDuration(time.Since(started))))
	return nil
}

func parseRequireDirective(value string) (moduleRef, bool, error) {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return moduleRef{}, false, nil
	}
	if len(fields) < 2 {
		return moduleRef{}, false, fmt.Errorf("parse require directive %q: expected module path and version", value)
	}

	ref := moduleRef{
		Path:    trimQuoted(fields[0]),
		Version: trimQuoted(fields[1]),
	}
	if ref.Path == "" || ref.Version == "" {
		return moduleRef{}, false, fmt.Errorf("parse require directive %q: expected module path and version", value)
	}
	return ref, true, nil
}

func stripLineComment(line string) string {
	if idx := strings.Index(line, "//"); idx >= 0 {
		return line[:idx]
	}
	return line
}

func trimQuoted(value string) string {
	return strings.Trim(value, "`\"")
}

func appendUniqueModule(modules []moduleRef, seen map[string]struct{}, ref moduleRef) []moduleRef {
	key := ref.Path + "@" + ref.Version
	if _, ok := seen[key]; ok {
		return modules
	}
	seen[key] = struct{}{}
	return append(modules, ref)
}

func addOrMergeModuleNode(depsGraph *sdk.Graph, node *sdk.Dependency, scope sdk.Scope) error {
	if existing, ok := depsGraph.Node(node.ID); ok {
		existing.AddScope(scope)
		return nil
	}
	if err := depsGraph.AddNode(node); err != nil {
		return fmt.Errorf("add node %q: %w", node.ID, err)
	}
	return nil
}
