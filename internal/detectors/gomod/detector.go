package gomod

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bomly/bomly-cli/internal/detectors"
	"github.com/bomly/bomly-cli/internal/logging"
	"github.com/bomly/bomly-cli/internal/model"
	"github.com/bomly/bomly-cli/pkg/system"
	"go.uber.org/zap"
)

var goExecLookPath = system.LookPath
var goExecCommand = system.Command

type moduleRef struct {
	Path    string
	Version string
}

// Detector resolves Go module dependency graphs by invoking the Go CLI.
type Detector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   detectors.Detector
}

// Ready reports whether the Go CLI is available.
func (d Detector) Ready() bool {
	_, err := goExecLookPath("go")
	return err == nil
}

// Applicable reports whether the target project contains a go.mod file.
func (d Detector) Applicable(ctx context.Context, req detectors.ResolveGraphRequest) (bool, error) {
	_ = ctx

	workingDir := d.WorkingDir
	if workingDir == "" {
		workingDir = req.ProjectPath
	}

	return system.FileExists(filepath.Join(workingDir, "go.mod"))
}

// Descriptor describes the Go CLI-backed detector.
func (d Detector) Descriptor() detectors.DetectorDescriptor {
	return detectors.DetectorDescriptor{
		Name:                "go-detector",
		ImplementationType:  detectors.NativeDetector,
		SupportedEcosystems: []detectors.Ecosystem{detectors.EcosystemGo},
		SupportedManagers:   []detectors.PackageManager{detectors.PackageManagerGoMod},
		SupportedModes:      []detectors.TargetMode{detectors.TargetModeFullGraph, detectors.TargetModeComponent},
		Capabilities:        []string{"graph-resolution", "component-targeting", "module-graph"},
	}
}

// ResolveGraph resolves a Go module dependency graph for the scan engine.
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

	modulePath, _, err := parseGoModFile(filepath.Join(workingDir, "go.mod"))
	if err != nil {
		return nil, err
	}

	goPath, err := goExecLookPath("go")
	if err != nil {
		return nil, fmt.Errorf("resolve go executable: %w", err)
	}

	cmd := goExecCommand(goPath, "mod", "graph")
	cmd.Dir = workingDir
	commandStderr := logging.NewCommandStderr(stderr, verbose)
	cmd.Stderr = commandStderr

	started := time.Now()
	logger.Debug("running go module detector", zap.String("working_dir", workingDir), zap.String("executable", goPath), zap.Strings("args", []string{"mod", "graph"}))
	raw, err := cmd.Output()
	if err != nil {
		logger.Error(fmt.Sprintf("Go module detector failed: %v", err))
		fields := []zap.Field{zap.Error(err)}
		if commandStderr.String() != "" {
			fields = append(fields, zap.String("stderr", commandStderr.String()))
		}
		logger.Debug("go module detector failure details", fields...)
		return nil, fmt.Errorf("run go mod graph: %w", err)
	}

	depsGraph, err := depGraphFromGoModGraph(raw, modulePath)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to map Go module output to a dependency graph: %v", err))
		logger.Debug("go module output mapping failed", zap.Error(err))
		return nil, err
	}
	duration := time.Since(started)
	logger.Info(fmt.Sprintf("Go module detector found %d dependencies in %s", depsGraph.Size(), logging.FormatDuration(duration)))

	return depsGraph, nil
}

func depGraphFromGoModGraph(raw []byte, rootModule string) (*model.Graph, error) {
	if strings.TrimSpace(rootModule) == "" {
		return nil, errors.New("go module path is empty")
	}

	depsGraph := model.New()
	rootNode := model.NewPackage(model.Package{
		Ecosystem: string(detectors.EcosystemGo),
		Name:      rootModule,
	})
	if err := depsGraph.AddPackage(rootNode); err != nil {
		return nil, fmt.Errorf("add root node: %w", err)
	}

	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	seenEdge := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("parse go mod graph line %q: expected 2 fields", line)
		}

		fromNode, err := nodeFromModuleToken(fields[0])
		if err != nil {
			return nil, err
		}
		toNode, err := nodeFromModuleToken(fields[1])
		if err != nil {
			return nil, err
		}

		if err := addNodeIfMissing(depsGraph, fromNode); err != nil {
			return nil, err
		}
		if err := addNodeIfMissing(depsGraph, toNode); err != nil {
			return nil, err
		}
		if err := depsGraph.AddDependency(fromNode.ID, toNode.ID); err != nil {
			return nil, fmt.Errorf("add go dependency %q -> %q: %w", fromNode.ID, toNode.ID, err)
		}
		seenEdge = true
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan go mod graph: %w", err)
	}
	if !seenEdge {
		return nil, errors.New("go mod graph output is empty")
	}

	return depsGraph, nil
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
	for scanner.Scan() {
		line := stripLineComment(scanner.Text())
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
				requires = appendUniqueModule(requires, seen, ref)
			}
		case inRequireBlock:
			ref, ok, err := parseRequireDirective(line)
			if err != nil {
				return "", nil, err
			}
			if ok {
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
func (d Detector) Install(_ context.Context, req detectors.ResolveGraphRequest) error {
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

func nodeFromModuleToken(token string) (*model.Package, error) {
	name, version := splitModuleToken(token)
	if name == "" {
		return nil, fmt.Errorf("parse go module token %q: empty module path", token)
	}
	return model.NewPackage(model.Package{
		Ecosystem: string(detectors.EcosystemGo),
		Name:      name,
		Version:   version,
	}), nil
}

func splitModuleToken(token string) (string, string) {
	idx := strings.LastIndex(token, "@")
	if idx < 0 {
		return token, ""
	}
	return token[:idx], token[idx+1:]
}

func addNodeIfMissing(depsGraph *model.Graph, node *model.Package) error {
	if _, ok := depsGraph.Package(node.ID); ok {
		return nil
	}
	if err := depsGraph.AddPackage(node); err != nil {
		return fmt.Errorf("add node %q: %w", node.ID, err)
	}
	return nil
}
