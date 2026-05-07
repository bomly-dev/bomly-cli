package python

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	var out bytes.Buffer
	cmd.Stdout = &out
	commandStderr := logging.NewCommandStderr(stderr, verbose)
	cmd.Stderr = commandStderr

	started := time.Now()
	logger.Debug("running external dependency detector", zap.String("detector", detectorName), zap.String("working_dir", cmd.Dir), zap.String("executable", command[0]), zap.Strings("args", command[1:]))
	if err := cmd.Run(); err != nil {
		logger.Error(fmt.Sprintf("%s failed: %v", detectorName, err))
		fields := []zap.Field{zap.Error(err), zap.String("detector", detectorName)}
		if commandStderr.String() != "" {
			fields = append(fields, zap.String("stderr", commandStderr.String()))
		}
		logger.Debug("external dependency detector failure details", fields...)
		return nil, fmt.Errorf("run %s: %w", detectorName, err)
	}

	depsGraph, err := depGraphFromPipInspect(out.Bytes())
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to map %s output to a dependency graph: %v", detectorName, err))
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
	commandStderr := logging.NewCommandStderr(req.Stderr, req.Verbose)
	cmd.Stderr = commandStderr
	started := time.Now()
	logger.Info(fmt.Sprintf("%s running install-first step", detectorName))
	logger.Debug("running python detector install-first", zap.String("detector", detectorName), zap.String("working_dir", cmd.Dir), zap.String("executable", command[0]), zap.Strings("args", command[1:]))
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
	rootNode := sdk.NewPackage(sdk.Package{
		Ecosystem: string(sdk.EcosystemPython),
		Name:      "root",
	})
	if err := depsGraph.AddPackage(rootNode); err != nil {
		return nil, fmt.Errorf("add root node: %w", err)
	}

	nodesByName := make(map[string]*sdk.Package, len(report.Installed))
	for _, pkg := range report.Installed {
		if pkg.Metadata.Name == "" {
			continue
		}
		node := sdk.NewPackage(sdk.Package{
			Ecosystem: string(sdk.EcosystemPython),
			Name:      normalizePythonName(pkg.Metadata.Name),
			Version:   pkg.Metadata.Version,
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
			if err := depsGraph.AddDependency(rootNode.ID, parent.ID); err != nil {
				return nil, fmt.Errorf("add direct dependency %q: %w", parent.ID, err)
			}
		}
		for _, requirement := range pkg.Metadata.RequiresDist {
			dependencyName := requirementName(requirement)
			if dependencyName == "" {
				continue
			}
			child := nodesByName[dependencyName]
			if child == nil {
				continue
			}
			if err := depsGraph.AddDependency(parent.ID, child.ID); err != nil {
				return nil, fmt.Errorf("add dependency %q -> %q: %w", parent.ID, child.ID, err)
			}
		}
	}

	return depsGraph, nil
}

func requirementName(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	match := requirementNamePattern.FindString(trimmed)
	return normalizePythonName(match)
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

func addNodeIfMissing(depsGraph *sdk.Graph, node *sdk.Package) error {
	if _, ok := depsGraph.Package(node.ID); ok {
		return nil
	}
	if err := depsGraph.AddPackage(node); err != nil {
		return fmt.Errorf("add node %q: %w", node.ID, err)
	}
	return nil
}
