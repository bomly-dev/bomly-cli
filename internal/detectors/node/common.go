package node

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/logging"
	"github.com/bomly-dev/bomly-cli/internal/system"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// BaseDetector provides shared command execution behavior for Node package-manager detectors.
type BaseDetector struct {
	Logger     *zap.Logger
	WorkingDir string
}

// NPMListNode is the npm list JSON node shape used by npm CLI and v1 package-lock parsing.
type NPMListNode struct {
	Name         string                  `json:"name"`
	Version      string                  `json:"version"`
	Dependencies map[string]*NPMListNode `json:"dependencies"`
}

type pnpmListNode struct {
	Name         string                   `json:"name"`
	Version      string                   `json:"version"`
	Dependencies map[string]*pnpmListNode `json:"dependencies"`
}

type yarnListEvent struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

type yarnListTreeData struct {
	Trees []yarnTreeNode `json:"trees"`
}

type yarnTreeNode struct {
	Name     string         `json:"name"`
	Children []yarnTreeNode `json:"children"`
}

// ProjectDir returns the configured working directory or falls back to the project path.
func (d BaseDetector) ProjectDir(projectPath string) string {
	if d.WorkingDir != "" {
		return d.WorkingDir
	}
	return projectPath
}

// ResolveGraph runs a package-manager CLI command and maps its JSON output into a graph.
func (d BaseDetector) ResolveGraph(stderr io.Writer, projectPath string, verbose bool, executable string, args []string, detectorName string, parse func([]byte) (*sdk.Graph, error)) (*sdk.Graph, error) {
	logger := d.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	cmd := system.Command(executable, args...)
	cmd.Dir = d.ProjectDir(projectPath)
	var out bytes.Buffer
	cmd.Stdout = &out
	commandStderr := logging.NewCommandStderr(stderr, verbose)
	cmd.Stderr = commandStderr

	started := time.Now()
	logger.Debug("running external dependency detector", zap.String("detector", detectorName), zap.String("working_dir", cmd.Dir), zap.String("executable", executable), zap.Strings("args", args))
	if err := cmd.Run(); err != nil {
		logger.Warn(fmt.Sprintf("%s failed: %v", detectorName, err))
		fields := []zap.Field{zap.Error(err), zap.String("detector", detectorName)}
		if commandStderr.String() != "" {
			fields = append(fields, zap.String("stderr", commandStderr.String()))
		}
		logger.Debug("external dependency detector failure details", fields...)
		return nil, fmt.Errorf("run %s: %w", detectorName, err)
	}

	depsGraph, err := parse(out.Bytes())
	if err != nil {
		logger.Warn(fmt.Sprintf("Failed to map %s output to a dependency graph: %v", detectorName, err))
		logger.Debug("dependency detector output mapping failed", zap.String("detector", detectorName), zap.Error(err))
		return nil, err
	}

	logger.Info(fmt.Sprintf("%s found %d dependencies in %s", detectorName, depsGraph.Size(), logging.FormatDuration(time.Since(started))))
	return depsGraph, nil
}

// Install runs a package-manager install command for detectors that support install-first.
func (d BaseDetector) Install(ctx context.Context, req sdk.DetectionRequest, executable string, defaultArgs []string, detectorName string) error {
	logger := d.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	args := append(append([]string{}, defaultArgs...), req.InstallArgs...)
	_ = ctx
	cmd := system.Command(executable, args...)
	cmd.Dir = d.ProjectDir(req.ProjectPath)
	commandStderr := logging.NewCommandStderr(req.Stderr, req.Verbose)
	cmd.Stderr = commandStderr
	started := time.Now()
	logger.Info(fmt.Sprintf("%s running install-first step", detectorName))
	logger.Debug("running detector install-first", zap.String("detector", detectorName), zap.String("working_dir", cmd.Dir), zap.String("executable", executable), zap.Strings("args", args))
	if err := cmd.Run(); err != nil {
		fields := []zap.Field{zap.Error(err)}
		if commandStderr.String() != "" {
			fields = append(fields, zap.String("stderr", commandStderr.String()))
		}
		logger.Debug("detector install-first failure details", fields...)
		return fmt.Errorf("run %s install step: %w", detectorName, err)
	}
	logger.Info(fmt.Sprintf("%s install-first completed in %s", detectorName, logging.FormatDuration(time.Since(started))))
	return nil
}

// DepGraphFromNPMJSON maps npm list JSON output into a dependency graph.
func DepGraphFromNPMJSON(raw []byte) (*sdk.Graph, error) {
	var root NPMListNode
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("parse npm json: %w", err)
	}
	return DepGraphFromNPMNode(&root)
}

// DepGraphFromNPMNode maps a npm dependency tree node into a dependency graph.
func DepGraphFromNPMNode(root *NPMListNode) (*sdk.Graph, error) {
	if root == nil {
		return nil, errors.New("npm root node is nil")
	}

	depsGraph := sdk.New()
	rootName := root.Name
	if rootName == "" {
		rootName = "root"
	}
	rootNode := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemNPM,
		Name:    rootName,
		Version: root.Version,
		Type:    sdk.PackageTypeApplication, FirstParty: true},
	})

	if err := depsGraph.AddNode(rootNode); err != nil {
		return nil, fmt.Errorf("add root node: %w", err)
	}

	type frame struct {
		parentID string
		deps     map[string]*NPMListNode
	}
	stack := []frame{{parentID: rootNode.ID, deps: root.Dependencies}}
	for len(stack) > 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		for depName, depNode := range current.deps {
			if depNode == nil {
				continue
			}
			name := depNode.Name
			if name == "" {
				name = depName
			}
			node := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemNPM,
				Name:    name,
				Version: depNode.Version},
			})

			if err := AddNodeIfMissing(depsGraph, node); err != nil {
				return nil, err
			}
			if err := depsGraph.AddEdge(current.parentID, node.ID); err != nil {
				return nil, fmt.Errorf("add dependency %q -> %q: %w", current.parentID, node.ID, err)
			}
			if len(depNode.Dependencies) > 0 {
				stack = append(stack, frame{parentID: node.ID, deps: depNode.Dependencies})
			}
		}
	}

	return depsGraph, nil
}

// DepGraphFromPNPMJSON maps pnpm list JSON output into a dependency graph.
func DepGraphFromPNPMJSON(raw []byte) (*sdk.Graph, error) {
	var roots []pnpmListNode
	if err := json.Unmarshal(raw, &roots); err != nil {
		return nil, fmt.Errorf("parse pnpm json: %w", err)
	}
	if len(roots) == 0 {
		return nil, errors.New("pnpm output is empty")
	}

	depsGraph := sdk.New()
	for _, root := range roots {
		rootNode := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemNPM,
			Name:    root.Name,
			Version: root.Version,
			Type:    sdk.PackageTypeApplication, FirstParty: true},
		})

		if err := AddNodeIfMissing(depsGraph, rootNode); err != nil {
			return nil, err
		}
		if err := addPNPMDependencies(depsGraph, rootNode.ID, root.Dependencies); err != nil {
			return nil, err
		}
	}
	return depsGraph, nil
}

func addPNPMDependencies(depsGraph *sdk.Graph, parentID string, deps map[string]*pnpmListNode) error {
	for depName, depNode := range deps {
		if depNode == nil {
			continue
		}
		name := depNode.Name
		if name == "" {
			name = depName
		}
		node := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemNPM,
			Name:    name,
			Version: depNode.Version},
		})

		if err := AddNodeIfMissing(depsGraph, node); err != nil {
			return err
		}
		if err := depsGraph.AddEdge(parentID, node.ID); err != nil {
			return fmt.Errorf("add dependency %q -> %q: %w", parentID, node.ID, err)
		}
		if err := addPNPMDependencies(depsGraph, node.ID, depNode.Dependencies); err != nil {
			return err
		}
	}
	return nil
}

// DepGraphFromYarnJSON maps Yarn list JSON output into a dependency graph.
func DepGraphFromYarnJSON(raw []byte) (*sdk.Graph, error) {
	events := bytes.Split(raw, []byte{'\n'})
	var treeData yarnListTreeData
	for _, line := range events {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var event yarnListEvent
		if err := json.Unmarshal(line, &event); err != nil {
			continue
		}
		if event.Type != "tree" {
			continue
		}
		if err := json.Unmarshal(event.Data, &treeData); err != nil {
			return nil, fmt.Errorf("parse yarn tree event: %w", err)
		}
		break
	}
	if len(treeData.Trees) == 0 {
		return nil, errors.New("yarn tree output is empty")
	}

	depsGraph := sdk.New()
	rootNode := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemNPM,
		Name: "root",
		Type: sdk.PackageTypeApplication, FirstParty: true},
	})

	if err := depsGraph.AddNode(rootNode); err != nil {
		return nil, fmt.Errorf("add root node: %w", err)
	}
	for _, tree := range treeData.Trees {
		if err := addYarnTree(depsGraph, rootNode.ID, tree); err != nil {
			return nil, err
		}
	}
	return depsGraph, nil
}

func addYarnTree(depsGraph *sdk.Graph, parentID string, tree yarnTreeNode) error {
	name, version, err := splitYarnTreeName(tree.Name)
	if err != nil {
		return err
	}
	node := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemNPM,
		Name:    name,
		Version: version},
	})

	if err := AddNodeIfMissing(depsGraph, node); err != nil {
		return err
	}
	if err := depsGraph.AddEdge(parentID, node.ID); err != nil {
		return fmt.Errorf("add dependency %q -> %q: %w", parentID, node.ID, err)
	}
	for _, child := range tree.Children {
		if err := addYarnTree(depsGraph, node.ID, child); err != nil {
			return err
		}
	}
	return nil
}

func splitYarnTreeName(value string) (string, string, error) {
	idx := bytes.LastIndexByte([]byte(value), '@')
	if idx <= 0 {
		return value, "", nil
	}
	return value[:idx], value[idx+1:], nil
}

// AddNodeIfMissing adds a package to a graph or merges scope into the existing package.
func AddNodeIfMissing(depsGraph *sdk.Graph, node *sdk.Dependency) error {
	if existing, ok := depsGraph.Node(node.ID); ok {
		existing.AddScope(node.PrimaryScope())
		return nil
	}
	if err := depsGraph.AddNode(node); err != nil {
		return fmt.Errorf("add node %q: %w", node.ID, err)
	}
	return nil
}

// PackageJSONManifest is the subset of package.json used by Node detectors.
type PackageJSONManifest struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
}

// AnnotateScopesFromPackageJSON annotates graph packages using direct dependency scopes from package.json.
func AnnotateScopesFromPackageJSON(projectPath string, depsGraph *sdk.Graph) error {
	if depsGraph == nil {
		return nil
	}

	data, err := os.ReadFile(filepath.Join(projectPath, "package.json"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read package.json: %w", err)
	}

	var manifest PackageJSONManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return fmt.Errorf("parse package.json: %w", err)
	}

	directScopes := make(map[string]sdk.Scope, len(manifest.Dependencies)+len(manifest.OptionalDependencies)+len(manifest.PeerDependencies)+len(manifest.DevDependencies))
	recordDirectScopes(directScopes, manifest.Dependencies, sdk.ScopeRuntime)
	recordDirectScopes(directScopes, manifest.OptionalDependencies, sdk.ScopeRuntime)
	recordDirectScopes(directScopes, manifest.PeerDependencies, sdk.ScopeRuntime)
	recordDirectScopes(directScopes, manifest.DevDependencies, sdk.ScopeDevelopment)

	rootID := ""
	for _, root := range depsGraph.Roots() {
		if root != nil {
			rootID = root.ID
			break
		}
	}
	if rootID == "" {
		return nil
	}

	propagateScopesFromRootDependencies(depsGraph, rootID, directScopes)
	return nil
}

func recordDirectScopes(target map[string]sdk.Scope, dependencies map[string]string, scope sdk.Scope) {
	for name := range dependencies {
		key := name
		if _, ok := target[key]; ok {
			target[key] = sdk.MergeScope(target[key], scope)
			continue
		}
		target[key] = scope
	}
}

func propagateScopesFromRootDependencies(depsGraph *sdk.Graph, rootID string, directScopes map[string]sdk.Scope) {
	rootDeps, err := depsGraph.DirectDependencies(rootID)
	if err != nil {
		return
	}

	queue := make([]*sdk.Dependency, 0, len(rootDeps))
	propagated := make(map[string]sdk.Scope, depsGraph.Size())
	for _, dep := range rootDeps {
		if dep == nil {
			continue
		}
		scope, ok := directScopes[dep.Name]
		if !ok {
			scope, ok = directScopes[dep.QualifiedName()]
		}
		if !ok || scope == sdk.ScopeUnknown {
			continue
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
			if child == nil {
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
}

// ApplyDirectDependencyScopes annotates direct root dependencies and their
// transitive dependencies with normalized scopes.
func ApplyDirectDependencyScopes(depsGraph *sdk.Graph, rootID string, directScopes map[string]sdk.Scope) {
	if depsGraph == nil || rootID == "" || len(directScopes) == 0 {
		return
	}
	propagateScopesFromRootDependencies(depsGraph, rootID, directScopes)
}

// DirectDependencyScopes builds direct dependency scopes from package.json dependency maps.
func DirectDependencyScopes(manifest PackageJSONManifest) map[string]sdk.Scope {
	directScopes := make(map[string]sdk.Scope, len(manifest.Dependencies)+len(manifest.OptionalDependencies)+len(manifest.PeerDependencies)+len(manifest.DevDependencies))
	recordDirectScopes(directScopes, manifest.Dependencies, sdk.ScopeRuntime)
	recordDirectScopes(directScopes, manifest.OptionalDependencies, sdk.ScopeRuntime)
	recordDirectScopes(directScopes, manifest.PeerDependencies, sdk.ScopeRuntime)
	recordDirectScopes(directScopes, manifest.DevDependencies, sdk.ScopeDevelopment)
	return directScopes
}
