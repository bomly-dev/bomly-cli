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

	"github.com/bomly/bomly-cli/internal/detectors"
	"github.com/bomly/bomly-cli/internal/logging"
	"github.com/bomly/bomly-cli/internal/model"
	"github.com/bomly/bomly-cli/pkg/system"
	"go.uber.org/zap"
)

type baseDetector struct {
	Logger     *zap.Logger
	WorkingDir string
}

type npmLSNode struct {
	Name         string                `json:"name"`
	Version      string                `json:"version"`
	Dependencies map[string]*npmLSNode `json:"dependencies"`
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

func (d baseDetector) workingDir(projectPath string) string {
	if d.WorkingDir != "" {
		return d.WorkingDir
	}
	return projectPath
}

func (d baseDetector) resolveGraph(stderr io.Writer, projectPath string, verbose bool, executable string, args []string, detectorName string, parse func([]byte) (*model.Graph, error)) (*model.Graph, error) {
	logger := d.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	cmd := system.Command(executable, args...)
	cmd.Dir = d.workingDir(projectPath)
	var out bytes.Buffer
	cmd.Stdout = &out
	commandStderr := logging.NewCommandStderr(stderr, verbose)
	cmd.Stderr = commandStderr

	started := time.Now()
	logger.Debug("running external dependency detector", zap.String("detector", detectorName), zap.String("working_dir", cmd.Dir), zap.String("executable", executable), zap.Strings("args", args))
	if err := cmd.Run(); err != nil {
		logger.Error(fmt.Sprintf("%s failed: %v", detectorName, err))
		fields := []zap.Field{zap.Error(err), zap.String("detector", detectorName)}
		if commandStderr.String() != "" {
			fields = append(fields, zap.String("stderr", commandStderr.String()))
		}
		logger.Debug("external dependency detector failure details", fields...)
		return nil, fmt.Errorf("run %s: %w", detectorName, err)
	}

	depsGraph, err := parse(out.Bytes())
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to map %s output to a dependency graph: %v", detectorName, err))
		logger.Debug("dependency detector output mapping failed", zap.String("detector", detectorName), zap.Error(err))
		return nil, err
	}

	logger.Info(fmt.Sprintf("%s found %d dependencies in %s", detectorName, depsGraph.Size(), logging.FormatDuration(time.Since(started))))
	return depsGraph, nil
}

func (d baseDetector) install(ctx context.Context, req detectors.ResolveGraphRequest, executable string, defaultArgs []string, detectorName string) error {
	logger := d.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	args := append(append([]string{}, defaultArgs...), req.InstallArgs...)
	_ = ctx
	cmd := system.Command(executable, args...)
	cmd.Dir = d.workingDir(req.ProjectPath)
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

func depGraphFromNPMJSON(raw []byte) (*model.Graph, error) {
	var root npmLSNode
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("parse npm json: %w", err)
	}
	return depGraphFromNPMNode(&root)
}

func depGraphFromNPMNode(root *npmLSNode) (*model.Graph, error) {
	if root == nil {
		return nil, errors.New("npm root node is nil")
	}

	depsGraph := model.New()
	rootName := root.Name
	if rootName == "" {
		rootName = "root"
	}
	rootNode := model.NewPackage(model.Package{
		Ecosystem: string(detectors.EcosystemNPM),
		Name:      rootName,
		Version:   root.Version,
	})
	if err := depsGraph.AddPackage(rootNode); err != nil {
		return nil, fmt.Errorf("add root node: %w", err)
	}

	type frame struct {
		parentID string
		deps     map[string]*npmLSNode
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
			node := model.NewPackage(model.Package{
				Ecosystem: string(detectors.EcosystemNPM),
				Name:      name,
				Version:   depNode.Version,
			})
			if err := addNodeIfMissing(depsGraph, node); err != nil {
				return nil, err
			}
			if err := depsGraph.AddDependency(current.parentID, node.ID); err != nil {
				return nil, fmt.Errorf("add dependency %q -> %q: %w", current.parentID, node.ID, err)
			}
			if len(depNode.Dependencies) > 0 {
				stack = append(stack, frame{parentID: node.ID, deps: depNode.Dependencies})
			}
		}
	}

	return depsGraph, nil
}

func depGraphFromPNPMJSON(raw []byte) (*model.Graph, error) {
	var roots []pnpmListNode
	if err := json.Unmarshal(raw, &roots); err != nil {
		return nil, fmt.Errorf("parse pnpm json: %w", err)
	}
	if len(roots) == 0 {
		return nil, errors.New("pnpm output is empty")
	}

	depsGraph := model.New()
	for _, root := range roots {
		rootNode := model.NewPackage(model.Package{
			Ecosystem: string(detectors.EcosystemNPM),
			Name:      root.Name,
			Version:   root.Version,
		})
		if err := addNodeIfMissing(depsGraph, rootNode); err != nil {
			return nil, err
		}
		if err := addPNPMDependencies(depsGraph, rootNode.ID, root.Dependencies); err != nil {
			return nil, err
		}
	}
	return depsGraph, nil
}

func addPNPMDependencies(depsGraph *model.Graph, parentID string, deps map[string]*pnpmListNode) error {
	for depName, depNode := range deps {
		if depNode == nil {
			continue
		}
		name := depNode.Name
		if name == "" {
			name = depName
		}
		node := model.NewPackage(model.Package{
			Ecosystem: string(detectors.EcosystemNPM),
			Name:      name,
			Version:   depNode.Version,
		})
		if err := addNodeIfMissing(depsGraph, node); err != nil {
			return err
		}
		if err := depsGraph.AddDependency(parentID, node.ID); err != nil {
			return fmt.Errorf("add dependency %q -> %q: %w", parentID, node.ID, err)
		}
		if err := addPNPMDependencies(depsGraph, node.ID, depNode.Dependencies); err != nil {
			return err
		}
	}
	return nil
}

func depGraphFromYarnJSON(raw []byte) (*model.Graph, error) {
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

	depsGraph := model.New()
	rootNode := model.NewPackage(model.Package{
		Ecosystem: string(detectors.EcosystemNPM),
		Name:      "root",
	})
	if err := depsGraph.AddPackage(rootNode); err != nil {
		return nil, fmt.Errorf("add root node: %w", err)
	}
	for _, tree := range treeData.Trees {
		if err := addYarnTree(depsGraph, rootNode.ID, tree); err != nil {
			return nil, err
		}
	}
	return depsGraph, nil
}

func addYarnTree(depsGraph *model.Graph, parentID string, tree yarnTreeNode) error {
	name, version, err := splitYarnTreeName(tree.Name)
	if err != nil {
		return err
	}
	node := model.NewPackage(model.Package{
		Ecosystem: string(detectors.EcosystemNPM),
		Name:      name,
		Version:   version,
	})
	if err := addNodeIfMissing(depsGraph, node); err != nil {
		return err
	}
	if err := depsGraph.AddDependency(parentID, node.ID); err != nil {
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

func addNodeIfMissing(depsGraph *model.Graph, node *model.Package) error {
	if existing, ok := depsGraph.Package(node.ID); ok {
		detectors.MergePackageScope(existing, detectors.Scope(node.Scope))
		return nil
	}
	if err := depsGraph.AddPackage(node); err != nil {
		return fmt.Errorf("add node %q: %w", node.ID, err)
	}
	return nil
}

type packageJSONManifest struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
}

func annotateScopesFromPackageJSON(projectPath string, depsGraph *model.Graph) error {
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

	var manifest packageJSONManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return fmt.Errorf("parse package.json: %w", err)
	}

	directScopes := make(map[string]detectors.Scope, len(manifest.Dependencies)+len(manifest.OptionalDependencies)+len(manifest.PeerDependencies)+len(manifest.DevDependencies))
	recordDirectScopes(directScopes, manifest.Dependencies, detectors.ScopeRuntime)
	recordDirectScopes(directScopes, manifest.OptionalDependencies, detectors.ScopeRuntime)
	recordDirectScopes(directScopes, manifest.PeerDependencies, detectors.ScopeRuntime)
	recordDirectScopes(directScopes, manifest.DevDependencies, detectors.ScopeDevelopment)

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

func recordDirectScopes(target map[string]detectors.Scope, dependencies map[string]string, scope detectors.Scope) {
	for name := range dependencies {
		key := name
		if _, ok := target[key]; ok {
			target[key] = detectors.MergeScope(target[key], scope)
			continue
		}
		target[key] = scope
	}
}

func propagateScopesFromRootDependencies(depsGraph *model.Graph, rootID string, directScopes map[string]detectors.Scope) {
	rootDeps, err := depsGraph.Dependencies(rootID)
	if err != nil {
		return
	}

	queue := make([]*model.Package, 0, len(rootDeps))
	propagated := make(map[string]detectors.Scope, depsGraph.Size())
	for _, dep := range rootDeps {
		if dep == nil {
			continue
		}
		scope, ok := directScopes[dep.Name]
		if !ok {
			scope, ok = directScopes[dep.QualifiedName()]
		}
		if !ok || scope == detectors.ScopeUnknown {
			continue
		}
		detectors.MergePackageScope(dep, scope)
		propagated[dep.ID] = detectors.MergeScope(propagated[dep.ID], scope)
		queue = append(queue, dep)
	}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		scope := propagated[current.ID]
		if scope == detectors.ScopeUnknown {
			continue
		}

		children, err := depsGraph.Dependencies(current.ID)
		if err != nil {
			continue
		}
		for _, child := range children {
			if child == nil {
				continue
			}
			nextScope := detectors.MergeScope(propagated[child.ID], scope)
			if nextScope == propagated[child.ID] && detectors.Scope(child.Scope) == nextScope {
				continue
			}
			propagated[child.ID] = nextScope
			detectors.MergePackageScope(child, nextScope)
			queue = append(queue, child)
		}
	}
}
