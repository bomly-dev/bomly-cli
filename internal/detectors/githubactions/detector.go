package githubactions

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/sdk"
	"gopkg.in/yaml.v3"
)

type workflowDocument struct {
	Jobs map[string]workflowJob `yaml:"jobs"`
}

type workflowJob struct {
	Uses  string         `yaml:"uses"`
	Steps []workflowStep `yaml:"steps"`
}

type workflowStep struct {
	Uses string `yaml:"uses"`
}

type actionDocument struct {
	Runs actionRuns `yaml:"runs"`
}

type actionRuns struct {
	Using string         `yaml:"using"`
	Steps []workflowStep `yaml:"steps"`
}

// Detector resolves GitHub Actions dependency graphs from workflow and action manifests.
type Detector struct{}

var evidencePatterns = []string{".github/workflows/*.yaml", ".github/workflows/*.yml", ".github/actions/*/action.yml", ".github/actions/*/action.yaml"}

// PackageManagerSupport returns GitHub Actions package-manager discovery metadata.
func (d Detector) PackageManagerSupport() []sdk.PackageManagerSupport {
	return []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerGitHubActions, evidencePatterns...)}
}

// Ready reports whether the detector can run in the current environment.
func (d Detector) Ready() bool {
	return true
}

// Applicable reports whether GitHub workflow or local action manifests are present.
func (d Detector) Applicable(ctx context.Context, req sdk.DetectionRequest) (bool, error) {
	_ = ctx
	workflowFiles, actionFiles, err := discoverManifestFiles(req.ProjectPath)
	if err != nil {
		return false, err
	}
	return len(workflowFiles) > 0 || len(actionFiles) > 0, nil
}

// Descriptor describes the GitHub Actions detector.
func (d Detector) Descriptor() sdk.DetectorDescriptor {
	return sdk.DetectorDescriptor{
		Name:                detectors.NameGitHubActions,
		Enabled:             true,
		Origin:              sdk.CoreOrigin,
		Technique:           sdk.ManifestTechnique,
		SupportedEcosystems: []sdk.Ecosystem{sdk.EcosystemGitHub},
		SupportedManagers:   []sdk.PackageManager{sdk.PackageManagerGitHubActions},
		SupportedModes:      []sdk.TargetMode{sdk.TargetModeFullGraph, sdk.TargetModeComponent},
		Capabilities:        []string{"graph-resolution", "component-targeting", "local-transitive-expansion"},
	}
}

// ResolveGraph resolves a GitHub Actions dependency graph from workflow and action manifests.
func (d Detector) ResolveGraph(_ context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	graphs, err := depGraphContainerFromRepository(req.ProjectPath)
	if err != nil {
		return sdk.DetectionResult{}, err
	}
	if graphs != nil {
		for i := range graphs.Entries {
			AttachWorkflowPositions(graphs.Entries[i].Graph, req.ProjectPath)
		}
	}
	return sdk.DetectionResult{
		Graphs: graphs,
	}, nil
}

func depGraphFromRepository(projectPath string) (*sdk.Graph, error) {
	container, err := depGraphContainerFromRepository(projectPath)
	if err != nil {
		return nil, err
	}
	return container.ConsolidatedGraph()
}

func depGraphContainerFromRepository(projectPath string) (*sdk.GraphContainer, error) {
	workflowFiles, actionFiles, err := discoverManifestFiles(projectPath)
	if err != nil {
		return nil, err
	}
	if len(workflowFiles) == 0 && len(actionFiles) == 0 {
		return nil, fmt.Errorf("no GitHub Actions manifests found")
	}

	depsGraph := sdk.New()
	workflowNodes := make(map[string]*sdk.Package, len(workflowFiles))
	actionNodes := make(map[string]*sdk.Package, len(actionFiles))

	for _, relPath := range workflowFiles {
		node := localWorkflowNode(relPath)
		workflowNodes[relPath] = node
		if err := addNodeIfMissing(depsGraph, node); err != nil {
			return nil, err
		}
	}
	for _, relManifestPath := range actionFiles {
		relActionPath := filepath.ToSlash(filepath.Dir(relManifestPath))
		node := localActionNode(relActionPath)
		actionNodes[relActionPath] = node
		if err := addNodeIfMissing(depsGraph, node); err != nil {
			return nil, err
		}
	}

	for _, relPath := range workflowFiles {
		refs, err := parseWorkflowRefs(filepath.Join(projectPath, filepath.FromSlash(relPath)))
		if err != nil {
			return nil, err
		}
		parent := workflowNodes[relPath]
		if err := addReferenceEdges(depsGraph, parent, relPath, refs, workflowNodes, actionNodes); err != nil {
			return nil, err
		}
	}
	for _, relManifestPath := range actionFiles {
		refs, err := parseActionRefs(filepath.Join(projectPath, filepath.FromSlash(relManifestPath)))
		if err != nil {
			return nil, err
		}
		parent := actionNodes[filepath.ToSlash(filepath.Dir(relManifestPath))]
		if err := addReferenceEdges(depsGraph, parent, relManifestPath, refs, workflowNodes, actionNodes); err != nil {
			return nil, err
		}
	}

	entries := make([]sdk.GraphEntry, 0, len(workflowFiles)+len(actionFiles))
	for _, relPath := range workflowFiles {
		rootID := localWorkflowNode(relPath).ID
		entryGraph, err := graphReachableFromRoot(depsGraph, rootID)
		if err != nil {
			return nil, err
		}
		entries = append(entries, sdk.GraphEntry{
			Graph: entryGraph,
			Manifest: sdk.ManifestMetadata{
				Path: relPath,
				Kind: "github-actions-workflow",
			},
		})
	}
	for _, relManifestPath := range actionFiles {
		relActionPath := filepath.ToSlash(filepath.Dir(relManifestPath))
		rootID := localActionNode(relActionPath).ID
		entryGraph, err := graphReachableFromRoot(depsGraph, rootID)
		if err != nil {
			return nil, err
		}
		entries = append(entries, sdk.GraphEntry{
			Graph: entryGraph,
			Manifest: sdk.ManifestMetadata{
				Path: relManifestPath,
				Kind: "github-actions-action",
			},
		})
	}

	return &sdk.GraphContainer{Entries: entries}, nil
}

func graphReachableFromRoot(source *sdk.Graph, rootID string) (*sdk.Graph, error) {
	root, ok := source.Package(rootID)
	if !ok {
		return nil, fmt.Errorf("github actions root %q not found", rootID)
	}
	out := sdk.New()
	if err := addNodeIfMissing(out, root.Clone()); err != nil {
		return nil, err
	}
	queue := []string{rootID}
	seen := map[string]struct{}{rootID: {}}
	for len(queue) > 0 {
		currentID := queue[0]
		queue = queue[1:]
		deps, err := source.Dependencies(currentID)
		if err != nil {
			return nil, err
		}
		for _, dep := range deps {
			if err := addNodeIfMissing(out, dep.Clone()); err != nil {
				return nil, err
			}
			if err := out.AddDependency(currentID, dep.ID); err != nil {
				return nil, err
			}
			if _, ok := seen[dep.ID]; ok {
				continue
			}
			seen[dep.ID] = struct{}{}
			queue = append(queue, dep.ID)
		}
	}
	return out, nil
}

func discoverManifestFiles(projectPath string) ([]string, []string, error) {
	workflowSet := make(map[string]struct{})
	for _, pattern := range []string{filepath.Join(projectPath, ".github", "workflows", "*.yml"), filepath.Join(projectPath, ".github", "workflows", "*.yaml")} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil, nil, err
		}
		for _, match := range matches {
			relPath, err := filepath.Rel(projectPath, match)
			if err != nil {
				return nil, nil, err
			}
			workflowSet[filepath.ToSlash(relPath)] = struct{}{}
		}
	}

	actionSet := make(map[string]struct{})
	actionsRoot := filepath.Join(projectPath, ".github", "actions")
	if info, err := os.Stat(actionsRoot); err == nil && info.IsDir() {
		walkErr := filepath.WalkDir(actionsRoot, func(candidate string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			name := strings.ToLower(entry.Name())
			if name != "action.yml" && name != "action.yaml" {
				return nil
			}
			relPath, err := filepath.Rel(projectPath, candidate)
			if err != nil {
				return err
			}
			actionSet[filepath.ToSlash(relPath)] = struct{}{}
			return nil
		})
		if walkErr != nil {
			return nil, nil, walkErr
		}
	}

	workflowFiles := setToSortedSlice(workflowSet)
	actionFiles := setToSortedSlice(actionSet)
	return workflowFiles, actionFiles, nil
}

func parseWorkflowRefs(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read workflow file %q: %w", path, err)
	}
	var document workflowDocument
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("parse workflow file %q: %w", path, err)
	}
	refs := make([]string, 0, 8)
	for _, job := range document.Jobs {
		if strings.TrimSpace(job.Uses) != "" {
			refs = append(refs, strings.TrimSpace(job.Uses))
		}
		for _, step := range job.Steps {
			if strings.TrimSpace(step.Uses) != "" {
				refs = append(refs, strings.TrimSpace(step.Uses))
			}
		}
	}
	return uniqueStrings(refs), nil
}

func parseActionRefs(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read action file %q: %w", path, err)
	}
	var document actionDocument
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("parse action file %q: %w", path, err)
	}
	refs := make([]string, 0, len(document.Runs.Steps))
	for _, step := range document.Runs.Steps {
		if strings.TrimSpace(step.Uses) != "" {
			refs = append(refs, strings.TrimSpace(step.Uses))
		}
	}
	return uniqueStrings(refs), nil
}

func addReferenceEdges(depsGraph *sdk.Graph, parent *sdk.Package, callerRelPath string, refs []string, workflowNodes map[string]*sdk.Package, actionNodes map[string]*sdk.Package) error {
	for _, ref := range refs {
		node, err := resolveReference(ref, callerRelPath, workflowNodes, actionNodes)
		if err != nil {
			return err
		}
		if node == nil {
			continue
		}
		if err := addNodeIfMissing(depsGraph, node); err != nil {
			return err
		}
		if err := depsGraph.AddDependency(parent.ID, node.ID); err != nil {
			return fmt.Errorf("add dependency %q -> %q: %w", parent.ID, node.ID, err)
		}
	}
	return nil
}

func resolveReference(ref, callerRelPath string, workflowNodes map[string]*sdk.Package, actionNodes map[string]*sdk.Package) (*sdk.Package, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, "docker://") {
		return nil, nil
	}
	if strings.HasPrefix(ref, "./") {
		for _, candidate := range localReferenceCandidates(ref, callerRelPath) {
			if workflowNode, ok := workflowNodes[candidate]; ok {
				return workflowNode, nil
			}
			if actionNode, ok := actionNodes[candidate]; ok {
				return actionNode, nil
			}
			for _, manifestName := range []string{"action.yml", "action.yaml"} {
				trimmed := strings.TrimSuffix(candidate, "/")
				if actionNode, ok := actionNodes[path.Join(trimmed)]; ok {
					return actionNode, nil
				}
				if actionNode, ok := actionNodes[path.Join(trimmed, strings.TrimSuffix(manifestName, filepath.Ext(manifestName)))]; ok {
					return actionNode, nil
				}
			}
		}
		return localActionNode(strings.TrimPrefix(filepath.ToSlash(filepath.Clean(strings.TrimPrefix(ref, "./"))), "./")), nil
	}

	name, version := splitVersionRef(ref)
	if name == "" {
		return nil, nil
	}
	org, packageName := splitExternalActionName(name)
	typeName := "action"
	if strings.Contains(name, ".github/workflows/") {
		typeName = "workflow"
	}
	return sdk.NewPackage(sdk.Package{
		Ecosystem:   string(sdk.EcosystemGitHub),
		Org:         org,
		Name:        packageName,
		Version:     version,
		Scope:       string(sdk.ScopeRuntime),
		BuildSystem: sdk.PackageManagerGitHubActions.Name(),
		Type:        typeName,
		Language:    "yaml",
	}), nil
}

func localReferenceCandidates(ref, callerRelPath string) []string {
	trimmed := strings.TrimPrefix(strings.TrimSpace(ref), "./")
	repoRelative := filepath.ToSlash(filepath.Clean(trimmed))
	callerRelative := filepath.ToSlash(filepath.Clean(filepath.Join(filepath.Dir(callerRelPath), trimmed)))
	return uniqueStrings([]string{repoRelative, callerRelative})
}

func splitVersionRef(ref string) (string, string) {
	idx := strings.LastIndex(ref, "@")
	if idx < 0 {
		return strings.TrimSpace(ref), ""
	}
	return strings.TrimSpace(ref[:idx]), strings.TrimSpace(ref[idx+1:])
}

func splitExternalActionName(value string) (string, string) {
	parts := strings.Split(strings.TrimSpace(value), "/")
	if len(parts) < 2 {
		return "", strings.TrimSpace(value)
	}
	return parts[0], strings.Join(parts[1:], "/")
}

func localWorkflowNode(relPath string) *sdk.Package {
	cleanPath := filepath.ToSlash(filepath.Clean(relPath))
	return sdk.NewPackageWithID("workflow:"+cleanPath, sdk.Package{
		Ecosystem:   string(sdk.EcosystemGitHub),
		Name:        cleanPath,
		Version:     "local",
		Scope:       string(sdk.ScopeRuntime),
		BuildSystem: sdk.PackageManagerGitHubActions.Name(),
		Type:        "workflow",
		Language:    "yaml",
	})
}

func localActionNode(relPath string) *sdk.Package {
	cleanPath := filepath.ToSlash(filepath.Clean(relPath))
	return sdk.NewPackageWithID("action:"+cleanPath, sdk.Package{
		Ecosystem:   string(sdk.EcosystemGitHub),
		Name:        cleanPath,
		Version:     "local",
		Scope:       string(sdk.ScopeRuntime),
		BuildSystem: sdk.PackageManagerGitHubActions.Name(),
		Type:        "action",
		Language:    "yaml",
	})
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

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func setToSortedSlice(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
