package githubactions

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-sdk/detectorkit"
	"github.com/bomly-dev/bomly-sdk/system"
	"gopkg.in/yaml.v3"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
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
func (d Detector) PackageManagerSupport() []plugin.PackageManagerSupport {
	return []plugin.PackageManagerSupport{plugin.Support(model.PackageManagerGitHubActions, evidencePatterns...)}
}

// Ready reports whether the detector can run in the current environment.
func (d Detector) Ready(context.Context, plugin.DetectionRequest) error {
	return nil
}

// Applicable reports whether GitHub workflow or local action manifests are present.
func (d Detector) Applicable(ctx context.Context, req plugin.DetectionRequest) (bool, error) {
	_ = ctx
	workflowFiles, actionFiles, err := discoverManifestFiles(req.ProjectPath)
	if err != nil {
		return false, err
	}
	return len(workflowFiles) > 0 || len(actionFiles) > 0, nil
}

// Descriptor describes the GitHub Actions detector.
func (d Detector) Descriptor() plugin.DetectorDescriptor {
	return plugin.DetectorDescriptor{
		Name:                detectors.NameGitHubActions,
		Technique:           plugin.ManifestTechnique,
		SupportedEcosystems: []model.Ecosystem{model.EcosystemGitHub},
		SupportedManagers:   []model.PackageManager{model.PackageManagerGitHubActions},
		Tags:                []string{"graph-resolution", "component-targeting", "local-transitive-expansion"},
	}
}

// ResolveGraph resolves a GitHub Actions dependency graph from workflow and action manifests.
func (d Detector) ResolveGraph(_ context.Context, req plugin.DetectionRequest) (plugin.DetectionResult, error) {
	graphs, err := depGraphContainerFromRepository(req.ProjectPath, originHost(req.ExecutionTarget))
	if err != nil {
		return plugin.DetectionResult{}, err
	}
	if graphs != nil {
		for i := range graphs.Entries {
			AttachWorkflowPositions(graphs.Entries[i].Graph, req.ProjectPath)
		}
	}
	// Returned through detectors.Unattributed rather than Attributed: a
	// workflow is not a module. Its root is the workflow file itself, so the
	// only "module root" available would be ".github/workflows", a directory
	// that declares no module and would be an invented join key. An empty
	// module root says what is true here -- nobody attributed these sites.
	return detectors.Unattributed(plugin.DetectionResult{
		Graphs: graphs,
	}, "a workflow file is not a module; there is no module root to attribute its sites to"), nil
}

// githubHost is the host every "uses: owner/repo@ref" reference resolves
// against when the scanned repository is not known to live elsewhere.
const githubHost = "github.com"

// originHost is the host an external reference's origin is published on,
// or "" when none is: the GitHub instance the scanned repository lives on
// decides where "owner/repo@ref" resolves, and only github.com is a
// resolution Bomly can state.
//
// A GitHub Enterprise Server or GHE.com instance looks the repository up on
// the instance first and, when configured, falls back to github.com for a
// repository the instance does not hold (GitHub Connect). Which of the two
// a reference resolved to is not knowable from the workflow file, so for a
// repository scanned from such a host the origin is omitted rather than
// guessed. A filesystem scan carries no host at all and is taken to be
// github.com, which is what the package URL type already asserts.
func originHost(target plugin.ExecutionTarget) string {
	if target.Kind != plugin.ExecutionTargetGitRepository {
		return githubHost
	}
	repository := strings.TrimSpace(target.RepositoryURL)
	if repository == "" {
		return githubHost
	}
	host := repositoryHost(repository)
	if host == githubHost || host == "www."+githubHost {
		return githubHost
	}
	return ""
}

// repositoryHost extracts the lowercase host of a clone URL, accepting the
// two forms --url hands to git clone unchanged: a scheme URL, and Git's
// scp-like "[user@]host:path" form, whose user is optional. Anything else
// yields "".
func repositoryHost(repository string) string {
	if strings.Contains(repository, "://") {
		parsed, err := url.Parse(repository)
		if err != nil || parsed.Host == "" {
			return ""
		}
		return strings.ToLower(parsed.Hostname())
	}
	// No scheme, so the form is scp-like and split by hand: url.Parse reads
	// "github.com:owner/repo.git" as a URL whose scheme is "github.com" and
	// fails outright on "git@github.com:owner/repo.git".
	host, _, found := strings.Cut(repository, ":")
	if !found {
		return ""
	}
	if at := strings.LastIndex(host, "@"); at >= 0 {
		host = host[at+1:]
	}
	if host == "" || strings.ContainsAny(host, "/\\ ") {
		return ""
	}
	return strings.ToLower(host)
}

// depGraphFromRepository resolves the repository's manifests into one
// consolidated graph, publishing origins on github.com.
func depGraphFromRepository(projectPath string) (*model.Graph, error) {
	container, err := depGraphContainerFromRepository(projectPath, githubHost)
	if err != nil {
		return nil, err
	}
	return container.ConsolidatedGraph()
}

// depGraphContainerFromRepository resolves every workflow and action
// manifest under projectPath. host is where external references publish
// their origin, or "" to publish none; see originHost.
func depGraphContainerFromRepository(projectPath, host string) (*model.GraphContainer, error) {
	workflowFiles, actionFiles, err := discoverManifestFiles(projectPath)
	if err != nil {
		return nil, err
	}
	if len(workflowFiles) == 0 && len(actionFiles) == 0 {
		return nil, fmt.Errorf("no GitHub Actions manifests found")
	}

	depsGraph := model.New()
	workflowNodes := make(map[string]*model.DependencyNode, len(workflowFiles))
	actionNodes := make(map[string]*model.DependencyNode, len(actionFiles))

	for _, relPath := range workflowFiles {
		node, err := localWorkflowNode(relPath)
		if err != nil {
			return nil, err
		}
		node.Digests = manifestFileDigests(projectPath, relPath)
		workflowNodes[relPath] = node
		if err := addNodeIfMissing(depsGraph, node); err != nil {
			return nil, err
		}
	}
	for _, relManifestPath := range actionFiles {
		relActionPath := filepath.ToSlash(filepath.Dir(relManifestPath))
		node, err := localActionNode(relActionPath)
		if err != nil {
			return nil, err
		}
		node.Digests = manifestFileDigests(projectPath, relManifestPath)
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
		if err := addReferenceEdges(depsGraph, parent, relPath, refs, host, workflowNodes, actionNodes); err != nil {
			return nil, err
		}
	}
	for _, relManifestPath := range actionFiles {
		refs, err := parseActionRefs(filepath.Join(projectPath, filepath.FromSlash(relManifestPath)))
		if err != nil {
			return nil, err
		}
		parent := actionNodes[filepath.ToSlash(filepath.Dir(relManifestPath))]
		if err := addReferenceEdges(depsGraph, parent, relManifestPath, refs, host, workflowNodes, actionNodes); err != nil {
			return nil, err
		}
	}

	entries := make([]model.GraphEntry, 0, len(workflowFiles)+len(actionFiles))
	for _, relPath := range workflowFiles {
		rootNode, err := localWorkflowNode(relPath)
		if err != nil {
			return nil, err
		}
		rootID := rootNode.NodeID()
		entryGraph, err := graphReachableFromRoot(depsGraph, rootID)
		if err != nil {
			return nil, err
		}
		entries = append(entries, model.GraphEntry{
			Graph: entryGraph,
			Manifest: model.ManifestMetadata{
				Path: relPath,
				Kind: "github-actions-workflow",
			},
		})
	}
	for _, relManifestPath := range actionFiles {
		relActionPath := filepath.ToSlash(filepath.Dir(relManifestPath))
		actionRoot, err := localActionNode(relActionPath)
		if err != nil {
			return nil, err
		}
		rootID := actionRoot.NodeID()
		entryGraph, err := graphReachableFromRoot(depsGraph, rootID)
		if err != nil {
			return nil, err
		}
		entries = append(entries, model.GraphEntry{
			Graph: entryGraph,
			Manifest: model.ManifestMetadata{
				Path: relManifestPath,
				Kind: "github-actions-action",
			},
		})
	}

	return &model.GraphContainer{Entries: entries}, nil
}

func graphReachableFromRoot(source *model.Graph, rootID string) (*model.Graph, error) {
	root, ok := source.Node(rootID)
	if !ok {
		return nil, fmt.Errorf("github actions root %q not found", rootID)
	}
	out := model.New()
	if _, err := out.InsertNode(root.CloneNode()); err != nil {
		return nil, err
	}
	queue := []string{rootID}
	seen := map[string]struct{}{rootID: {}}
	for len(queue) > 0 {
		currentID := queue[0]
		queue = queue[1:]
		depsNodes, err := source.DirectDependencies(currentID)
		deps := model.DependencyNodesOf(depsNodes)
		if err != nil {
			return nil, err
		}
		for _, dep := range deps {
			if _, err := out.InsertNode(dep.CloneNode()); err != nil {
				return nil, err
			}
			if err := out.AddEdge(currentID, dep.NodeID()); err != nil {
				return nil, err
			}
			if _, ok := seen[dep.NodeID()]; ok {
				continue
			}
			seen[dep.NodeID()] = struct{}{}
			queue = append(queue, dep.NodeID())
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
	data, err := system.ReadRepositoryFile(path)
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
	data, err := system.ReadRepositoryFile(path)
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

// addReferenceEdges resolves each "uses:" reference a manifest makes and
// links the manifest's node to the node the reference names; see
// resolveReference for what each reference becomes.
func addReferenceEdges(depsGraph *model.Graph, parent *model.DependencyNode, callerRelPath string, refs []string, host string, workflowNodes map[string]*model.DependencyNode, actionNodes map[string]*model.DependencyNode) error {
	for _, ref := range refs {
		node, err := resolveReference(ref, callerRelPath, host, workflowNodes, actionNodes)
		if err != nil {
			return err
		}
		if node == nil {
			continue
		}
		if err := addNodeIfMissing(depsGraph, node); err != nil {
			return err
		}
		if err := depsGraph.AddEdge(parent.NodeID(), node.NodeID()); err != nil {
			return fmt.Errorf("add dependency %q -> %q: %w", parent.NodeID(), node.NodeID(), err)
		}
	}
	return nil
}

// resolveReference turns one "uses:" value into the node it depends on: a
// Docker image reference is not a GitHub Actions dependency and yields nil,
// a local reference resolves to the workflow or action node already built
// for that path, and an external "owner/repo[/path]@ref" reference becomes
// a dependency node carrying its origin on host (none when host is empty)
// and, for a SHA-pinned ref, the commit as a SHA-1 digest.
func resolveReference(ref, callerRelPath, host string, workflowNodes map[string]*model.DependencyNode, actionNodes map[string]*model.DependencyNode) (*model.DependencyNode, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, "docker://") {
		return nil, nil
	}
	if localPath, rootOnly, isLocal := localReferencePath(ref); isLocal {
		for _, candidate := range localReferenceCandidates(localPath, callerRelPath, rootOnly) {
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
		return localActionNode(strings.TrimPrefix(filepath.ToSlash(filepath.Clean(localPath)), "./"))
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
	node, err := model.NewDependencyNode(model.Coordinates{Ecosystem: model.EcosystemGitHub,
		Org:     org,
		Name:    packageName,
		Version: version,

		PackageManager: model.PackageManagerGitHubActions,
		Type:           model.ParsePackageType(typeName),
		Language:       "yaml"})
	if err != nil {
		return nil, fmt.Errorf("build dependency node: %w", err)
	}
	node.Scopes = model.ScopesOf(model.ScopeRuntime)
	// Where the reference resolves from: the repository the first two path
	// segments name, at the ref written after "@". This is the identity the
	// formats keep for version-controlled sources -- the SPDX 2.3 download
	// location in its "git+<url>@<revision>" form, a CycloneDX vcs reference
	// -- and it is recorded for every external reference, tag- or
	// branch-pinned ones included, because the ref is what the manifest
	// said even when it is not a commit (issue #508).
	if origin := model.RepositoryOrigin(actionRepositoryURL(host, org, packageName), version); origin != nil {
		node.Origins = model.MergeOrigins(node.Origins, []model.DependencyOrigin{*origin})
	}
	// A SHA-pinned ref is also the Git object ID of the pinned commit, and a
	// Git object ID is a SHA-1, so it is published as one: the CycloneDX
	// hashes[].alg and SPDX checksum vocabularies both have that member, and
	// relabelling it would misstate what was computed. It stays beside the
	// origin rather than replacing it, since a consumer that verifies pins
	// reads the hash and one that follows sources reads the locator.
	if isGitCommitSHA(version) {
		node.Digests = []model.Digest{{Algorithm: model.DigestAlgorithmSHA1, Value: strings.ToLower(version)}}
	}
	return node, nil
}

// localReferencePath reports whether a "uses:" value names a path inside
// the scanned repository, and returns that path without its marker. Two
// spellings mean this: "./path", which resolves against the checked-out
// tree, and "$/path", the self-repository form that resolves against the
// workflow's own repository at the running commit. Neither names another
// repository, so neither gets an external identity or an origin. rootOnly
// is true for the "$/" form, which GitHub defines against the repository
// root alone; the caller-relative reading the "./" form is also given is
// not part of its definition.
func localReferencePath(ref string) (path string, rootOnly bool, isLocal bool) {
	switch {
	case strings.HasPrefix(ref, "$/"):
		return strings.TrimPrefix(ref, "$/"), true, true
	case strings.HasPrefix(ref, "./"):
		return strings.TrimPrefix(ref, "./"), false, true
	}
	return "", false, false
}

// actionRepositoryURL is the repository a "uses: owner/repo[/path]@ref"
// reference is fetched from on host, or "" when host is empty or the
// reference does not name an owner and a repository; RepositoryOrigin
// declines to publish either. The repository is always the first two
// segments: in "github/codeql-action/upload-sarif" the third segment is a
// directory inside github/codeql-action, and a reusable workflow's
// ".github/workflows/<file>.yml" is a path inside its repository the same
// way.
func actionRepositoryURL(host, org, name string) string {
	repository, _, _ := strings.Cut(strings.TrimSpace(name), "/")
	org = strings.TrimSpace(org)
	host = strings.TrimSpace(host)
	if host == "" || org == "" || repository == "" {
		return ""
	}
	location := url.URL{Scheme: "https", Host: host, Path: "/" + org + "/" + repository}
	return location.String()
}

// isGitCommitSHA reports whether value is a full 40-hex-character Git object ID.
func isGitCommitSHA(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}

// localReferenceCandidates lists where a local reference's path (already
// stripped of its "./" or "$/" marker) may point: the repository root, and,
// unless rootOnly, the caller's own directory.
func localReferenceCandidates(localPath, callerRelPath string, rootOnly bool) []string {
	trimmed := strings.TrimSpace(localPath)
	repoRelative := filepath.ToSlash(filepath.Clean(trimmed))
	if rootOnly {
		return []string{repoRelative}
	}
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

func localWorkflowNode(relPath string) (*model.DependencyNode, error) {
	cleanPath := filepath.ToSlash(filepath.Clean(relPath))
	node, err := model.NewDependencyNode(model.Coordinates{
		Ecosystem:      model.EcosystemGitHub,
		Name:           cleanPath,
		Version:        "local",
		PackageManager: model.PackageManagerGitHubActions,
		Type:           model.PackageTypeWorkflow,
		Language:       "yaml",
	})
	if err != nil {
		return nil, fmt.Errorf("build local workflow node %q: %w", cleanPath, err)
	}
	node.Scopes = model.ScopesOf(model.ScopeRuntime)
	return node, nil

}

func localActionNode(relPath string) (*model.DependencyNode, error) {
	cleanPath := filepath.ToSlash(filepath.Clean(relPath))
	node, err := model.NewDependencyNode(model.Coordinates{
		Ecosystem:      model.EcosystemGitHub,
		Name:           cleanPath,
		Version:        "local",
		PackageManager: model.PackageManagerGitHubActions,
		Type:           model.PackageTypeAction,
		Language:       "yaml",
	})
	if err != nil {
		return nil, fmt.Errorf("build local action node %q: %w", cleanPath, err)
	}
	node.Scopes = model.ScopesOf(model.ScopeRuntime)
	return node, nil

}

// manifestFileDigests hashes a workflow or action manifest file so local
// manifest components carry verifiable integrity data. Returns nil on any
// read failure — digests are metadata, never a resolution requirement.
func manifestFileDigests(projectPath, relPath string) []model.Digest {
	data, err := system.ReadRepositoryFile(filepath.Join(projectPath, filepath.FromSlash(relPath)))
	if err != nil {
		return nil
	}
	sum := sha256.Sum256(data)
	return []model.Digest{{Algorithm: model.DigestAlgorithmSHA256, Value: hex.EncodeToString(sum[:])}}
}

func addNodeIfMissing(depsGraph *model.Graph, node *model.DependencyNode) error {
	_, err := detectorkit.EnsureNode(depsGraph, node)
	return err
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
