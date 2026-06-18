package python

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/bomly-dev/bomly-cli/sdk"
)

// pipLockFileName is the committed, fully-pinned lock the pip fast-path reads.
// It is a pip-compile-style requirements file: every package pinned with "=="
// and annotated with "# via" comments that record the edges. Reading it avoids
// installing into (and inspecting) the ambient Python environment, which would
// otherwise capture whatever tooling happens to live in site-packages.
const pipLockFileName = "requirements.lock"

// pipLockPinnedLine matches a top-level pinned requirement ("name==version").
// The leading character class excludes whitespace and '#' so indented comment
// lines never match.
var pipLockPinnedLine = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*([^\s;\\]+)`)

// pipLockDevHint marks a "-r"/"-c" input file that denotes development scope
// (e.g. requirements-dev.in). Matched case-insensitively.
var pipLockDevHint = regexp.MustCompile(`(?i)dev`)

// pipLockEntry is one pinned package plus the sources that pulled it in.
type pipLockEntry struct {
	name     string
	version  string
	viaPkgs  []string // parent package names (transitive edges)
	viaFiles []string // "-r"/"-c" input files (direct dependencies)
}

// pipLockFilePath returns the path to requirements.lock if it exists inside
// projectPath, or an empty string if it does not.
func pipLockFilePath(projectPath string) string {
	p := filepath.Join(projectPath, pipLockFileName)
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return ""
}

// depGraphFromRequirementsLock parses a pip-compile-style requirements.lock and
// builds a dependency graph with transitive edges and runtime/development
// scope. Direct dependencies are those whose "# via" annotation references an
// input file ("-r foo.in"); a file matching pipLockDevHint marks development
// scope. Runtime always wins over development during BFS propagation.
func depGraphFromRequirementsLock(lockPath, projectPath string) (*sdk.Graph, error) {
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", pipLockFileName, err)
	}

	entries, err := parsePipLock(data)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("%s contains no pinned packages", pipLockFileName)
	}

	nodesByName := make(map[string]*sdk.Dependency, len(entries))
	for _, e := range entries {
		node := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemPython,
			Name:           e.name,
			Version:        e.version,
			PackageManager: sdk.PackageManagerPip,
			Language:       "python",
			Type:           sdk.PackageTypePackage,
			PURL:           sdk.BuildPackageURL("pypi", "", e.name, e.version)},
		})
		nodesByName[e.name] = node
	}

	g := sdk.New()
	root := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{Ecosystem: sdk.EcosystemPython,
		Name:           "root",
		PackageManager: sdk.PackageManagerPip,
		Language:       "python",
		Type:           sdk.PackageTypeApplication},
	})
	if err := g.AddNode(root); err != nil {
		return nil, fmt.Errorf("add root node: %w", err)
	}
	for _, node := range nodesByName {
		if err := addNodeIfMissing(g, node); err != nil {
			return nil, err
		}
	}

	// Wire edges and seed direct-dependency scopes.
	directScope := make(map[string]sdk.Scope, len(entries))
	for _, e := range entries {
		child := nodesByName[e.name]
		if child == nil {
			continue
		}
		for _, file := range e.viaFiles {
			scope := sdk.ScopeRuntime
			if pipLockDevHint.MatchString(file) {
				scope = sdk.ScopeDevelopment
			}
			directScope[child.ID] = sdk.MergeScope(directScope[child.ID], scope)
			if err := g.AddEdge(root.ID, child.ID); err != nil {
				return nil, fmt.Errorf("wire root→%s: %w", e.name, err)
			}
		}
		for _, parentName := range e.viaPkgs {
			parent := nodesByName[normalizePythonName(parentName)]
			if parent == nil || parent.ID == child.ID {
				continue
			}
			_ = g.AddEdge(parent.ID, child.ID)
		}
	}

	// Orphans (no incoming edge) attach to root to keep a single-root graph.
	for _, node := range nodesByName {
		if node == nil {
			continue
		}
		if dependents, _ := g.Dependents(node.ID); len(dependents) == 0 {
			_ = g.AddEdge(root.ID, node.ID)
		}
	}

	propagatePipScopes(g, root, directScope)
	return g, nil
}

// parsePipLock tokenizes a pip-compile-style lock into pinned entries. A pinned
// line ("name==version") opens an entry; the indented "# via ..." comment lines
// that follow attribute the entry to parent packages or input files.
func parsePipLock(data []byte) ([]*pipLockEntry, error) {
	var entries []*pipLockEntry
	var current *pipLockEntry

	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "":
			continue
		case !strings.HasPrefix(line, " ") && !strings.HasPrefix(trimmed, "#"):
			m := pipLockPinnedLine.FindStringSubmatch(line)
			if m == nil {
				// Unpinned/unsupported line (e.g. a bare "-e ." editable install).
				current = nil
				continue
			}
			current = &pipLockEntry{name: normalizePythonName(m[1]), version: m[2]}
			entries = append(entries, current)
		case current != nil && strings.HasPrefix(trimmed, "#"):
			parsePipLockViaLine(trimmed, current)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", pipLockFileName, err)
	}
	return entries, nil
}

// parsePipLockViaLine consumes one annotation comment line and records its
// sources on the entry. Handles both the "# via requests" single-line form and
// the multi-line form ("# via" followed by "#   requests" / "#   -r foo.in").
func parsePipLockViaLine(comment string, entry *pipLockEntry) {
	body := strings.TrimSpace(strings.TrimPrefix(comment, "#"))
	switch {
	case body == "via":
		body = ""
	case strings.HasPrefix(body, "via "):
		body = strings.TrimSpace(body[len("via "):])
	}
	if body == "" {
		return
	}
	fields := strings.FieldsFunc(body, func(r rune) bool { return r == ' ' || r == '\t' || r == ',' })
	for i := 0; i < len(fields); i++ {
		switch fields[i] {
		case "-r", "-c", "--requirement", "--constraint":
			if i+1 < len(fields) {
				entry.viaFiles = append(entry.viaFiles, fields[i+1])
				i++
			}
		default:
			entry.viaPkgs = append(entry.viaPkgs, fields[i])
		}
	}
}

// propagatePipScopes seeds direct-dependency scopes and BFS-propagates them so
// that any package reachable on a runtime path is marked runtime even if it is
// also a development dependency. Remaining unscoped packages default to runtime.
func propagatePipScopes(g *sdk.Graph, root *sdk.Dependency, directScope map[string]sdk.Scope) {
	directDeps, _ := g.DirectDependencies(root.ID)
	propagated := make(map[string]sdk.Scope, g.Size())
	queue := make([]*sdk.Dependency, 0, len(directDeps))
	for _, dep := range directDeps {
		if dep == nil {
			continue
		}
		scope := directScope[dep.ID]
		if scope == sdk.ScopeUnknown {
			scope = sdk.ScopeRuntime
		}
		propagated[dep.ID] = sdk.MergeScope(propagated[dep.ID], scope)
		dep.AddScope(propagated[dep.ID])
		queue = append(queue, dep)
	}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		scope := propagated[current.ID]
		if scope == sdk.ScopeUnknown {
			continue
		}
		children, err := g.DirectDependencies(current.ID)
		if err != nil {
			continue
		}
		for _, child := range children {
			if child == nil || child.ID == root.ID {
				continue
			}
			next := sdk.MergeScope(propagated[child.ID], scope)
			if next == propagated[child.ID] && child.PrimaryScope() == next {
				continue
			}
			propagated[child.ID] = next
			child.AddScope(next)
			queue = append(queue, child)
		}
	}
	for _, pkg := range g.Nodes() {
		if pkg != nil && pkg.ID != root.ID && pkg.PrimaryScope() == sdk.ScopeUnknown {
			pkg.AddScope(sdk.ScopeRuntime)
		}
	}
}
