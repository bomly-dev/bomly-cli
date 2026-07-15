package maven

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/sdk"
)

// mavenModule is one reactor module discovered by walking pom <modules>
// declarations: its directory relative to the reactor root and the
// coordinates its pom declares (groupId falls back to <parent>).
type mavenModule struct {
	Dir        string
	GroupID    string
	ArtifactID string
}

// maxPomModuleDepth caps the recursive <modules> walk so cyclic or hostile
// pom trees cannot recurse unboundedly.
const maxPomModuleDepth = 16

type pomModulesDocument struct {
	GroupID    string           `xml:"groupId"`
	ArtifactID string           `xml:"artifactId"`
	Parent     pomModulesParent `xml:"parent"`
	Modules    []string         `xml:"modules>module"`
}

type pomModulesParent struct {
	GroupID string `xml:"groupId"`
}

// walkPomModules recursively reads <modules><module> declarations starting at
// rootDir's pom.xml and returns every reactor module with its resolved
// coordinates. The root pom itself is not returned. Unreadable or unparsable
// module poms are skipped; the caller degrades to a single manifest entry.
func walkPomModules(rootDir string) ([]mavenModule, error) {
	visited := map[string]struct{}{}
	var modules []mavenModule
	var walk func(dir, rel string, depth int) error
	walk = func(dir, rel string, depth int) error {
		if depth > maxPomModuleDepth {
			return nil
		}
		canonical := dir
		if resolved, err := filepath.EvalSymlinks(dir); err == nil {
			canonical = resolved
		}
		if _, ok := visited[canonical]; ok {
			return nil
		}
		visited[canonical] = struct{}{}

		doc, err := readPomModulesDocument(filepath.Join(dir, "pom.xml"))
		if err != nil {
			if rel == "." {
				return err
			}
			return nil
		}
		if rel != "." {
			groupID := strings.TrimSpace(doc.GroupID)
			if groupID == "" {
				groupID = strings.TrimSpace(doc.Parent.GroupID)
			}
			artifactID := strings.TrimSpace(doc.ArtifactID)
			if artifactID != "" {
				modules = append(modules, mavenModule{Dir: rel, GroupID: groupID, ArtifactID: artifactID})
			}
		}
		for _, module := range doc.Modules {
			module = strings.TrimSpace(strings.ReplaceAll(module, "\\", "/"))
			if module == "" {
				continue
			}
			childRel := module
			if rel != "." {
				childRel = rel + "/" + module
			}
			childRel = filepath.ToSlash(filepath.Clean(childRel))
			if childRel == "." || strings.HasPrefix(childRel, "../") {
				continue
			}
			if err := walk(filepath.Join(rootDir, filepath.FromSlash(childRel)), childRel, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(rootDir, ".", 0); err != nil {
		return nil, err
	}
	sort.Slice(modules, func(i, j int) bool { return modules[i].Dir < modules[j].Dir })
	return modules, nil
}

func readPomModulesDocument(path string) (pomModulesDocument, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return pomModulesDocument{}, fmt.Errorf("read %s: %w", path, err)
	}
	var doc pomModulesDocument
	if err := xml.Unmarshal(raw, &doc); err != nil {
		return pomModulesDocument{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return doc, nil
}

// moduleKey builds the groupId:artifactId lookup key used to match reactor
// modules against TGF graph nodes.
func (m mavenModule) moduleKey() string {
	return m.GroupID + ":" + m.ArtifactID
}

// graphNodeModuleKey derives the groupId:artifactId key for a graph node,
// stripping the ":classifier" suffix depGraphFromMavenTGF appends to names.
func graphNodeModuleKey(pkg *sdk.Dependency) string {
	name := pkg.Name
	if idx := strings.Index(name, ":"); idx >= 0 {
		name = name[:idx]
	}
	return pkg.Org + ":" + name
}
