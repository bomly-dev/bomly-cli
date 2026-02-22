package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/explain"
	"github.com/bomly-dev/bomly-cli/internal/output"
	model "github.com/bomly-dev/bomly-cli/sdk"
)

type whyTreeNode struct {
	key            string
	label          string
	children       map[string]*whyTreeNode
	childOrder     []string
	annotations    []string
	annotationSeen map[string]struct{}
}

func whyTreeLines(paths []explain.Path) []string {
	return whyTreeLinesForTarget(paths, "")
}

func whyTreeLinesForTarget(paths []explain.Path, targetID string) []string {
	root := &whyTreeNode{children: make(map[string]*whyTreeNode)}
	for _, path := range paths {
		current := root
		for _, node := range path.Packages {
			current = current.child(node)
		}
		current.addAnnotation(whyPathAnnotation(path))
	}

	lines := make([]string, 0)
	for _, id := range root.childOrder {
		lines = appendWhyTreeLines(lines, root.children[id], "", true, true, targetID)
	}
	return lines
}

func appendWhyTreeLines(lines []string, node *whyTreeNode, prefix string, isLast bool, root bool, targetID string) []string {
	line := node.label
	if targetID != "" && node.key == targetID {
		line = ansiStyled(line, ansiBold, ansiCyan) + " " + ansiStyled("[analyzed]", ansiDim)
	}
	if len(node.annotations) > 0 {
		line = fmt.Sprintf("%s (%s)", line, strings.Join(node.annotations, "; "))
	}
	if root {
		lines = append(lines, line)
	} else {
		connector := "|- "
		if isLast {
			connector = "\\- "
		}
		lines = append(lines, prefix+connector+line)
	}

	childPrefix := prefix
	if !root {
		if isLast {
			childPrefix += "   "
		} else {
			childPrefix += "|  "
		}
	}
	for i, key := range node.childOrder {
		child := node.children[key]
		lines = appendWhyTreeLines(lines, child, childPrefix, i == len(node.childOrder)-1, false, targetID)
	}
	return lines
}

func (n *whyTreeNode) child(ref output.PackageRef) *whyTreeNode {
	key := ref.ID
	if key == "" {
		key = explainPackageDisplayName(ref)
	}
	if child, ok := n.children[key]; ok {
		return child
	}
	child := &whyTreeNode{
		key:            key,
		label:          explainPackageDisplayName(ref),
		children:       make(map[string]*whyTreeNode),
		annotationSeen: make(map[string]struct{}),
	}
	n.children[key] = child
	n.childOrder = append(n.childOrder, key)
	return child
}

func (n *whyTreeNode) addAnnotation(annotation string) {
	if annotation == "" {
		return
	}
	if _, ok := n.annotationSeen[annotation]; ok {
		return
	}
	n.annotationSeen[annotation] = struct{}{}
	n.annotations = append(n.annotations, annotation)
}

func whyPathAnnotation(path explain.Path) string {
	parts := []string{path.Relationship}
	if path.Cyclic {
		parts = append(parts, "cycle to "+path.CycleTo)
	}
	return strings.Join(parts, ", ")
}

func explainPackageDisplayName(ref output.PackageRef) string {
	name := strings.TrimSpace(ref.Name)
	if name == "" {
		name = strings.TrimSpace(ref.ID)
	}
	if ref.Version != "" && !strings.HasSuffix(name, "@"+ref.Version) {
		name += "@" + ref.Version
	}
	if name == "" {
		return "-"
	}
	return name
}

func explainGraphFromPaths(source *model.Graph, paths []explain.Path) (*model.Graph, error) {
	focused := model.New()
	if source == nil {
		return focused, nil
	}
	for _, path := range paths {
		for i, ref := range path.Packages {
			pkg, ok := source.Package(ref.ID)
			if !ok || pkg == nil {
				continue
			}
			if _, exists := focused.Package(pkg.ID); !exists {
				if err := focused.AddPackage(pkg.Clone()); err != nil {
					return nil, err
				}
			}
			if i == 0 {
				continue
			}
			parentRef := path.Packages[i-1]
			parent, ok := source.Package(parentRef.ID)
			if !ok || parent == nil {
				continue
			}
			if _, exists := focused.Package(parent.ID); !exists {
				if err := focused.AddPackage(parent.Clone()); err != nil {
					return nil, err
				}
			}
			if err := focused.AddDependency(parent.ID, pkg.ID); err != nil && !errors.Is(err, model.ErrCycleDetected) {
				return nil, err
			}
		}
	}
	return focused, nil
}

func explainManifestMetadata(result model.DetectionResult) model.ManifestMetadata {
	if result.Graphs != nil && len(result.Graphs.Entries) > 0 {
		return result.Graphs.Entries[0].Manifest
	}
	return model.ManifestMetadata{
		Path: result.SubprojectInfo.ExecutionTarget.Location,
		Kind: result.SubprojectInfo.PrimaryPackageManager().Name(),
	}
}
