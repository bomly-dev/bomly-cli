package render

import (
	"fmt"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/engine/explain"
	"github.com/bomly-dev/bomly-cli/internal/output"
)

type whyTreeNode struct {
	key            string
	label          string
	children       map[string]*whyTreeNode
	childOrder     []string
	annotations    []string
	annotationSeen map[string]struct{}
}

// WhyTreeLines renders a why/explain dependency tree without highlighting.
func WhyTreeLines(paths []explain.Path) []string {
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
		line = Style(line, Bold, Cyan) + " " + Style("[analyzed]", Dim)
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
