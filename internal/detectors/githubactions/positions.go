package githubactions

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// usesLine matches `uses: owner/repo[/path]@ref` entries in workflow
// YAML. The captured value is the owner/repo coordinate (excluding
// path and ref).
var usesLine = regexp.MustCompile(`^\s*-?\s*uses\s*:\s*['"]?([A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*)(?:/[^@'"\s]*)?@[^'"\s]+['"]?\s*$`)

// workflowPositions walks .github/workflows/*.yml + .github/actions/*/action.yml
// and returns a map from owner/repo coordinate to the line where the
// `uses:` entry first appears.
func workflowPositions(projectDir string) map[string]*sdk.SourcePosition {
	out := make(map[string]*sdk.SourcePosition)
	patterns := []string{
		filepath.Join(projectDir, ".github", "workflows", "*.yml"),
		filepath.Join(projectDir, ".github", "workflows", "*.yaml"),
		filepath.Join(projectDir, ".github", "actions", "*", "action.yml"),
		filepath.Join(projectDir, ".github", "actions", "*", "action.yaml"),
	}
	for _, pattern := range patterns {
		matches, _ := filepath.Glob(pattern)
		for _, file := range matches {
			rel, err := filepath.Rel(projectDir, file)
			if err != nil || rel == "" {
				rel = filepath.Base(file)
			}
			rel = filepath.ToSlash(rel)
			_ = detectors.ScanLines(file, func(line int, text string) {
				m := usesLine.FindStringSubmatch(text)
				if m == nil {
					return
				}
				coord := strings.TrimSpace(m[1])
				if coord == "" {
					return
				}
				if _, exists := out[coord]; exists {
					return
				}
				out[coord] = &sdk.SourcePosition{File: rel, Line: line}
			})
		}
	}
	return out
}

// AttachWorkflowPositions wires workflow / action.yml line numbers
// into the resolved graph.
func AttachWorkflowPositions(g *sdk.Graph, projectDir string) {
	if g == nil || projectDir == "" {
		return
	}
	positions := workflowPositions(projectDir)
	if len(positions) == 0 {
		return
	}
	detectors.AttachPositions(g, positions, func(pkg *sdk.Package) string {
		if pkg == nil {
			return ""
		}
		// GitHub Actions packages have Name=owner/repo.
		return strings.TrimSpace(pkg.Name)
	})
}
