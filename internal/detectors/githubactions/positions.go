package githubactions

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// usesLine matches `uses: owner/repo[/path]@ref` entries in workflow
// YAML. The captured value is the action coordinate excluding the ref.
var usesLine = regexp.MustCompile(`^\s*-?\s*uses\s*:\s*['"]?([A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*(?:/[^@'"\s]*)?)@[^'"\s]+['"]?\s*$`)

// workflowPositions walks .github/workflows/*.yml + .github/actions/*/action.yml
// and returns every line where a `uses:` entry appears for each owner/repo
// coordinate.
func workflowPositions(projectDir string) map[string][]*sdk.SourcePosition {
	out := make(map[string][]*sdk.SourcePosition)
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
				matches := usesLine.FindStringSubmatchIndex(text)
				if len(matches) < 4 {
					return
				}
				coord := strings.TrimSpace(text[matches[2]:matches[3]])
				if coord == "" {
					return
				}
				appendPosition(out, coord, &sdk.SourcePosition{File: rel, Line: line, Column: matches[2] + 1, EndLine: line})
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
	detectors.AttachPositionCandidates(g, positions, func(pkg *sdk.Dependency) []string {
		if pkg == nil {
			return nil
		}
		// External GitHub Actions packages store owner and repository
		// separately, while workflow manifests spell them as owner/repo.
		if strings.TrimSpace(pkg.Org) != "" && strings.TrimSpace(pkg.Name) != "" {
			return []string{strings.Trim(strings.TrimSpace(pkg.Org), "/") + "/" + strings.Trim(strings.TrimSpace(pkg.Name), "/")}
		}
		return []string{strings.TrimSpace(pkg.Name)}
	})
}

func appendPosition(out map[string][]*sdk.SourcePosition, key string, pos *sdk.SourcePosition) {
	key = strings.TrimSpace(key)
	if key == "" || pos == nil {
		return
	}
	for _, existing := range out[key] {
		if existing.File == pos.File && existing.Line == pos.Line && existing.Column == pos.Column {
			return
		}
	}
	out[key] = append(out[key], pos)
}
