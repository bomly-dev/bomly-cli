package runtime

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/system"
	model "github.com/bomly-dev/bomly-cli/sdk"
)

func pathMatchesPatterns(candidatePath string, patterns []string) bool {
	info, err := os.Stat(candidatePath)
	if err != nil {
		return false
	}
	if !info.IsDir() {
		return len(matchingPatternsForFile(candidatePath, patterns)) > 0
	}
	for _, pattern := range patterns {
		if patternExists(candidatePath, pattern) {
			return true
		}
	}
	return false
}

func matchingPatternsForFile(path string, patterns []string) []string {
	matched := make([]string, 0, len(patterns))
	slashPath := filepath.ToSlash(path)
	base := filepath.Base(slashPath)
	for _, pattern := range patterns {
		slashPattern := filepath.ToSlash(pattern)
		if matchesPath, _ := filepath.Match(slashPattern, slashPath); matchesPath {
			matched = append(matched, pattern)
			continue
		}
		if matchesBase, _ := filepath.Match(slashPattern, base); matchesBase {
			matched = append(matched, pattern)
		}
	}
	return matched
}

func patternExists(dir, pattern string) bool {
	if !strings.ContainsAny(pattern, "*?[") {
		exists, err := system.FileExists(filepath.Join(dir, filepath.FromSlash(pattern)))
		return err == nil && exists
	}
	matches, err := filepath.Glob(filepath.Join(dir, filepath.FromSlash(pattern)))
	return err == nil && len(matches) > 0
}

func resolveMatchedManifestPath(candidatePath string, patterns []string) (string, bool) {
	info, err := os.Stat(candidatePath)
	if err != nil {
		return "", false
	}
	if !info.IsDir() {
		if len(matchingPatternsForFile(candidatePath, patterns)) == 0 {
			return "", false
		}
		return candidatePath, true
	}

	for _, pattern := range patterns {
		resolvedPath, ok := resolveManifestCandidate(candidatePath, pattern)
		if ok {
			return resolvedPath, true
		}
	}
	return "", false
}

func resolveManifestCandidate(basePath, pattern string) (string, bool) {
	pattern = filepath.FromSlash(pattern)
	if pattern == "" {
		return "", false
	}
	if !strings.ContainsAny(pattern, "*?[") {
		candidate := filepath.Join(basePath, pattern)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, true
		}
		return "", false
	}

	matches, err := filepath.Glob(filepath.Join(basePath, pattern))
	if err != nil || len(matches) == 0 {
		return "", false
	}
	for _, match := range matches {
		if info, statErr := os.Stat(match); statErr == nil && !info.IsDir() {
			return match, true
		}
	}
	return "", false
}

func executionTargetIsSingleFile(executionTarget model.ExecutionTarget) (bool, error) {
	if executionTarget.Kind != model.ExecutionTargetFilesystem {
		return false, nil
	}
	info, err := os.Stat(executionTarget.Location)
	if err != nil {
		return false, err
	}
	return !info.IsDir(), nil
}
