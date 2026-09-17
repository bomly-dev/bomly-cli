package registry

import (
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/bomly-dev/bomly-sdk/system"

	"github.com/bomly-dev/bomly-sdk/model"
)

// IndexedDetectors describes a set of package managers that will be detected by the same primary detector.
type IndexedDetectors struct {
	Path            string
	PrimaryDetector string
	PackageManagers []model.PackageManager
}

// packageManagerMatch describes a package manager that matches a set of evidence patterns.
type packageManagerMatch struct {
	manager         model.PackageManager
	matchedPatterns []string
	score           int
}

// DetectPackageManagers identifies package managers for a filesystem path.
func DetectPackageManagers(candidatePath string) ([]model.PackageManager, error) {
	info, err := os.Stat(candidatePath)
	if err != nil {
		return nil, err
	}
	matches := detectPackageManagerMatches(candidatePath, info.IsDir())
	managers := make([]model.PackageManager, 0, len(matches))
	for _, match := range deduplicateMatches(matches) {
		managers = append(managers, match.manager)
	}
	return uniquePackageManagers(managers), nil
}

func detectPackageManagerMatches(candidatePath string, isDir bool) []packageManagerMatch {
	matches := make([]packageManagerMatch, 0, 8)
	for _, manager := range SupportedPackageManagers() {
		patterns := EvidencePatternsForPackageManager(manager)
		if len(patterns) == 0 {
			continue
		}
		if isDir {
			matchedPatterns := matchingPatternsInDirectory(candidatePath, manager, patterns)
			if len(matchedPatterns) > 0 {
				matches = append(matches, packageManagerMatch{manager: manager, matchedPatterns: matchedPatterns, score: evidenceScore(matchedPatterns)})
			}
			continue
		}
		matchedPatterns := matchingPatternsForFile(candidatePath, manager, patterns)
		if len(matchedPatterns) > 0 {
			matches = append(matches, packageManagerMatch{manager: manager, matchedPatterns: matchedPatterns, score: evidenceScore(matchedPatterns)})
		}
	}
	return matches
}

func deduplicateMatches(matches []packageManagerMatch) []packageManagerMatch {
	if len(matches) < 2 {
		return matches
	}

	filtered := make([]packageManagerMatch, 0, len(matches))
	for i, current := range matches {
		if current.manager == model.PackageManagerUnknown {
			continue
		}
		drop := false
		for j, other := range matches {
			if i == j || current.manager.Ecosystem() != other.manager.Ecosystem() {
				continue
			}
			if current.score < other.score {
				drop = true
				break
			}
			if isStrictSubset(current.matchedPatterns, other.matchedPatterns) {
				drop = true
				break
			}
			if sameStringSet(current.matchedPatterns, other.matchedPatterns) && current.score == other.score && current.manager > other.manager {
				drop = true
				break
			}
		}
		if !drop {
			filtered = append(filtered, current)
		}
	}
	return filtered
}

func matchingPatternsInDirectory(dir string, manager model.PackageManager, patterns []string) []string {
	matched := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		if patternMatchesDirectory(dir, manager, pattern) {
			matched = append(matched, pattern)
		}
	}
	return matched
}

func matchingPatternsForFile(path string, manager model.PackageManager, patterns []string) []string {
	matched := make([]string, 0, len(patterns))
	slashPath := filepath.ToSlash(path)
	base := filepath.Base(slashPath)
	for _, pattern := range patterns {
		slashPattern := filepath.ToSlash(pattern)
		if matchedPath, _ := filepath.Match(slashPattern, slashPath); matchedPath {
			if pyprojectPatternMatches(path, manager, pattern) {
				matched = append(matched, pattern)
			}
			continue
		}
		if matchedBase, _ := filepath.Match(slashPattern, base); matchedBase {
			if pyprojectPatternMatches(path, manager, pattern) {
				matched = append(matched, pattern)
			}
		}
	}
	return matched
}

func fileExists(path string) bool {
	exists, err := system.FileExists(path)
	return err == nil && exists
}

func patternExists(dir string, pattern string) bool {
	if !strings.ContainsAny(pattern, "*?[") {
		return fileExists(filepath.Join(dir, filepath.FromSlash(pattern)))
	}
	matches, err := filepath.Glob(filepath.Join(dir, filepath.FromSlash(pattern)))
	return err == nil && len(matches) > 0
}

func patternMatchesDirectory(dir string, manager model.PackageManager, pattern string) bool {
	if !patternExists(dir, pattern) {
		return false
	}
	if !isPyprojectPattern(pattern) {
		return true
	}
	return pyprojectBelongsToManager(filepath.Join(dir, filepath.FromSlash(pattern)), manager)
}

func pyprojectPatternMatches(path string, manager model.PackageManager, pattern string) bool {
	if !isPyprojectPattern(pattern) {
		return true
	}
	return pyprojectBelongsToManager(path, manager)
}

func isPyprojectPattern(pattern string) bool {
	return filepath.ToSlash(pattern) == "pyproject.toml"
}

func evidenceScore(patterns []string) int {
	score := 0
	for _, pattern := range patterns {
		if patternSpecificity(pattern) > score {
			score = patternSpecificity(pattern)
		}
	}
	return score
}

func patternSpecificity(pattern string) int {
	switch filepath.ToSlash(pattern) {
	case "package.json", "pyproject.toml":
		return 1
	default:
		return 2
	}
}

func pyprojectBelongsToManager(path string, manager model.PackageManager) bool {
	switch manager {
	case model.PackageManagerPoetry:
		hasTable, _ := pyprojectHasTable(path, "tool.poetry")
		return hasTable
	case model.PackageManagerUV:
		hasTable, _ := pyprojectHasTable(path, "tool.uv")
		return hasTable
	case model.PackageManagerPDM:
		hasPoetryTable, readable := pyprojectHasTable(path, "tool.poetry")
		if !readable {
			return false
		}
		hasUVTable, readable := pyprojectHasTable(path, "tool.uv")
		return readable && !hasPoetryTable && !hasUVTable
	default:
		return true
	}
}

func pyprojectHasTable(path string, table string) (bool, bool) {
	raw, err := system.ReadRepositoryFile(path)
	if err != nil {
		return false, false
	}
	for line := range strings.SplitSeq(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "[") || !strings.Contains(trimmed, "]") {
			continue
		}
		trimmed = strings.TrimPrefix(trimmed, "[")
		trimmed = strings.TrimPrefix(trimmed, "[")
		trimmed = trimmed[:strings.Index(trimmed, "]")]
		name := strings.TrimSpace(trimmed)
		if strings.EqualFold(name, table) || strings.HasPrefix(strings.ToLower(name), strings.ToLower(table)+".") {
			return true, true
		}
	}
	return false, true
}

func uniquePackageManagers(values []model.PackageManager) []model.PackageManager {
	result := make([]model.PackageManager, 0, len(values))
	seen := make(map[model.PackageManager]struct{}, len(values))
	for _, value := range values {
		if value == model.PackageManagerUnknown {
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

func isStrictSubset(left []string, right []string) bool {
	if len(left) >= len(right) {
		return false
	}
	for _, value := range left {
		if !containsString(right, value) {
			return false
		}
	}
	return true
}

func sameStringSet(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for _, value := range left {
		if !containsString(right, value) {
			return false
		}
	}
	return true
}

func containsString(values []string, target string) bool {
	return slices.Contains(values, target)
}
