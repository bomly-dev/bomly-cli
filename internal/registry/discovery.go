package registry

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/bomly/bomly-cli/pkg/system"
)

// IndexedPackageManagers describes one detection run for a path after deduping
// by the primary detector that will execute.
type IndexedPackageManagers struct {
	Path            string
	PackageManager  PackageManager
	PackageManagers []PackageManager
}

type packageManagerMatch struct {
	manager         PackageManager
	matchedPatterns []string
}

// IndexPackageManagers groups matches by the primary detector that will run.
func IndexPackageManagers(candidatePath string) ([]IndexedPackageManagers, error) {
	managers, err := DetectPackageManagers(candidatePath)
	if err != nil {
		return nil, err
	}
	grouped := make([]IndexedPackageManagers, 0, len(managers))
	indexByDetector := make(map[string]int, len(managers))
	for _, manager := range managers {
		detectorName := manager.PrimaryDetector()
		if detectorName == "" {
			detectorName = manager.Name()
		}
		idx, ok := indexByDetector[detectorName]
		if !ok {
			idx = len(grouped)
			indexByDetector[detectorName] = idx
			grouped = append(grouped, IndexedPackageManagers{
				Path:            candidatePath,
				PackageManager:  manager,
				PackageManagers: []PackageManager{},
			})
		}
		grouped[idx].PackageManagers = appendUniquePackageManager(grouped[idx].PackageManagers, manager)
	}
	return grouped, nil
}

// DetectPackageManagers identifies package managers for a filesystem path.
func DetectPackageManagers(candidatePath string) ([]PackageManager, error) {
	info, err := os.Stat(candidatePath)
	if err != nil {
		return nil, err
	}
	matches := detectPackageManagerMatches(candidatePath, info.IsDir())
	managers := make([]PackageManager, 0, len(matches))
	for _, match := range normalizePackageManagerMatches(matches) {
		managers = append(managers, match.manager)
	}
	return uniquePackageManagers(managers), nil
}

// DetectPackageManagersForFile identifies package managers for a single file target.
func DetectPackageManagersForFile(candidatePath string) []PackageManager {
	return uniquePackageManagers(detectPackageManagersForFile(candidatePath))
}

func detectPackageManagersForFile(candidatePath string) []PackageManager {
	matches := detectPackageManagerMatches(candidatePath, false)
	managers := make([]PackageManager, 0, len(matches))
	for _, match := range normalizePackageManagerMatches(matches) {
		managers = append(managers, match.manager)
	}
	return managers
}

func detectPackageManagerMatches(candidatePath string, isDir bool) []packageManagerMatch {
	matches := make([]packageManagerMatch, 0, 8)
	for _, manager := range AllPackageManagers() {
		patterns := manager.EvidencePatterns()
		if len(patterns) == 0 {
			continue
		}
		if isDir {
			matchedPatterns := matchingPatternsInDirectory(candidatePath, patterns)
			if len(matchedPatterns) > 0 {
				matches = append(matches, packageManagerMatch{manager: manager, matchedPatterns: matchedPatterns})
			}
			continue
		}
		matchedPatterns := matchingPatternsForFile(candidatePath, patterns)
		if len(matchedPatterns) > 0 {
			matches = append(matches, packageManagerMatch{manager: manager, matchedPatterns: matchedPatterns})
		}
	}
	return matches
}

func normalizePackageManagerMatches(matches []packageManagerMatch) []packageManagerMatch {
	if len(matches) < 2 {
		return matches
	}

	filtered := make([]packageManagerMatch, 0, len(matches))
	for i, current := range matches {
		if current.manager == PackageManagerUnknown {
			continue
		}
		drop := false
		for j, other := range matches {
			if i == j || current.manager.Ecosystem() != other.manager.Ecosystem() {
				continue
			}
			if isStrictSubset(current.matchedPatterns, other.matchedPatterns) {
				drop = true
				break
			}
			if sameStringSet(current.matchedPatterns, other.matchedPatterns) && current.manager > other.manager {
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

func matchingPatternsInDirectory(dir string, patterns []string) []string {
	matched := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		if patternExists(dir, pattern) {
			matched = append(matched, pattern)
		}
	}
	return matched
}

func matchingPatternsForFile(path string, patterns []string) []string {
	matched := make([]string, 0, len(patterns))
	slashPath := filepath.ToSlash(path)
	base := filepath.Base(slashPath)
	for _, pattern := range patterns {
		slashPattern := filepath.ToSlash(pattern)
		if matchedPath, _ := filepath.Match(slashPattern, slashPath); matchedPath {
			matched = append(matched, pattern)
			continue
		}
		if matchedBase, _ := filepath.Match(slashPattern, base); matchedBase {
			matched = append(matched, pattern)
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

func uniquePackageManagers(values []PackageManager) []PackageManager {
	result := make([]PackageManager, 0, len(values))
	seen := make(map[PackageManager]struct{}, len(values))
	for _, value := range values {
		if value == PackageManagerUnknown {
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

func appendUniquePackageManager(values []PackageManager, value PackageManager) []PackageManager {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
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
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
