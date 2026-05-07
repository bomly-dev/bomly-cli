package registry

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/system"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// IndexedDetectors describes a set of package managers that will be detected by the same primary detector.
type IndexedDetectors struct {
	Path            string
	PrimaryDetector string
	PackageManagers []sdk.PackageManager
}

// packageManagerMatch describes a package manager that matches a set of evidence patterns.
type packageManagerMatch struct {
	manager         sdk.PackageManager
	matchedPatterns []string
}

// IndexDetectors identifies detectors along with their package managers for a filesystem path.
func IndexDetectors(candidatePath string) ([]IndexedDetectors, error) {
	managers, err := DetectPackageManagers(candidatePath)
	if err != nil {
		return nil, err
	}
	grouped := make([]IndexedDetectors, 0, len(managers))
	indexByDetector := make(map[string]int, len(managers))
	for _, manager := range managers {
		detectorName := PrimaryDetectorForPackageManager(manager)
		if detectorName == "" {
			detectorName = manager.Name()
		}
		idx, ok := indexByDetector[detectorName]
		if !ok {
			idx = len(grouped)
			indexByDetector[detectorName] = idx
			grouped = append(grouped, IndexedDetectors{
				Path:            candidatePath,
				PrimaryDetector: detectorName,
				PackageManagers: []sdk.PackageManager{},
			})
		}
		grouped[idx].PackageManagers = appendUniquePackageManager(grouped[idx].PackageManagers, manager)
	}
	return grouped, nil
}

// DetectPackageManagers identifies package managers for a filesystem path.
func DetectPackageManagers(candidatePath string) ([]sdk.PackageManager, error) {
	info, err := os.Stat(candidatePath)
	if err != nil {
		return nil, err
	}
	matches := detectPackageManagerMatches(candidatePath, info.IsDir())
	managers := make([]sdk.PackageManager, 0, len(matches))
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

func deduplicateMatches(matches []packageManagerMatch) []packageManagerMatch {
	if len(matches) < 2 {
		return matches
	}

	filtered := make([]packageManagerMatch, 0, len(matches))
	for i, current := range matches {
		if current.manager == sdk.PackageManagerUnknown {
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

func uniquePackageManagers(values []sdk.PackageManager) []sdk.PackageManager {
	result := make([]sdk.PackageManager, 0, len(values))
	seen := make(map[sdk.PackageManager]struct{}, len(values))
	for _, value := range values {
		if value == sdk.PackageManagerUnknown {
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

func appendUniquePackageManager(values []sdk.PackageManager, value sdk.PackageManager) []sdk.PackageManager {
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
