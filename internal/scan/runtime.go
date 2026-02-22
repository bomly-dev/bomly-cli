package scan

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bomly/bomly-cli/pkg/system"
)

// RegistryFilter narrows a registry down to the runtime-relevant selections.
type RegistryFilter struct {
	DetectorFilter    DetectorFilter
	AuditorFilter     AuditorFilter
	MatcherFilter     MatcherFilter
	IncludeEcosystems map[Ecosystem]struct{}
	ExcludeEcosystems map[Ecosystem]struct{}
}

// DetectorDiscoveryPlan describes how one detector participates in runtime planning.
type DetectorDiscoveryPlan struct {
	SupportedEcosystems []Ecosystem
	SupportedManagers   []PackageManager
	EvidencePatterns    []string
	TargetKinds         []ExecutionTargetKind
}

// Clone returns a deep copy of the discovery plan.
func (p DetectorDiscoveryPlan) Clone() DetectorDiscoveryPlan {
	return DetectorDiscoveryPlan{
		SupportedEcosystems: append([]Ecosystem(nil), p.SupportedEcosystems...),
		SupportedManagers:   append([]PackageManager(nil), p.SupportedManagers...),
		EvidencePatterns:    append([]string(nil), p.EvidencePatterns...),
		TargetKinds:         append([]ExecutionTargetKind(nil), p.TargetKinds...),
	}
}

// PrepareRequest defines the inputs required to build one execution runtime.
type PrepareRequest struct {
	Registry             *Registry
	ExecutionTarget      ExecutionTarget
	Recursive            bool
	ForcedPackageManager PackageManager
	DetectorFilter       DetectorFilter
	AuditorFilter        AuditorFilter
	MatcherFilter        MatcherFilter
	IncludeEcosystems    map[Ecosystem]struct{}
	ExcludeEcosystems    map[Ecosystem]struct{}
}

// Runtime is the prepared execution state reused across resolution, matching, and audit.
type Runtime struct {
	Registry          *Registry
	ExecutionTarget   ExecutionTarget
	Subprojects       []Subproject
	DetectorFilter    DetectorFilter
	AuditorFilter     AuditorFilter
	MatcherFilter     MatcherFilter
	IncludeEcosystems map[Ecosystem]struct{}
	ExcludeEcosystems map[Ecosystem]struct{}
}

type packageManagerMatch struct {
	manager         PackageManager
	matchedPatterns []string
}

var (
	// ErrNoSubprojects indicates that no compatible subprojects were discovered for the runtime.
	ErrNoSubprojects = errors.New("unable to infer package manager subprojects")
	// ErrNoSubprojectsMatchedFilters indicates that no discovered subprojects remained after applying filters.
	ErrNoSubprojectsMatchedFilters = errors.New("no discovered subprojects matched the selected ecosystems")
)

// Prepare builds a filtered runtime and plans subprojects from the selected execution target.
func Prepare(req PrepareRequest) (*Runtime, error) {
	if req.Registry == nil {
		return nil, fmt.Errorf("prepare runtime: registry is nil")
	}

	filteredRegistry := req.Registry.Filter(RegistryFilter{
		DetectorFilter:    req.DetectorFilter,
		AuditorFilter:     req.AuditorFilter,
		MatcherFilter:     req.MatcherFilter,
		IncludeEcosystems: req.IncludeEcosystems,
		ExcludeEcosystems: req.ExcludeEcosystems,
	})

	subprojects, err := planSubprojects(filteredRegistry, req)
	if err != nil {
		return nil, err
	}

	return &Runtime{
		Registry:          filteredRegistry,
		ExecutionTarget:   req.ExecutionTarget,
		Subprojects:       subprojects,
		DetectorFilter:    req.DetectorFilter,
		AuditorFilter:     req.AuditorFilter,
		MatcherFilter:     req.MatcherFilter,
		IncludeEcosystems: cloneEcosystemSet(req.IncludeEcosystems),
		ExcludeEcosystems: cloneEcosystemSet(req.ExcludeEcosystems),
	}, nil
}

func cloneEcosystemSet(values map[Ecosystem]struct{}) map[Ecosystem]struct{} {
	if len(values) == 0 {
		return nil
	}
	cloned := make(map[Ecosystem]struct{}, len(values))
	for value := range values {
		cloned[value] = struct{}{}
	}
	return cloned
}

func planSubprojects(registryValue *Registry, req PrepareRequest) ([]Subproject, error) {
	if req.ForcedPackageManager != PackageManagerUnknown {
		subproject, ok := plannedSubprojectForPackageManager(registryValue, req.ExecutionTarget, req.ExecutionTarget.Location, req.ForcedPackageManager)
		if !ok {
			return nil, noSubprojectsError(req)
		}
		return []Subproject{subproject}, nil
	}

	switch req.ExecutionTarget.Kind {
	case ExecutionTargetContainerImage:
		return planContainerSubprojects(registryValue, req)
	default:
		return planFilesystemSubprojects(registryValue, req)
	}
}

func planContainerSubprojects(registryValue *Registry, req PrepareRequest) ([]Subproject, error) {
	plans := registryValue.DiscoveryPlans()
	if len(plans) == 0 {
		return nil, noSubprojectsError(req)
	}

	subprojects := make([]Subproject, 0, len(plans))
	seen := make(map[string]struct{}, len(plans))
	for detectorName, plan := range plans {
		if !supportsTargetKind(plan.TargetKinds, ExecutionTargetContainerImage) {
			continue
		}
		detectors := registryValue.PlannedDetectors(ResolveGraphRequest{
			ProjectPath:     req.ExecutionTarget.Location,
			ExecutionTarget: req.ExecutionTarget,
			Ecosystem:       singleEcosystem(plan.SupportedEcosystems, req.IncludeEcosystems),
			PackageManager:  singlePackageManager(plan.SupportedManagers),
			DetectorFilter:  req.DetectorFilter,
			Mode:            TargetModeFullGraph,
		}, []string{detectorName})
		chain := expandDetectorNames(registryValue, detectors)
		if len(chain) == 0 {
			continue
		}
		key := strings.Join(chain, "|")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		subprojects = append(subprojects, Subproject{
			ExecutionTarget:         req.ExecutionTarget,
			RelativePath:            ".",
			PackageManager:          singlePackageManager(plan.SupportedManagers),
			DetectedPackageManagers: append([]PackageManager(nil), plan.SupportedManagers...),
			PlannedDetectors:        chain,
			Ecosystem:               singleEcosystem(plan.SupportedEcosystems, req.IncludeEcosystems),
		})
	}

	if len(subprojects) == 0 {
		return nil, noSubprojectsError(req)
	}
	sortSubprojects(subprojects)
	return subprojects, nil
}

func planFilesystemSubprojects(registryValue *Registry, req PrepareRequest) ([]Subproject, error) {
	isSingleFile, err := executionTargetIsSingleFile(req.ExecutionTarget)
	if err != nil {
		return nil, fmt.Errorf("discover subprojects: %w", err)
	}
	if isSingleFile {
		subprojects := plannedSubprojectsForPath(registryValue, req.ExecutionTarget, req.ExecutionTarget.Location, req.DetectorFilter, req.IncludeEcosystems)
		if len(subprojects) == 0 {
			return nil, noSubprojectsError(req)
		}
		return subprojects, nil
	}

	seen := make(map[string]Subproject)
	collect := func(candidatePath string) {
		for _, subproject := range plannedSubprojectsForPath(registryValue, req.ExecutionTarget, candidatePath, req.DetectorFilter, req.IncludeEcosystems) {
			key := subproject.RelativePath + "::" + subproject.PackageManager.Name() + "::" + strings.Join(subproject.PlannedDetectors, "|")
			seen[key] = subproject
		}
	}

	if req.Recursive {
		err := filepath.WalkDir(req.ExecutionTarget.Location, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if !entry.IsDir() {
				return nil
			}
			if path != req.ExecutionTarget.Location && shouldSkipDiscoveryDir(entry.Name()) {
				return filepath.SkipDir
			}
			collect(path)
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("discover subprojects: %w", err)
		}
	} else {
		collect(req.ExecutionTarget.Location)
	}

	subprojects := make([]Subproject, 0, len(seen))
	for _, subproject := range seen {
		subprojects = append(subprojects, subproject)
	}
	if len(subprojects) == 0 {
		return nil, noSubprojectsError(req)
	}
	sortSubprojects(subprojects)
	return subprojects, nil
}

func plannedSubprojectsForPath(
	registryValue *Registry,
	executionTarget ExecutionTarget,
	candidatePath string,
	detectorFilter DetectorFilter,
	includeEcosystems map[Ecosystem]struct{},
) []Subproject {
	grouped := make(map[string]*Subproject)

	for _, manager := range detectPackageManagers(candidatePath) {
		subproject, ok := plannedSubprojectForPackageManager(registryValue, executionTarget, candidatePath, manager)
		if !ok {
			continue
		}
		key := subproject.RelativePath + "::" + strings.Join(subproject.PlannedDetectors, "|")
		existing, ok := grouped[key]
		if !ok {
			copyValue := subproject
			copyValue.DetectedPackageManagers = append([]PackageManager(nil), subproject.DetectedPackageManagers...)
			copyValue.PlannedDetectors = append([]string(nil), subproject.PlannedDetectors...)
			grouped[key] = &copyValue
			continue
		}
		existing.DetectedPackageManagers = appendUniquePackageManager(existing.DetectedPackageManagers, manager)
	}

	subprojects := make([]Subproject, 0, len(grouped))
	for _, subproject := range grouped {
		subprojects = append(subprojects, *subproject)
	}

	for _, subproject := range plannedPluginSubprojectsForPath(registryValue, executionTarget, candidatePath, detectorFilter, includeEcosystems) {
		key := subproject.RelativePath + "::" + strings.Join(subproject.PlannedDetectors, "|")
		if _, ok := grouped[key]; ok {
			continue
		}
		subprojects = append(subprojects, subproject)
	}

	sortSubprojects(subprojects)
	return subprojects
}

func detectPackageManagers(candidatePath string) []PackageManager {
	info, err := os.Stat(candidatePath)
	if err != nil {
		return nil
	}
	matches := detectPackageManagerMatches(candidatePath, info.IsDir())
	managers := make([]PackageManager, 0, len(matches))
	for _, match := range normalizePackageManagerMatches(matches) {
		managers = append(managers, match.manager)
	}
	return uniquePackageManagers(managers)
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

func plannedSubprojectForPackageManager(registryValue *Registry, executionTarget ExecutionTarget, candidatePath string, manager PackageManager) (Subproject, bool) {
	patterns := EvidencePatternsForPackageManager(manager)
	if len(patterns) == 0 || !pathMatchesPatterns(candidatePath, patterns) {
		return Subproject{}, false
	}

	projectPath := candidatePath
	if manager == PackageManagerSBOM {
		resolvedPath, ok := resolveMatchedManifestPath(candidatePath, patterns)
		if !ok {
			return Subproject{}, false
		}
		projectPath = resolvedPath
	}

	relPath, err := filepath.Rel(executionTarget.Location, projectPath)
	if err != nil {
		return Subproject{}, false
	}
	if relPath == "" {
		relPath = "."
	}

	resolveReq := ResolveGraphRequest{
		ProjectPath:     projectPath,
		ExecutionTarget: executionTarget,
		Ecosystem:       manager.Ecosystem(),
		PackageManager:  manager,
		Mode:            TargetModeFullGraph,
	}
	chain := expandDetectorNames(registryValue, registryValue.Detectors(resolveReq))
	if len(chain) == 0 {
		return Subproject{}, false
	}

	return Subproject{
		ExecutionTarget:         concreteSubprojectExecutionTarget(executionTarget, projectPath),
		RelativePath:            filepath.ToSlash(relPath),
		PackageManager:          manager,
		DetectedPackageManagers: []PackageManager{manager},
		PlannedDetectors:        chain,
		Ecosystem:               manager.Ecosystem(),
	}, true
}

func plannedPluginSubprojectsForPath(
	registryValue *Registry,
	executionTarget ExecutionTarget,
	candidatePath string,
	detectorFilter DetectorFilter,
	includeEcosystems map[Ecosystem]struct{},
) []Subproject {
	if executionTarget.Kind != ExecutionTargetFilesystem && executionTarget.Kind != ExecutionTargetGitRepository {
		return nil
	}

	plans := registryValue.DiscoveryPlans()
	if len(plans) == 0 {
		return nil
	}

	relPath, err := filepath.Rel(executionTarget.Location, candidatePath)
	if err != nil {
		return nil
	}
	if relPath == "" {
		relPath = "."
	}

	subprojects := make([]Subproject, 0)
	for detectorName, plan := range plans {
		targetKinds := []ExecutionTargetKind{executionTarget.Kind}
		if executionTarget.Kind == ExecutionTargetGitRepository {
			targetKinds = append(targetKinds, ExecutionTargetFilesystem)
		}
		if !supportsTargetKind(plan.TargetKinds, targetKinds...) {
			continue
		}
		if len(plan.EvidencePatterns) == 0 || !pathMatchesPatterns(candidatePath, plan.EvidencePatterns) {
			continue
		}
		detectors := registryValue.PlannedDetectors(ResolveGraphRequest{
			ProjectPath:     candidatePath,
			ExecutionTarget: executionTarget,
			Ecosystem:       singleEcosystem(plan.SupportedEcosystems, includeEcosystems),
			PackageManager:  singlePackageManager(plan.SupportedManagers),
			DetectorFilter:  detectorFilter,
			Mode:            TargetModeFullGraph,
		}, []string{detectorName})
		chain := expandDetectorNames(registryValue, detectors)
		if len(chain) == 0 {
			continue
		}
		subprojects = append(subprojects, Subproject{
			ExecutionTarget:         concreteSubprojectExecutionTarget(executionTarget, candidatePath),
			RelativePath:            filepath.ToSlash(relPath),
			PackageManager:          singlePackageManager(plan.SupportedManagers),
			DetectedPackageManagers: append([]PackageManager(nil), plan.SupportedManagers...),
			PlannedDetectors:        chain,
			Ecosystem:               singleEcosystem(plan.SupportedEcosystems, includeEcosystems),
		})
	}
	return subprojects
}

func expandDetectorNames(registryValue *Registry, detectors []Detector) []string {
	if len(detectors) == 0 {
		return nil
	}

	allowed := make(map[string]struct{}, len(registryValue.detectors))
	for _, detector := range registryValue.detectors {
		name := detector.Descriptor().Name
		if name == "" {
			continue
		}
		allowed[name] = struct{}{}
	}

	names := make([]string, 0, len(detectors))
	seen := make(map[string]struct{}, len(detectors))
	for _, detector := range detectors {
		appendDetectorChain(detector, allowed, seen, &names)
	}
	return names
}

func appendDetectorChain(detector Detector, allowed map[string]struct{}, seen map[string]struct{}, names *[]string) {
	if detector == nil {
		return
	}

	name := detector.Descriptor().Name
	if name == "" {
		return
	}
	if _, ok := allowed[name]; !ok {
		return
	}
	if _, ok := seen[name]; !ok {
		seen[name] = struct{}{}
		*names = append(*names, name)
	}

	fallbackProvider, ok := detector.(FallbackDetector)
	if !ok {
		return
	}
	fallback := fallbackProvider.FallbackDetector()
	if fallback == nil {
		return
	}
	appendDetectorChain(fallback, allowed, seen, names)
}

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

func matchingPatternsInDirectory(dir string, patterns []string) []string {
	matched := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		if patternExists(dir, pattern) {
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

func executionTargetIsSingleFile(executionTarget ExecutionTarget) (bool, error) {
	if executionTarget.Kind != ExecutionTargetFilesystem {
		return false, nil
	}
	info, err := os.Stat(executionTarget.Location)
	if err != nil {
		return false, err
	}
	return !info.IsDir(), nil
}

func concreteSubprojectExecutionTarget(parent ExecutionTarget, location string) ExecutionTarget {
	target := parent
	target.Location = location
	if parent.Kind == ExecutionTargetContainerImage {
		return target
	}
	target.Kind = ExecutionTargetFilesystem
	return target
}

func supportsTargetKind(targetKinds []ExecutionTargetKind, candidates ...ExecutionTargetKind) bool {
	if len(targetKinds) == 0 {
		return false
	}
	for _, targetKind := range targetKinds {
		for _, candidate := range candidates {
			if targetKind == candidate {
				return true
			}
		}
	}
	return false
}

func singleEcosystem(ecosystems []Ecosystem, include map[Ecosystem]struct{}) Ecosystem {
	if len(include) == 1 {
		for ecosystem := range include {
			return ecosystem
		}
	}
	if len(ecosystems) == 1 {
		return ecosystems[0]
	}
	return EcosystemUnknown
}

func singlePackageManager(managers []PackageManager) PackageManager {
	if len(managers) == 1 {
		return managers[0]
	}
	return PackageManagerUnknown
}

func appendUniquePackageManager(values []PackageManager, value PackageManager) []PackageManager {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
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

func sortSubprojects(subprojects []Subproject) {
	sort.Slice(subprojects, func(i, j int) bool {
		if subprojects[i].RelativePath != subprojects[j].RelativePath {
			return subprojects[i].RelativePath < subprojects[j].RelativePath
		}
		return subprojects[i].PackageManager.Name() < subprojects[j].PackageManager.Name()
	})
}

func shouldSkipDiscoveryDir(name string) bool {
	switch name {
	case ".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build", "coverage", ".next", ".turbo":
		return true
	default:
		return strings.HasPrefix(name, ".") && name != "."
	}
}

func noSubprojectsError(req PrepareRequest) error {
	if len(req.IncludeEcosystems) > 0 || len(req.ExcludeEcosystems) > 0 {
		return ErrNoSubprojectsMatchedFilters
	}
	return ErrNoSubprojects
}

func isStrictSubset(left, right []string) bool {
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

func sameStringSet(left, right []string) bool {
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
