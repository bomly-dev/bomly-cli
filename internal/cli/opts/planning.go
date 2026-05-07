package opts

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/registry"
	"github.com/bomly-dev/bomly-cli/internal/scan"
	"github.com/bomly-dev/bomly-cli/internal/system"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// Request defines the inputs required to build one execution runtime.
type Request struct {
	Registry             *scan.Registry
	ExecutionTarget      sdk.ExecutionTarget
	ForcedPackageManager sdk.PackageManager
	DetectorFilter       sdk.DetectorFilter
	EcosystemFilter      sdk.EcosystemFilter
}

// ErrNoSubprojects indicates that no compatible subprojects were discovered for the runtime.
var ErrNoSubprojects = errors.New("no subprojects discovered for execution target with the applied filters")

// PlanSubprojects discovers subprojects for an execution target with the provided registry and filters.
func PlanSubprojects(registryValue *scan.Registry, req Request) ([]sdk.Subproject, error) {
	if req.ForcedPackageManager != sdk.PackageManagerUnknown {
		subproject, ok := plannedSubprojectForPackageManager(
			registryValue,
			req.ExecutionTarget,
			req.ExecutionTarget.Location,
			req.ForcedPackageManager,
			nil,
			req.DetectorFilter,
		)
		if !ok {
			return nil, noSubprojectsError(req)
		}
		return []sdk.Subproject{subproject}, nil
	}

	switch req.ExecutionTarget.Kind {
	case sdk.ExecutionTargetContainerImage:
		return planContainerSubprojects(registryValue, req)
	default:
		return planFilesystemSubprojects(registryValue, req)
	}
}

func planContainerSubprojects(registryValue *scan.Registry, req Request) ([]sdk.Subproject, error) {
	plans := registryValue.DiscoveryPlans()
	if len(plans) == 0 {
		return nil, noSubprojectsError(req)
	}

	subprojects := make([]sdk.Subproject, 0, len(plans))
	seen := make(map[string]struct{}, len(plans))
	for detectorName, plan := range plans {
		if !supportsTargetKind(plan.TargetKinds, sdk.ExecutionTargetContainerImage) {
			continue
		}
		detectorList := registryValue.PlannedDetectors(sdk.DetectionRequest{
			ProjectPath:     req.ExecutionTarget.Location,
			ExecutionTarget: req.ExecutionTarget,
			Ecosystem:       singleEcosystem(plan.SupportedEcosystems, req.EcosystemFilter),
			PackageManager:  singlePackageManager(plan.SupportedManagers),
			DetectorFilter:  req.DetectorFilter,
			Mode:            sdk.TargetModeFullGraph,
		}, []string{detectorName})
		chain := expandDetectorNames(registryValue, detectorList)
		if len(chain) == 0 {
			continue
		}
		key := strings.Join(chain, "|")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		subprojects = append(subprojects, sdk.Subproject{
			ExecutionTarget:         req.ExecutionTarget,
			RelativePath:            ".",
			PrimaryDetector:         chain[0],
			DetectedPackageManagers: append([]sdk.PackageManager(nil), plan.SupportedManagers...),
			PlannedDetectors:        chain,
			Ecosystem:               singleEcosystem(plan.SupportedEcosystems, req.EcosystemFilter),
		})
	}

	if len(subprojects) == 0 {
		return nil, noSubprojectsError(req)
	}
	sortSubprojects(subprojects)
	return subprojects, nil
}

func planFilesystemSubprojects(registryValue *scan.Registry, req Request) ([]sdk.Subproject, error) {
	isSingleFile, err := executionTargetIsSingleFile(req.ExecutionTarget)
	if err != nil {
		return nil, fmt.Errorf("discover subprojects: %w", err)
	}
	if isSingleFile {
		subprojects := plannedSubprojectsForPath(
			registryValue,
			req.ExecutionTarget,
			req.ExecutionTarget.Location,
			req.DetectorFilter,
			req.EcosystemFilter,
		)
		if len(subprojects) == 0 {
			return nil, noSubprojectsError(req)
		}
		return subprojects, nil
	}

	seen := map[string]sdk.Subproject{}
	for _, subproject := range plannedSubprojectsForPath(
		registryValue,
		req.ExecutionTarget,
		req.ExecutionTarget.Location,
		req.DetectorFilter,
		req.EcosystemFilter,
	) {
		seen[subprojectDedupKey(subproject)] = subproject
	}

	subprojects := make([]sdk.Subproject, 0, len(seen))
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
	registryValue *scan.Registry,
	executionTarget sdk.ExecutionTarget,
	candidatePath string,
	detectorFilter sdk.DetectorFilter,
	ecosystemFilter sdk.EcosystemFilter,
) []sdk.Subproject {
	grouped := make(map[string]*sdk.Subproject)

	for manager, evidencePatterns := range detectPackageManagersForPath(registryValue, executionTarget.Kind, candidatePath) {
		ecosystem := manager.Ecosystem()
		if len(ecosystemFilter.Include) > 0 && !ecosystemFilter.Includes(ecosystem) {
			continue
		}
		if len(ecosystemFilter.Exclude) > 0 && ecosystemFilter.Excludes(ecosystem) {
			continue
		}

		subproject, ok := plannedSubprojectForPackageManager(registryValue, executionTarget, candidatePath, manager, evidencePatterns, detectorFilter)
		if !ok {
			continue
		}
		key := subproject.RelativePath + "::" + strings.Join(subproject.PlannedDetectors, "|")
		existing, ok := grouped[key]
		if !ok {
			copyValue := subproject
			copyValue.DetectedPackageManagers = append([]sdk.PackageManager(nil), subproject.DetectedPackageManagers...)
			copyValue.PlannedDetectors = append([]string(nil), subproject.PlannedDetectors...)
			grouped[key] = &copyValue
			continue
		}
		existing.DetectedPackageManagers = appendUniquePackageManager(existing.DetectedPackageManagers, manager)
	}

	subprojects := make([]sdk.Subproject, 0, len(grouped))
	for _, subproject := range grouped {
		subprojects = append(subprojects, *subproject)
	}

	for _, subproject := range plannedPluginSubprojectsForPath(registryValue, executionTarget, candidatePath, detectorFilter, ecosystemFilter) {
		key := subproject.RelativePath + "::" + strings.Join(subproject.PlannedDetectors, "|")
		if _, ok := grouped[key]; ok {
			continue
		}
		subprojects = append(subprojects, subproject)
	}

	sortSubprojects(subprojects)
	return subprojects
}

func detectPackageManagers(candidatePath string) []sdk.PackageManager {
	managers, err := registry.DetectPackageManagers(candidatePath)
	if err != nil {
		return nil
	}
	return managers
}

func detectPackageManagersForPath(
	registryValue *scan.Registry,
	targetKind sdk.ExecutionTargetKind,
	candidatePath string,
) map[sdk.PackageManager][]string {
	detected := make(map[sdk.PackageManager][]string)
	for _, manager := range detectPackageManagers(candidatePath) {
		detected[manager] = appendUniquePatterns(detected[manager], registry.EvidencePatternsForPackageManager(manager)...)
	}

	if registryValue == nil {
		return detected
	}

	targetKinds := discoveryTargetKinds(targetKind)
	for _, planEntry := range sortedDiscoveryPlans(registryValue.DiscoveryPlans()) {
		plan := planEntry.plan
		if len(plan.SupportedManagers) == 0 {
			continue
		}
		if !supportsTargetKind(plan.TargetKinds, targetKinds...) {
			continue
		}
		if len(plan.EvidencePatterns) == 0 || !pathMatchesPatterns(candidatePath, plan.EvidencePatterns) {
			continue
		}
		for _, manager := range plan.SupportedManagers {
			detected[manager] = appendUniquePatterns(detected[manager], plan.EvidencePatterns...)
		}
	}

	return detected
}

func plannedSubprojectForPackageManager(
	registryValue *scan.Registry,
	executionTarget sdk.ExecutionTarget,
	candidatePath string,
	manager sdk.PackageManager,
	evidencePatterns []string,
	detectorFilter sdk.DetectorFilter,
) (sdk.Subproject, bool) {
	patterns := evidencePatterns
	if len(patterns) == 0 {
		patterns = registry.EvidencePatternsForPackageManager(manager)
	}
	if len(patterns) == 0 {
		return sdk.Subproject{}, false
	}

	projectPath := candidatePath
	if manager == sdk.PackageManagerSBOM {
		resolvedPath, ok := resolveMatchedManifestPath(candidatePath, patterns)
		if !ok {
			return sdk.Subproject{}, false
		}
		projectPath = resolvedPath
	}

	relPath, err := filepath.Rel(executionTarget.Location, projectPath)
	if err != nil {
		return sdk.Subproject{}, false
	}
	if relPath == "" {
		relPath = "."
	}

	resolveReq := sdk.DetectionRequest{
		ProjectPath:     projectPath,
		ExecutionTarget: executionTarget,
		Ecosystem:       manager.Ecosystem(),
		PackageManager:  manager,
		DetectorFilter:  detectorFilter,
		Mode:            sdk.TargetModeFullGraph,
	}
	chain := expandDetectorNames(registryValue, registryValue.PlannedDetectors(resolveReq, detectorNamesForPackageManager(registryValue, executionTarget.Kind, candidatePath, manager)))
	if len(chain) == 0 {
		return sdk.Subproject{}, false
	}

	return sdk.Subproject{
		ExecutionTarget:         concreteSubprojectExecutionTarget(executionTarget, projectPath),
		RelativePath:            filepath.ToSlash(relPath),
		PrimaryDetector:         chain[0],
		DetectedPackageManagers: []sdk.PackageManager{manager},
		PlannedDetectors:        chain,
		Ecosystem:               manager.Ecosystem(),
	}, true
}

func plannedPluginSubprojectsForPath(
	registryValue *scan.Registry,
	executionTarget sdk.ExecutionTarget,
	candidatePath string,
	detectorFilter sdk.DetectorFilter,
	ecosystemFilter sdk.EcosystemFilter,
) []sdk.Subproject {
	if executionTarget.Kind != sdk.ExecutionTargetFilesystem && executionTarget.Kind != sdk.ExecutionTargetGitRepository {
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

	subprojects := make([]sdk.Subproject, 0)
	for _, planEntry := range sortedDiscoveryPlans(plans) {
		detectorName := planEntry.name
		plan := planEntry.plan
		if len(plan.SupportedManagers) > 0 {
			continue
		}
		if !supportsTargetKind(plan.TargetKinds, discoveryTargetKinds(executionTarget.Kind)...) {
			continue
		}
		if len(plan.EvidencePatterns) == 0 || !pathMatchesPatterns(candidatePath, plan.EvidencePatterns) {
			continue
		}
		detectorList := registryValue.PlannedDetectors(sdk.DetectionRequest{
			ProjectPath:     candidatePath,
			ExecutionTarget: executionTarget,
			Ecosystem:       singleEcosystem(plan.SupportedEcosystems, ecosystemFilter),
			PackageManager:  singlePackageManager(plan.SupportedManagers),
			DetectorFilter:  detectorFilter,
			Mode:            sdk.TargetModeFullGraph,
		}, []string{detectorName})
		chain := expandDetectorNames(registryValue, detectorList)
		if len(chain) == 0 {
			continue
		}
		subprojects = append(subprojects, sdk.Subproject{
			ExecutionTarget:         concreteSubprojectExecutionTarget(executionTarget, candidatePath),
			RelativePath:            filepath.ToSlash(relPath),
			PrimaryDetector:         chain[0],
			DetectedPackageManagers: append([]sdk.PackageManager(nil), plan.SupportedManagers...),
			PlannedDetectors:        chain,
			Ecosystem:               singleEcosystem(plan.SupportedEcosystems, ecosystemFilter),
		})
	}
	return subprojects
}

type discoveryPlanEntry struct {
	name string
	plan registry.DetectorDiscoveryPlan
}

func sortedDiscoveryPlans(plans map[string]registry.DetectorDiscoveryPlan) []discoveryPlanEntry {
	if len(plans) == 0 {
		return nil
	}
	names := make([]string, 0, len(plans))
	for name := range plans {
		names = append(names, name)
	}
	sort.Strings(names)

	entries := make([]discoveryPlanEntry, 0, len(names))
	for _, name := range names {
		entries = append(entries, discoveryPlanEntry{name: name, plan: plans[name]})
	}
	return entries
}

func discoveryTargetKinds(targetKind sdk.ExecutionTargetKind) []sdk.ExecutionTargetKind {
	if targetKind == sdk.ExecutionTargetGitRepository {
		return []sdk.ExecutionTargetKind{sdk.ExecutionTargetGitRepository, sdk.ExecutionTargetFilesystem}
	}
	return []sdk.ExecutionTargetKind{targetKind}
}

func detectorNamesForPackageManager(
	registryValue *scan.Registry,
	targetKind sdk.ExecutionTargetKind,
	candidatePath string,
	manager sdk.PackageManager,
) []string {
	names := append([]string(nil), registry.DetectorNamesForPackageManager(manager)...)
	if registryValue == nil {
		return names
	}

	targetKinds := discoveryTargetKinds(targetKind)
	for _, planEntry := range sortedDiscoveryPlans(registryValue.DiscoveryPlans()) {
		if !supportsTargetKind(planEntry.plan.TargetKinds, targetKinds...) {
			continue
		}
		if !containsPackageManager(planEntry.plan.SupportedManagers, manager) {
			continue
		}
		if len(planEntry.plan.EvidencePatterns) > 0 && !pathMatchesPatterns(candidatePath, planEntry.plan.EvidencePatterns) {
			continue
		}
		names = appendUniqueDetectorName(names, planEntry.name)
	}
	return names
}

func containsPackageManager(managers []sdk.PackageManager, target sdk.PackageManager) bool {
	for _, manager := range managers {
		if manager == target {
			return true
		}
	}
	return false
}

func appendUniqueDetectorName(names []string, name string) []string {
	for _, existing := range names {
		if existing == name {
			return names
		}
	}
	return append(names, name)
}

func subprojectDedupKey(subproject sdk.Subproject) string {
	return strings.Join([]string{
		subproject.RelativePath,
		subproject.PrimaryPackageManager().Name(),
		strings.Join(subproject.PlannedDetectors, "|"),
	}, "::")
}

func appendUniquePatterns(existing []string, patterns ...string) []string {
	for _, pattern := range patterns {
		if pattern == "" {
			continue
		}
		seen := false
		for _, current := range existing {
			if current == pattern {
				seen = true
				break
			}
		}
		if !seen {
			existing = append(existing, pattern)
		}
	}
	return existing
}

func expandDetectorNames(registryValue *scan.Registry, detectors []sdk.Detector) []string {
	if len(detectors) == 0 {
		return nil
	}

	descriptors := registryValue.DetectorDescriptors()
	allowed := make(map[string]struct{}, len(descriptors))
	for _, descriptor := range descriptors {
		name := descriptor.Name
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

func appendDetectorChain(detector sdk.Detector, allowed map[string]struct{}, seen map[string]struct{}, names *[]string) {
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
}

func concreteSubprojectExecutionTarget(parent sdk.ExecutionTarget, location string) sdk.ExecutionTarget {
	target := parent
	target.Location = location
	if parent.Kind == sdk.ExecutionTargetContainerImage {
		return target
	}
	target.Kind = sdk.ExecutionTargetFilesystem
	return target
}

func supportsTargetKind(targetKinds []sdk.ExecutionTargetKind, candidates ...sdk.ExecutionTargetKind) bool {
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

func singleEcosystem(ecosystems []sdk.Ecosystem, ecosystemFilter sdk.EcosystemFilter) sdk.Ecosystem {
	if len(ecosystemFilter.Include) == 1 {
		return ecosystemFilter.Include[0]
	}
	if len(ecosystems) == 1 {
		return ecosystems[0]
	}
	return sdk.EcosystemUnknown
}

func singlePackageManager(managers []sdk.PackageManager) sdk.PackageManager {
	if len(managers) == 1 {
		return managers[0]
	}
	return sdk.PackageManagerUnknown
}

func appendUniquePackageManager(values []sdk.PackageManager, value sdk.PackageManager) []sdk.PackageManager {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func sortSubprojects(subprojects []sdk.Subproject) {
	sort.Slice(subprojects, func(i, j int) bool {
		if subprojects[i].RelativePath != subprojects[j].RelativePath {
			return subprojects[i].RelativePath < subprojects[j].RelativePath
		}
		return subprojects[i].PrimaryPackageManager().Name() < subprojects[j].PrimaryPackageManager().Name()
	})
}

func noSubprojectsError(req Request) error {
	var hints []string

	if len(req.DetectorFilter.Include) > 0 {
		hints = append(hints, fmt.Sprintf("--detectors %s", strings.Join(req.DetectorFilter.Include, ",")))
	}
	if len(req.DetectorFilter.Exclude) > 0 {
		hints = append(hints, fmt.Sprintf("--exclude-detectors %s", strings.Join(req.DetectorFilter.Exclude, ",")))
	}
	if len(req.EcosystemFilter.Include) > 0 {
		names := make([]string, 0, len(req.EcosystemFilter.Include))
		for _, e := range req.EcosystemFilter.Include {
			names = append(names, string(e))
		}
		sort.Strings(names)
		hints = append(hints, fmt.Sprintf("--ecosystems %s", strings.Join(names, ",")))
	}
	if len(req.EcosystemFilter.Exclude) > 0 {
		names := make([]string, 0, len(req.EcosystemFilter.Exclude))
		for _, e := range req.EcosystemFilter.Exclude {
			names = append(names, "-"+string(e))
		}
		sort.Strings(names)
		hints = append(hints, fmt.Sprintf("--ecosystems %s", strings.Join(names, ",")))
	}

	if len(hints) > 0 {
		return fmt.Errorf("%w (active filters: %s)", ErrNoSubprojects, strings.Join(hints, ", "))
	}
	return ErrNoSubprojects
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

func executionTargetIsSingleFile(executionTarget sdk.ExecutionTarget) (bool, error) {
	if executionTarget.Kind != sdk.ExecutionTargetFilesystem {
		return false, nil
	}
	info, err := os.Stat(executionTarget.Location)
	if err != nil {
		return false, err
	}
	return !info.IsDir(), nil
}
