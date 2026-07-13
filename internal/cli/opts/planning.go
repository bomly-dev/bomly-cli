package opts

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/cli/exit"
	"github.com/bomly-dev/bomly-cli/internal/engine"
	"github.com/bomly-dev/bomly-cli/internal/registry"
	"github.com/bomly-dev/bomly-cli/internal/system"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// Request defines the inputs required to build one execution runtime.
type Request struct {
	Registry             *engine.Registry
	ExecutionTarget      sdk.ExecutionTarget
	ForcedPackageManager sdk.PackageManager
	DetectorFilter       sdk.DetectorFilter
	EcosystemFilter      sdk.EcosystemFilter
	// Recursive enables nested-manifest discovery below the execution-target
	// root. MaxDepth bounds the walk (0 = unlimited) and ExcludeGlobs adds
	// root-relative glob skips on top of the built-in ignore rules. Both are
	// only consulted when Recursive is set.
	Recursive    bool
	MaxDepth     int
	ExcludeGlobs []string
	// Logger receives discovery progress diagnostics; nil is treated as no-op.
	Logger *zap.Logger
}

// ErrNoSubprojects indicates that no compatible subprojects were discovered for the runtime.
var ErrNoSubprojects = errors.New("no subprojects discovered for execution target with the applied filters")

// PlanSubprojects discovers subprojects for an execution target with the provided registry and filters.
func PlanSubprojects(registryValue *engine.Registry, req Request) ([]sdk.Subproject, error) {
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

func planContainerSubprojects(registryValue *engine.Registry, req Request) ([]sdk.Subproject, error) {
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

func planFilesystemSubprojects(registryValue *engine.Registry, req Request) ([]sdk.Subproject, error) {
	isSingleFile, err := executionTargetIsSingleFile(req.ExecutionTarget)
	if err != nil {
		return nil, fmt.Errorf("discover subprojects: %w", err)
	}
	if isSingleFile {
		if req.Recursive {
			return nil, exit.InvalidInputError("--recursive requires a directory target, got file %s", req.ExecutionTarget.Location)
		}
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

	if req.Recursive {
		return planRecursiveFilesystemSubprojects(registryValue, req)
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
	registryValue *engine.Registry,
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
	registryValue *engine.Registry,
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
	registryValue *engine.Registry,
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
	registryValue *engine.Registry,
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
	registryValue *engine.Registry,
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

func expandDetectorNames(registryValue *engine.Registry, detectors []sdk.Detector) []string {
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

	// Wrap as a "nothing to evaluate" exit (5), distinct from a resolution
	// failure (3): no subprojects were discovered at all, which CI wrappers can
	// treat as a neutral pass. ErrNoSubprojects stays the inner sentinel so
	// errors.Is(err, ErrNoSubprojects) callers keep working.
	err := ErrNoSubprojects
	if req.Recursive {
		err = fmt.Errorf("%w (recursive discovery, max depth %s, %d exclude pattern(s))", err, describeMaxDepth(req.MaxDepth), len(req.ExcludeGlobs))
	}
	if len(hints) > 0 {
		err = fmt.Errorf("%w (active filters: %s)", err, strings.Join(hints, ", "))
	}
	findings, truncated := describeDiscoveryFindings(req.ExecutionTarget)
	if probe := renderDiscoveryProbe(req.ExecutionTarget, findings, truncated); len(probe) > 0 {
		err = fmt.Errorf("%w; discovery probe: %s", err, strings.Join(probe, "; "))
	}
	if !req.Recursive {
		if nested := firstNestedFinding(findings); nested != "" {
			err = fmt.Errorf("%w; hint: manifests exist in subdirectories (e.g. %s); retry with --recursive", err, nested)
		}
	}
	return exit.NothingToEvaluateError(err)
}

// describeMaxDepth renders a depth cap for error messages (0 = unlimited).
func describeMaxDepth(maxDepth int) string {
	if maxDepth <= 0 {
		return "unlimited"
	}
	return fmt.Sprintf("%d", maxDepth)
}

// firstNestedFinding returns the relative path of the first discovery finding
// below the target root, or "" when all evidence sits at the root.
func firstNestedFinding(findings []discoveryFinding) string {
	for _, finding := range findings {
		if finding.RelativePath != "." && finding.RelativePath != "" {
			return finding.RelativePath
		}
	}
	return ""
}

// discoveryProbe limits for DescribeDiscovery: how deep below the target to
// look for manifest evidence and how many findings to report.
const (
	discoveryProbeMaxDepth = 3
	discoveryProbeMaxLines = 8
)

// discoveryFinding is one piece of manifest evidence surfaced by the
// diagnostic discovery probe: which manifest pattern exists, in which
// root-relative directory, and which package manager it belongs to.
type discoveryFinding struct {
	RelativePath string
	Manager      sdk.PackageManager
	Evidence     string
}

// DescribeDiscovery probes a filesystem execution target for known manifest
// evidence (drawn from the built-in package-manager support catalog) so a
// "no subprojects discovered" failure explains itself: which manifest files
// exist, where, and which package manager they belong to. Returns nil for
// non-filesystem targets.
func DescribeDiscovery(target sdk.ExecutionTarget) []string {
	findings, truncated := describeDiscoveryFindings(target)
	return renderDiscoveryProbe(target, findings, truncated)
}

// describeDiscoveryFindings walks the target (bounded by
// discoveryProbeMaxDepth / discoveryProbeMaxLines and the shared skip rules)
// and returns the manifest evidence it saw, plus whether output was truncated.
func describeDiscoveryFindings(target sdk.ExecutionTarget) ([]discoveryFinding, bool) {
	if strings.TrimSpace(target.Location) == "" {
		return nil, false
	}
	switch target.Kind {
	case sdk.ExecutionTargetFilesystem, sdk.ExecutionTargetGitRepository, "":
	default:
		return nil, false
	}
	root, err := filepath.Abs(target.Location)
	if err != nil {
		return nil, false
	}

	var findings []discoveryFinding
	truncated := false
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil //nolint:nilerr // best-effort probe: skip unreadable entries
		}
		if !entry.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return nil //nolint:nilerr // best-effort probe
		}
		rel = filepath.ToSlash(rel)
		if rel != "." && shouldSkipDiscoveryDir(entry.Name(), path) {
			return filepath.SkipDir
		}
		if discoveryDepth(rel) > discoveryProbeMaxDepth {
			return filepath.SkipDir
		}
		if len(findings) >= discoveryProbeMaxLines {
			truncated = true
			return filepath.SkipAll
		}
		managers, detectErr := registry.DetectPackageManagers(path)
		if detectErr != nil {
			return nil //nolint:nilerr // best-effort probe
		}
		for idx, manager := range managers {
			evidence := firstEvidenceInDir(path, registry.EvidencePatternsForPackageManager(manager))
			findings = append(findings, discoveryFinding{RelativePath: rel, Manager: manager, Evidence: evidence})
			if len(findings) >= discoveryProbeMaxLines {
				if idx < len(managers)-1 {
					truncated = true
				}
				break
			}
		}
		return nil
	})
	return findings, truncated
}

// renderDiscoveryProbe formats probe findings for the "no subprojects
// discovered" error text. Returns nil for targets the probe does not cover.
func renderDiscoveryProbe(target sdk.ExecutionTarget, findings []discoveryFinding, truncated bool) []string {
	if strings.TrimSpace(target.Location) == "" {
		return nil
	}
	switch target.Kind {
	case sdk.ExecutionTargetFilesystem, sdk.ExecutionTargetGitRepository, "":
	default:
		return nil
	}
	if len(findings) == 0 {
		root, err := filepath.Abs(target.Location)
		if err != nil {
			return nil
		}
		return []string{fmt.Sprintf("no known manifest files found under %s (depth <= %d)", root, discoveryProbeMaxDepth)}
	}
	lines := make([]string, 0, len(findings)+1)
	for _, finding := range findings {
		lines = append(lines, fmt.Sprintf("found %s at %s (%s)", valueOrPattern(finding.Evidence, "manifest evidence"), finding.RelativePath, finding.Manager.Name()))
	}
	if truncated {
		lines = append(lines, "…")
	}
	return lines
}

// firstEvidenceInDir names the first evidence pattern that exists in dir.
func firstEvidenceInDir(dir string, patterns []string) string {
	for _, pattern := range patterns {
		if patternExists(dir, pattern) {
			return pattern
		}
	}
	return ""
}

func valueOrPattern(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
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
