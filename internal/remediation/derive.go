package remediation

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// Input contains the completed detection and enrichment evidence used to
// derive canonical package remediation context.
type Input struct {
	ProjectPath string
	Registry    *sdk.PackageRegistry
	Manifests   []sdk.ConsolidatedManifest
	Detections  []sdk.DetectionResult
	Detectors   map[string]sdk.Detector
}

// Warning reports a detector remediation provider failure or rejected hint.
type Warning struct {
	Source  string
	Message string
}

type vulnerabilityEvidence struct {
	version        string
	hasFixEvidence bool
	unavailable    bool
	contradictory  bool
}

type validatedHint struct {
	detectorName        string
	sourceDependencyRef string
	dependencyRef       string
	manifestPath        string
	strategies          map[sdk.RemediationAction]string
}

type detectedOccurrence struct {
	manifestPath string
	manager      sdk.PackageManager
	canonicalRef string
}

// Derive replaces every package remediation value with canonical status,
// version, and occurrence suggestions derived from completed enrichment.
// Detector providers contribute read-only package-manager evidence; they
// cannot select the final version or action.
func Derive(ctx context.Context, in Input) []Warning {
	if in.Registry == nil {
		return nil
	}
	derivePackageSummaries(in.Registry)
	hints, warnings := collectHints(ctx, in)
	deriveSuggestions(in.Registry, in.Manifests, hints)
	return warnings
}

func derivePackageSummaries(registry *sdk.PackageRegistry) {
	for _, pkg := range registry.All() {
		pkg.Remediation = derivePackageRemediation(pkg.Version, pkg.Vulnerabilities)
	}
}

func derivePackageRemediation(currentVersion string, vulnerabilities []sdk.Vulnerability) *sdk.PackageRemediation {
	if len(vulnerabilities) == 0 {
		return nil
	}

	current, _ := semver.NewVersion(strings.TrimSpace(currentVersion))
	evidence := make([]vulnerabilityEvidence, 0, len(vulnerabilities))
	hasFixEvidence := false
	allUnavailable := true
	for _, vulnerability := range vulnerabilities {
		item := remediationEvidenceForVulnerability(vulnerability, current)
		evidence = append(evidence, item)
		hasFixEvidence = hasFixEvidence || item.hasFixEvidence
		allUnavailable = allUnavailable && item.unavailable
		if item.contradictory {
			return &sdk.PackageRemediation{Status: sdk.PackageRemediationUnknown}
		}
	}

	if allUnavailable {
		return &sdk.PackageRemediation{Status: sdk.PackageRemediationUnavailable}
	}
	if !hasFixEvidence {
		return &sdk.PackageRemediation{Status: sdk.PackageRemediationUnknown}
	}

	versions := make([]string, 0, len(evidence))
	for _, item := range evidence {
		if item.version == "" {
			return &sdk.PackageRemediation{Status: sdk.PackageRemediationPartial}
		}
		versions = append(versions, item.version)
	}
	recommended, comparable := highestComparableVersion(versions)
	if !comparable {
		return &sdk.PackageRemediation{Status: sdk.PackageRemediationPartial}
	}
	return &sdk.PackageRemediation{
		Status:             sdk.PackageRemediationComplete,
		RecommendedVersion: recommended,
	}
}

func remediationEvidenceForVulnerability(
	vulnerability sdk.Vulnerability,
	current *semver.Version,
) vulnerabilityEvidence {
	values := preferredFixVersions(vulnerability)
	explicitlyUnavailable := vulnerability.FixState == sdk.FixStateNotFixed ||
		vulnerability.FixState == sdk.FixStateWontFix
	if len(values) == 0 {
		return vulnerabilityEvidence{unavailable: explicitlyUnavailable}
	}
	if explicitlyUnavailable {
		return vulnerabilityEvidence{
			hasFixEvidence: true,
			contradictory:  true,
		}
	}
	if current != nil {
		var comparable bool
		values, comparable = versionsNewerThan(values, current)
		if !comparable || len(values) == 0 {
			return vulnerabilityEvidence{hasFixEvidence: true}
		}
	}

	version, comparable := lowestComparableVersion(values)
	if !comparable {
		return vulnerabilityEvidence{hasFixEvidence: true}
	}
	return vulnerabilityEvidence{
		version:        version,
		hasFixEvidence: true,
	}
}

func preferredFixVersions(vulnerability sdk.Vulnerability) []string {
	if value := strings.TrimSpace(vulnerability.FixedIn); value != "" {
		return []string{value}
	}

	available := make([]string, 0, len(vulnerability.FixAvailable))
	for _, fix := range vulnerability.FixAvailable {
		if value := strings.TrimSpace(fix.Version); value != "" {
			available = append(available, value)
		}
	}
	if len(available) > 0 {
		return uniqueSortedVersions(available)
	}

	fixed := make([]string, 0, len(vulnerability.FixedVersions))
	for _, version := range vulnerability.FixedVersions {
		if value := strings.TrimSpace(version); value != "" {
			fixed = append(fixed, value)
		}
	}
	return uniqueSortedVersions(fixed)
}

func versionsNewerThan(values []string, current *semver.Version) ([]string, bool) {
	newer := make([]string, 0, len(values))
	for _, value := range values {
		candidate, err := semver.NewVersion(strings.TrimSpace(value))
		if err != nil {
			return nil, false
		}
		if candidate.GreaterThan(current) {
			newer = append(newer, value)
		}
	}
	return newer, true
}

func uniqueSortedVersions(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	unique := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		unique = append(unique, value)
	}
	sort.Strings(unique)
	return unique
}

func lowestComparableVersion(values []string) (string, bool) {
	return selectComparableVersion(values, false)
}

func highestComparableVersion(values []string) (string, bool) {
	return selectComparableVersion(values, true)
}

func selectComparableVersion(values []string, highest bool) (string, bool) {
	if len(values) == 0 {
		return "", false
	}
	selected := strings.TrimSpace(values[0])
	if selected == "" {
		return "", false
	}
	if len(values) == 1 {
		return selected, true
	}

	selectedSemver, err := semver.NewVersion(selected)
	if err != nil {
		for _, value := range values[1:] {
			if strings.TrimSpace(value) != selected {
				return "", false
			}
		}
		return selected, true
	}
	for _, value := range values[1:] {
		candidate := strings.TrimSpace(value)
		candidateSemver, err := semver.NewVersion(candidate)
		if err != nil {
			return "", false
		}
		comparison := candidateSemver.Compare(selectedSemver)
		if (highest && comparison > 0) || (!highest && comparison < 0) {
			selected = candidate
			selectedSemver = candidateSemver
		}
	}
	return selected, true
}

func collectHints(ctx context.Context, in Input) ([]validatedHint, []Warning) {
	var hints []validatedHint
	var warnings []Warning
	for _, detection := range in.Detections {
		detector := in.Detectors[detection.DetectorName]
		if detector == nil {
			continue
		}
		descriptor := detector.Descriptor()
		if len(descriptor.RemediationCapabilities) == 0 {
			continue
		}
		provider, ok := detector.(sdk.DetectorRemediationProvider)
		if !ok {
			warnings = append(warnings, Warning{
				Source:  detection.DetectorName,
				Message: "detector advertises remediation capabilities but does not implement the provider",
			})
			continue
		}
		response, err := provider.RemediationHints(ctx, sdk.RemediationHintRequest{
			ProjectPath: in.ProjectPath,
			Detection:   cloneDetectionResult(detection),
			Registry:    cloneRegistry(in.Registry),
		})
		if err != nil {
			warnings = append(warnings, Warning{Source: detection.DetectorName, Message: err.Error()})
			continue
		}
		for _, diagnostic := range response.Diagnostics {
			if message := strings.TrimSpace(diagnostic); message != "" {
				warnings = append(warnings, Warning{Source: detection.DetectorName, Message: message})
			}
		}
		validated, rejected := validateHints(detection, descriptor, response.Hints)
		for idx := range validated {
			validated[idx].detectorName = detection.DetectorName
			manifestPath, dependencyRef, ok := selectedOccurrence(
				in.ProjectPath,
				in.Manifests,
				detection.DetectorName,
				validated[idx].manifestPath,
				validated[idx].dependencyRef,
				validated[idx].sourceDependencyRef,
			)
			if !ok {
				validated[idx].dependencyRef = ""
				continue
			}
			validated[idx].manifestPath = manifestPath
			validated[idx].dependencyRef = dependencyRef
		}
		for _, hint := range validated {
			if hint.dependencyRef != "" {
				hints = append(hints, hint)
			}
		}
		for _, message := range rejected {
			warnings = append(warnings, Warning{Source: detection.DetectorName, Message: message})
		}
	}
	return hints, warnings
}

func validateHints(
	detection sdk.DetectionResult,
	descriptor sdk.DetectorDescriptor,
	raw []sdk.RemediationHint,
) ([]validatedHint, []string) {
	occurrences := detectionOccurrences(detection, descriptor)
	var valid []validatedHint
	var rejected []string
	for _, hint := range raw {
		dependencyRef := strings.TrimSpace(hint.DependencyRef)
		manifestPath := strings.TrimSpace(hint.ManifestPath)
		detected, ok := occurrences[dependencyRef]
		if dependencyRef == "" || !ok {
			rejected = append(rejected, fmt.Sprintf("ignored remediation hint for unknown dependency %q", dependencyRef))
			continue
		}
		if manifestPath != "" {
			occurrence, ok := occurrenceForManifest(detected, manifestPath)
			if !ok {
				rejected = append(rejected, fmt.Sprintf("ignored remediation hint for dependency %q and unknown manifest %q", dependencyRef, manifestPath))
				continue
			}
			detected = []detectedOccurrence{occurrence}
		} else if len(detected) == 1 {
			manifestPath = detected[0].manifestPath
		} else {
			rejected = append(rejected, fmt.Sprintf("ignored ambiguous remediation hint for dependency %q", dependencyRef))
			continue
		}

		advertised := advertisedActions(descriptor.RemediationCapabilities, detected[0].manager)
		strategies := map[sdk.RemediationAction]string{}
		for _, strategy := range hint.Strategies {
			if _, ok := advertised[strategy.Action]; !ok {
				rejected = append(rejected, fmt.Sprintf("ignored unadvertised remediation action %q for dependency %q", strategy.Action, dependencyRef))
				continue
			}
			switch strategy.Action {
			case sdk.RemediationActionDirectBump,
				sdk.RemediationActionTransitiveOverride,
				sdk.RemediationActionLockfileRefresh:
				strategies[strategy.Action] = strings.TrimSpace(strategy.Advice)
			default:
				rejected = append(rejected, fmt.Sprintf("ignored detector-owned remediation decision %q for dependency %q", strategy.Action, dependencyRef))
			}
		}
		if len(strategies) > 0 {
			valid = append(valid, validatedHint{
				sourceDependencyRef: dependencyRef,
				dependencyRef:       detected[0].canonicalRef,
				manifestPath:        manifestPath,
				strategies:          strategies,
			})
		}
	}
	return valid, rejected
}

func detectionOccurrences(
	detection sdk.DetectionResult,
	descriptor sdk.DetectorDescriptor,
) map[string][]detectedOccurrence {
	result := map[string][]detectedOccurrence{}
	if detection.Graphs == nil {
		return result
	}
	for _, entry := range detection.Graphs.Entries {
		if entry.Graph == nil {
			continue
		}
		path := strings.TrimSpace(entry.Manifest.Path)
		for _, dependency := range entry.Graph.Nodes() {
			if dependency == nil || dependency.ID == "" {
				continue
			}
			manager := dependency.PackageManager
			if manager == sdk.PackageManagerUnknown {
				manager = detectedManager(detection.SubprojectInfo, descriptor)
			}
			occurrence := detectedOccurrence{
				manifestPath: path,
				manager:      manager,
				canonicalRef: canonicalDependencyRef(dependency),
			}
			result[dependency.ID] = append(result[dependency.ID], occurrence)
		}
	}
	return result
}

func detectedManager(
	subproject sdk.Subproject,
	descriptor sdk.DetectorDescriptor,
) sdk.PackageManager {
	for _, detected := range subproject.DetectedPackageManagers {
		if containsManager(descriptor.SupportedManagers, detected) {
			return detected
		}
	}
	if len(descriptor.SupportedManagers) == 1 {
		return descriptor.SupportedManagers[0]
	}
	return sdk.PackageManagerUnknown
}

func canonicalDependencyRef(dependency *sdk.Dependency) string {
	if dependency == nil {
		return ""
	}
	if purl := sdk.CanonicalPackageURLFromDependency(dependency); purl != "" {
		return purl
	}
	return dependency.ID
}

func selectedOccurrence(
	projectPath string,
	manifests []sdk.ConsolidatedManifest,
	detectorName string,
	rawManifestPath string,
	dependencyRef string,
	sourceDependencyRef string,
) (string, string, bool) {
	if path, ok := selectedManifestForDependency(
		projectPath,
		manifests,
		detectorName,
		rawManifestPath,
		dependencyRef,
	); ok {
		return path, dependencyRef, true
	}
	if sourceDependencyRef != dependencyRef {
		if path, ok := selectedManifestForDependency(
			projectPath,
			manifests,
			detectorName,
			rawManifestPath,
			sourceDependencyRef,
		); ok {
			return path, sourceDependencyRef, true
		}
	}
	return "", "", false
}

func selectedManifestForDependency(
	projectPath string,
	manifests []sdk.ConsolidatedManifest,
	detectorName string,
	rawManifestPath string,
	dependencyRef string,
) (string, bool) {
	raw := normalizeManifestPath(projectPath, rawManifestPath)
	var candidates []string
	for _, manifest := range manifests {
		if manifest.DetectorName != detectorName || manifest.Entry.Graph == nil {
			continue
		}
		if _, ok := manifest.Entry.Graph.Node(dependencyRef); !ok {
			continue
		}
		candidate := normalizeManifestPath(projectPath, manifest.Entry.Manifest.Path)
		if candidate == raw ||
			strings.HasSuffix(raw, "/"+candidate) ||
			strings.HasSuffix(candidate, "/"+raw) {
			return manifest.Entry.Manifest.Path, true
		}
		candidates = append(candidates, manifest.Entry.Manifest.Path)
	}
	if len(candidates) == 1 {
		return candidates[0], true
	}
	return "", false
}

func normalizeManifestPath(projectPath, value string) string {
	value = strings.Trim(strings.ReplaceAll(strings.TrimSpace(value), "\\", "/"), "/")
	projectPath = strings.Trim(strings.ReplaceAll(strings.TrimSpace(projectPath), "\\", "/"), "/")
	if projectPath != "" {
		value = strings.TrimPrefix(value, projectPath)
		value = strings.TrimPrefix(value, "/")
	}
	return value
}

func occurrenceForManifest(occurrences []detectedOccurrence, manifestPath string) (detectedOccurrence, bool) {
	for _, occurrence := range occurrences {
		if occurrence.manifestPath == manifestPath {
			return occurrence, true
		}
	}
	return detectedOccurrence{}, false
}

func advertisedActions(
	capabilities []sdk.RemediationCapability,
	manager sdk.PackageManager,
) map[sdk.RemediationAction]struct{} {
	result := map[sdk.RemediationAction]struct{}{}
	for _, capability := range capabilities {
		if !containsManager(capability.SupportedManagers, manager) {
			continue
		}
		for _, action := range capability.Actions {
			result[action] = struct{}{}
		}
	}
	return result
}

func containsManager(managers []sdk.PackageManager, target sdk.PackageManager) bool {
	for _, manager := range managers {
		if manager == target {
			return true
		}
	}
	return false
}

func deriveSuggestions(
	registry *sdk.PackageRegistry,
	manifests []sdk.ConsolidatedManifest,
	hints []validatedHint,
) {
	hintsByOccurrence := map[string]validatedHint{}
	for _, hint := range hints {
		key := hint.detectorName + "\x00" + hint.manifestPath + "\x00" + hint.dependencyRef
		hintsByOccurrence[key] = hint
	}

	type suggestionKey struct {
		packageRef string
		targetRef  string
		manifest   string
		action     sdk.RemediationAction
		advice     string
	}
	grouped := map[suggestionKey]map[string]struct{}{}
	for _, manifest := range manifests {
		graph := manifest.Entry.Graph
		if graph == nil {
			continue
		}
		manifestPath := strings.TrimSpace(manifest.Entry.Manifest.Path)
		for _, dependency := range graph.Nodes() {
			if dependency == nil || dependency.PackageRef == "" {
				continue
			}
			pkg, ok := registry.Get(dependency.PackageRef)
			if !ok || pkg == nil || pkg.Remediation == nil {
				continue
			}
			hintKey := manifest.DetectorName + "\x00" + manifestPath + "\x00" + dependency.ID
			hint := hintsByOccurrence[hintKey]
			action, targetRef, advice := selectAction(graph, dependency, pkg.Remediation, hint)
			key := suggestionKey{
				packageRef: dependency.PackageRef,
				targetRef:  targetRef,
				manifest:   manifestPath,
				action:     action,
				advice:     advice,
			}
			if grouped[key] == nil {
				grouped[key] = map[string]struct{}{}
			}
			grouped[key][dependency.ID] = struct{}{}
		}
	}

	for _, pkg := range registry.All() {
		if pkg.Remediation != nil {
			pkg.Remediation.Suggestions = nil
		}
	}
	keys := make([]suggestionKey, 0, len(grouped))
	for key := range grouped {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].packageRef != keys[j].packageRef {
			return keys[i].packageRef < keys[j].packageRef
		}
		if keys[i].manifest != keys[j].manifest {
			return keys[i].manifest < keys[j].manifest
		}
		if keys[i].action != keys[j].action {
			return keys[i].action < keys[j].action
		}
		if keys[i].targetRef != keys[j].targetRef {
			return keys[i].targetRef < keys[j].targetRef
		}
		return keys[i].advice < keys[j].advice
	})
	for _, key := range keys {
		pkg, ok := registry.Get(key.packageRef)
		if !ok || pkg == nil || pkg.Remediation == nil {
			continue
		}
		refs := make([]string, 0, len(grouped[key]))
		for ref := range grouped[key] {
			refs = append(refs, ref)
		}
		sort.Strings(refs)
		pkg.Remediation.Suggestions = append(pkg.Remediation.Suggestions, sdk.PackageRemediationSuggestion{
			DependencyRefs:      refs,
			TargetDependencyRef: key.targetRef,
			ManifestPath:        key.manifest,
			Action:              key.action,
			OverrideAdvice:      key.advice,
		})
	}
}

func selectAction(
	graph *sdk.Graph,
	dependency *sdk.Dependency,
	remediation *sdk.PackageRemediation,
	hint validatedHint,
) (sdk.RemediationAction, string, string) {
	targetRef := dependency.ID
	relationship := dependency.Relationship
	if relationship == "" {
		var ok bool
		relationship, targetRef, ok = inferredPlacement(graph, dependency.ID)
		if !ok {
			relationship = sdk.DependencyRelationshipUnknown
			targetRef = dependency.ID
		}
	}
	if remediation.Status == sdk.PackageRemediationUnavailable {
		return sdk.RemediationActionNoFixUpstream, targetRef, ""
	}
	if remediation.Status != sdk.PackageRemediationComplete ||
		!dependency.RegistryMatchEligible() ||
		relationship == sdk.DependencyRelationshipUnknown {
		return sdk.RemediationActionManualReview, targetRef, ""
	}

	switch relationship {
	case sdk.DependencyRelationshipDirect:
		if _, ok := hint.strategies[sdk.RemediationActionDirectBump]; ok {
			return sdk.RemediationActionDirectBump, targetRef, ""
		}
	case sdk.DependencyRelationshipTransitive:
		if dependency.Relationship == sdk.DependencyRelationshipTransitive {
			var ok bool
			_, targetRef, ok = inferredPlacement(graph, dependency.ID)
			if !ok {
				return sdk.RemediationActionManualReview, dependency.ID, ""
			}
		}
		if targetRef == dependency.ID {
			return sdk.RemediationActionManualReview, dependency.ID, ""
		}
		if advice, ok := hint.strategies[sdk.RemediationActionTransitiveOverride]; ok {
			return sdk.RemediationActionTransitiveOverride, targetRef, advice
		}
		if _, ok := hint.strategies[sdk.RemediationActionLockfileRefresh]; ok {
			return sdk.RemediationActionLockfileRefresh, targetRef, ""
		}
	default:
		return sdk.RemediationActionManualReview, targetRef, ""
	}
	return sdk.RemediationActionManualReview, targetRef, ""
}

type placementState struct {
	nodeID string
	path   []string
}

func inferredPlacement(
	graph *sdk.Graph,
	dependencyID string,
) (sdk.DependencyRelationship, string, bool) {
	if graph == nil {
		return sdk.DependencyRelationshipUnknown, dependencyID, false
	}
	if _, ok := graph.Node(dependencyID); !ok {
		return sdk.DependencyRelationshipUnknown, dependencyID, false
	}

	queue := []placementState{{nodeID: dependencyID, path: []string{dependencyID}}}
	bestDistance := map[string]int{dependencyID: 0}
	var candidates []placementState
	shortest := -1
	for len(queue) > 0 {
		state := queue[0]
		queue = queue[1:]
		distance := len(state.path) - 1
		if shortest >= 0 && distance > shortest {
			continue
		}
		parents, err := graph.Dependents(state.nodeID)
		if err != nil {
			continue
		}
		if len(parents) == 0 {
			root, _ := graph.Node(state.nodeID)
			if executableRoot(root) && len(state.path) >= 2 {
				shortest = distance
				candidates = append(candidates, state)
			}
			continue
		}
		for _, parent := range parents {
			if parent == nil {
				continue
			}
			nextDistance := distance + 1
			if previous, seen := bestDistance[parent.ID]; seen && previous < nextDistance {
				continue
			}
			bestDistance[parent.ID] = nextDistance
			path := append(append([]string(nil), state.path...), parent.ID)
			queue = append(queue, placementState{nodeID: parent.ID, path: path})
		}
	}
	if len(candidates) == 0 {
		return sdk.DependencyRelationshipUnknown, dependencyID, false
	}
	sort.Slice(candidates, func(i, j int) bool {
		return strings.Join(candidates[i].path, "\x00") < strings.Join(candidates[j].path, "\x00")
	})
	path := candidates[0].path
	if len(path) == 2 {
		return sdk.DependencyRelationshipDirect, dependencyID, true
	}
	return sdk.DependencyRelationshipTransitive, path[len(path)-2], true
}

func executableRoot(dependency *sdk.Dependency) bool {
	if dependency == nil || dependency.Type == sdk.PackageTypeManifest {
		return false
	}
	return dependency.FirstParty ||
		dependency.Source == sdk.DependencySourceProject ||
		dependency.Type == sdk.PackageTypeApplication
}

func cloneRegistry(registry *sdk.PackageRegistry) *sdk.PackageRegistry {
	if registry == nil {
		return nil
	}
	clone := sdk.NewPackageRegistry()
	for _, pkg := range registry.All() {
		clone.Add(pkg.Clone())
	}
	return clone
}

func cloneDetectionResult(result sdk.DetectionResult) sdk.DetectionResult {
	clone := result
	if result.Graphs == nil {
		return clone
	}
	clone.Graphs = &sdk.GraphContainer{Entries: make([]sdk.GraphEntry, 0, len(result.Graphs.Entries))}
	for _, entry := range result.Graphs.Entries {
		entryClone := entry
		entryClone.Graph = cloneGraph(entry.Graph)
		if entry.Manifest.Resolution != nil {
			resolution := *entry.Manifest.Resolution
			resolution.InstallCommand = append([]string(nil), entry.Manifest.Resolution.InstallCommand...)
			if entry.Manifest.Resolution.Fallback != nil {
				fallback := *entry.Manifest.Resolution.Fallback
				resolution.Fallback = &fallback
			}
			entryClone.Manifest.Resolution = &resolution
		}
		if len(entry.Packages) > 0 {
			entryClone.Packages = make([]*sdk.Package, 0, len(entry.Packages))
			for _, pkg := range entry.Packages {
				entryClone.Packages = append(entryClone.Packages, pkg.Clone())
			}
		}
		clone.Graphs.Entries = append(clone.Graphs.Entries, entryClone)
	}
	return clone
}

func cloneGraph(graph *sdk.Graph) *sdk.Graph {
	if graph == nil {
		return nil
	}
	clone := sdk.NewWithCapacity(graph.Size())
	for _, dependency := range graph.Nodes() {
		_ = clone.AddNode(dependency.Clone())
	}
	for _, dependency := range graph.Nodes() {
		children, err := graph.DirectDependencies(dependency.ID)
		if err != nil {
			continue
		}
		for _, child := range children {
			_ = clone.AddEdge(dependency.ID, child.ID)
		}
	}
	return clone
}
