package scan

import "sort"

// Registry holds registered detectors, auditors, matchers, and hooks.
type Registry struct {
	detectors      []Detector
	auditors       []Auditor
	matchers       []Matcher
	preHooks       []PreResolveHook
	postHooks      []PostResolveHook
	discoveryPlans map[string]DetectorDiscoveryPlan
}

// NewRegistry creates an empty scan registry.
func NewRegistry() *Registry {
	return &Registry{
		discoveryPlans: make(map[string]DetectorDiscoveryPlan),
	}
}

// RegisterDetector adds a detector to the registry.
func (r *Registry) RegisterDetector(detector Detector) {
	if detector == nil {
		return
	}
	r.detectors = append(r.detectors, detector)
}

// RegisterDetectorDiscoveryPlan records planning metadata for automatic detector discovery.
func (r *Registry) RegisterDetectorDiscoveryPlan(detectorName string, plan DetectorDiscoveryPlan) {
	if r == nil || detectorName == "" {
		return
	}
	if r.discoveryPlans == nil {
		r.discoveryPlans = make(map[string]DetectorDiscoveryPlan)
	}
	r.discoveryPlans[detectorName] = plan
}

// RegisterAuditor adds an auditor to the registry.
func (r *Registry) RegisterAuditor(auditor Auditor) {
	if auditor == nil {
		return
	}
	r.auditors = append(r.auditors, auditor)
}

// RegisterMatcher adds a matcher to the registry.
func (r *Registry) RegisterMatcher(matcher Matcher) {
	if matcher == nil {
		return
	}
	r.matchers = append(r.matchers, matcher)
}

// DetectorDescriptors returns registered detector descriptors in registration order.
func (r *Registry) DetectorDescriptors() []DetectorDescriptor {
	descriptors := make([]DetectorDescriptor, 0, len(r.detectors))
	for _, detector := range r.detectors {
		descriptors = append(descriptors, detector.Descriptor())
	}
	return descriptors
}

// AuditorDescriptors returns registered auditor descriptors sorted by name.
func (r *Registry) AuditorDescriptors() []AuditorDescriptor {
	descriptors := make([]AuditorDescriptor, 0, len(r.auditors))
	for _, auditor := range r.auditors {
		descriptors = append(descriptors, auditor.Descriptor())
	}
	sort.Slice(descriptors, func(i, j int) bool {
		return descriptors[i].Name < descriptors[j].Name
	})
	return descriptors
}

// MatcherDescriptors returns registered matcher descriptors sorted by name.
func (r *Registry) MatcherDescriptors() []MatcherDescriptor {
	descriptors := make([]MatcherDescriptor, 0, len(r.matchers))
	for _, matcher := range r.matchers {
		descriptors = append(descriptors, matcher.Descriptor())
	}
	sort.Slice(descriptors, func(i, j int) bool {
		return descriptors[i].Name < descriptors[j].Name
	})
	return descriptors
}

// Detectors returns matching detectors in registration order.
func (r *Registry) Detectors(req ResolveGraphRequest) []Detector {
	matches := make([]Detector, 0, len(r.detectors))
	for _, detector := range r.detectors {
		descriptor := detector.Descriptor()
		if !req.DetectorFilter.Includes(descriptor.Name) || req.DetectorFilter.Excludes(descriptor.Name) {
			continue
		}
		if req.Ecosystem != EcosystemUnknown && !supportsEcosystem(descriptor.SupportedEcosystems, req.Ecosystem) {
			continue
		}
		if req.PackageManager != PackageManagerUnknown && !supportsPackageManager(descriptor.SupportedManagers, req.PackageManager) {
			continue
		}
		if !supportsMode(descriptor.SupportedModes, req.Mode) {
			continue
		}
		matches = append(matches, detector)
	}
	return matches
}

// PlannedDetectors returns detectors matching the requested names in the provided order.
func (r *Registry) PlannedDetectors(req ResolveGraphRequest, names []string) []Detector {
	if len(names) == 0 {
		return r.Detectors(req)
	}

	available := make(map[string]Detector, len(r.detectors))
	for _, detector := range r.detectors {
		descriptor := detector.Descriptor()
		if !req.DetectorFilter.Includes(descriptor.Name) || req.DetectorFilter.Excludes(descriptor.Name) {
			continue
		}
		if !supportsMode(descriptor.SupportedModes, req.Mode) {
			continue
		}
		available[descriptor.Name] = detector
	}

	matches := make([]Detector, 0, len(names))
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		detector, ok := available[name]
		if !ok {
			continue
		}
		seen[name] = struct{}{}
		matches = append(matches, detector)
	}
	return matches
}

// Auditors returns matching auditors sorted by priority descending then name.
func (r *Registry) Auditors(req AuditRequest) []Auditor {
	matches := make([]Auditor, 0, len(r.auditors))
	for _, auditor := range r.auditors {
		descriptor := auditor.Descriptor()
		if !req.AuditorFilter.Includes(descriptor.Name) || req.AuditorFilter.Excludes(descriptor.Name) {
			continue
		}
		if !supportsEcosystem(descriptor.SupportedEcosystems, req.Ecosystem) {
			continue
		}
		if !supportsPackageManager(descriptor.SupportedManagers, req.PackageManager) {
			continue
		}
		if !supportsMode(descriptor.SupportedModes, req.Mode) {
			continue
		}
		matches = append(matches, auditor)
	}
	sort.Slice(matches, func(i, j int) bool {
		left := matches[i].Descriptor()
		right := matches[j].Descriptor()
		if left.Priority == right.Priority {
			return left.Name < right.Name
		}
		return left.Priority > right.Priority
	})
	return matches
}

// Matchers returns matching matchers sorted by priority descending then name.
func (r *Registry) Matchers(req MatchRequest) []Matcher {
	matches := make([]Matcher, 0, len(r.matchers))
	for _, matcher := range r.matchers {
		descriptor := matcher.Descriptor()
		if !req.MatcherFilter.Includes(descriptor.Name) || req.MatcherFilter.Excludes(descriptor.Name) {
			continue
		}
		if req.Ecosystem != EcosystemUnknown && !supportsEcosystem(descriptor.SupportedEcosystems, req.Ecosystem) {
			continue
		}
		if req.PackageManager != PackageManagerUnknown && !supportsPackageManager(descriptor.SupportedManagers, req.PackageManager) {
			continue
		}
		if !supportsMode(descriptor.SupportedModes, req.Mode) {
			continue
		}
		matches = append(matches, matcher)
	}
	sort.Slice(matches, func(i, j int) bool {
		left := matches[i].Descriptor()
		right := matches[j].Descriptor()
		if left.Priority == right.Priority {
			return left.Name < right.Name
		}
		return left.Priority > right.Priority
	})
	return matches
}

func supportsEcosystem(supported []Ecosystem, ecosystem Ecosystem) bool {
	if len(supported) == 0 {
		return true
	}
	for _, candidate := range supported {
		if candidate == ecosystem {
			return true
		}
	}
	return false
}

func supportsPackageManager(supported []PackageManager, manager PackageManager) bool {
	if len(supported) == 0 {
		return true
	}
	for _, candidate := range supported {
		if candidate == manager {
			return true
		}
	}
	return false
}

func supportsMode(supported []TargetMode, mode TargetMode) bool {
	for _, candidate := range supported {
		if candidate == mode {
			return true
		}
	}
	return false
}

// RegisterPreResolveHook adds a pre-resolve hook to the registry.
func (r *Registry) RegisterPreResolveHook(hook PreResolveHook) {
	if hook == nil {
		return
	}
	r.preHooks = append(r.preHooks, hook)
}

// RegisterPostResolveHook adds a post-resolve hook to the registry.
func (r *Registry) RegisterPostResolveHook(hook PostResolveHook) {
	if hook == nil {
		return
	}
	r.postHooks = append(r.postHooks, hook)
}

// PreResolveHooks returns registered pre-resolve hooks sorted by priority (ascending).
func (r *Registry) PreResolveHooks() []PreResolveHook {
	hooks := make([]PreResolveHook, len(r.preHooks))
	copy(hooks, r.preHooks)
	sort.Slice(hooks, func(i, j int) bool {
		return hooks[i].Descriptor().Priority < hooks[j].Descriptor().Priority
	})
	return hooks
}

// PostResolveHooks returns registered post-resolve hooks sorted by priority (ascending).
func (r *Registry) PostResolveHooks() []PostResolveHook {
	hooks := make([]PostResolveHook, len(r.postHooks))
	copy(hooks, r.postHooks)
	sort.Slice(hooks, func(i, j int) bool {
		return hooks[i].Descriptor().Priority < hooks[j].Descriptor().Priority
	})
	return hooks
}

// DiscoveryPlans returns planning metadata keyed by detector name.
func (r *Registry) DiscoveryPlans() map[string]DetectorDiscoveryPlan {
	if r == nil || len(r.discoveryPlans) == 0 {
		return nil
	}
	out := make(map[string]DetectorDiscoveryPlan, len(r.discoveryPlans))
	for name, plan := range r.discoveryPlans {
		out[name] = plan.Clone()
	}
	return out
}

// Filter returns a copy of the registry filtered by the supplied detector, auditor,
// matcher, and ecosystem selections.
func (r *Registry) Filter(filter RegistryFilter) *Registry {
	if r == nil {
		return NewRegistry()
	}

	filtered := NewRegistry()
	filtered.preHooks = append(filtered.preHooks, r.preHooks...)
	filtered.postHooks = append(filtered.postHooks, r.postHooks...)

	allowedDetectors := make(map[string]struct{}, len(r.detectors))
	for _, detector := range r.detectors {
		descriptor := detector.Descriptor()
		if !filter.DetectorFilter.Includes(descriptor.Name) || filter.DetectorFilter.Excludes(descriptor.Name) {
			continue
		}
		supportedEcosystems := descriptor.SupportedEcosystems
		if plan, ok := r.discoveryPlans[descriptor.Name]; ok {
			supportedEcosystems = mergeEcosystems(supportedEcosystems, plan.SupportedEcosystems)
		}
		if !descriptorAllowsEcosystem(supportedEcosystems, filter.IncludeEcosystems, filter.ExcludeEcosystems) {
			continue
		}
		filtered.detectors = append(filtered.detectors, detector)
		allowedDetectors[descriptor.Name] = struct{}{}
	}

	for _, auditor := range r.auditors {
		descriptor := auditor.Descriptor()
		if !filter.AuditorFilter.Includes(descriptor.Name) || filter.AuditorFilter.Excludes(descriptor.Name) {
			continue
		}
		if !descriptorAllowsEcosystem(descriptor.SupportedEcosystems, filter.IncludeEcosystems, filter.ExcludeEcosystems) {
			continue
		}
		filtered.auditors = append(filtered.auditors, auditor)
	}

	for _, matcher := range r.matchers {
		descriptor := matcher.Descriptor()
		if !filter.MatcherFilter.Includes(descriptor.Name) || filter.MatcherFilter.Excludes(descriptor.Name) {
			continue
		}
		if !descriptorAllowsEcosystem(descriptor.SupportedEcosystems, filter.IncludeEcosystems, filter.ExcludeEcosystems) {
			continue
		}
		filtered.matchers = append(filtered.matchers, matcher)
	}

	for name, plan := range r.discoveryPlans {
		if _, ok := allowedDetectors[name]; !ok {
			continue
		}
		if !descriptorAllowsEcosystem(plan.SupportedEcosystems, filter.IncludeEcosystems, filter.ExcludeEcosystems) {
			continue
		}
		filtered.discoveryPlans[name] = plan.Clone()
	}

	return filtered
}

func descriptorAllowsEcosystem(supported []Ecosystem, include, exclude map[Ecosystem]struct{}) bool {
	if len(exclude) > 0 && len(supported) > 0 {
		allExcluded := true
		for _, ecosystem := range supported {
			if _, ok := exclude[ecosystem]; !ok {
				allExcluded = false
				break
			}
		}
		if allExcluded {
			return false
		}
	}

	if len(include) == 0 {
		return true
	}
	if len(supported) == 0 {
		return true
	}
	for _, ecosystem := range supported {
		if _, ok := include[ecosystem]; ok {
			return true
		}
	}
	return false
}

func mergeEcosystems(left, right []Ecosystem) []Ecosystem {
	if len(left) == 0 {
		return append([]Ecosystem(nil), right...)
	}
	if len(right) == 0 {
		return append([]Ecosystem(nil), left...)
	}

	merged := append([]Ecosystem(nil), left...)
	seen := make(map[Ecosystem]struct{}, len(left)+len(right))
	for _, ecosystem := range left {
		seen[ecosystem] = struct{}{}
	}
	for _, ecosystem := range right {
		if _, ok := seen[ecosystem]; ok {
			continue
		}
		seen[ecosystem] = struct{}{}
		merged = append(merged, ecosystem)
	}
	return merged
}
