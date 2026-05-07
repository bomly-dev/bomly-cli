package engine

import (
	"sort"

	"github.com/bomly-dev/bomly-cli/internal/registry"
	model "github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// RegistryConfigs holds built-in registry wiring options resolved by the CLI layer.
type RegistryConfigs = registry.RegistryConfigs

// RegistryFilter narrows a registry down to the runtime-relevant selections.
type RegistryFilter = registry.RegistryFilter

// DetectorDiscoveryPlan describes how one detector participates in runtime planning.
type DetectorDiscoveryPlan = registry.DetectorDiscoveryPlan

// Registry wraps the shared registry with scan-specific hook registration.
type Registry struct {
	*registry.Registry
	preHooks  []PreResolveHook
	postHooks []PostResolveHook
}

// NewRegistry creates an empty scan registry.
func NewRegistry(configs RegistryConfigs, logger zap.Logger) *Registry {
	return &Registry{Registry: registry.NewRegistry(configs, logger)}
}

func (r *Registry) registerDetector(detector model.Detector) {
	if r == nil {
		return
	}
	r.Registry.RegisterDetector(detector)
}

func (r *Registry) registerMatcher(matcher model.Matcher) {
	if r == nil {
		return
	}
	r.Registry.RegisterMatcher(matcher)
}

func (r *Registry) registerAuditor(auditor model.Auditor) {
	if r == nil {
		return
	}
	r.Registry.RegisterAuditor(auditor)
}

func (r *Registry) registerDetectorDiscoveryPlan(detectorName string, plan DetectorDiscoveryPlan) {
	if r == nil {
		return
	}
	r.Registry.RegisterDetectorDiscoveryPlan(detectorName, plan)
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
	sortHooks(hooks)
	return hooks
}

// PostResolveHooks returns registered post-resolve hooks sorted by priority (ascending).
func (r *Registry) PostResolveHooks() []PostResolveHook {
	hooks := make([]PostResolveHook, len(r.postHooks))
	copy(hooks, r.postHooks)
	sortHooks(hooks)
	return hooks
}

// Filter returns a copy of the registry filtered by the supplied detector, auditor,
// matcher, and ecosystem selections.
func (r *Registry) Filter(filter RegistryFilter) *Registry {
	if r == nil {
		return nil
	}
	filtered := &Registry{
		Registry: r.Registry.Filter(filter),
	}
	filtered.preHooks = append(filtered.preHooks, r.preHooks...)
	filtered.postHooks = append(filtered.postHooks, r.postHooks...)
	return filtered
}

type hookDescriptor interface {
	Descriptor() HookDescriptor
}

func sortHooks[T hookDescriptor](hooks []T) {
	sort.Slice(hooks, func(i, j int) bool {
		return hooks[i].Descriptor().Priority < hooks[j].Descriptor().Priority
	})
}
