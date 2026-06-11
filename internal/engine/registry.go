package engine

import (
	"github.com/bomly-dev/bomly-cli/internal/registry"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// RegistryConfigs holds built-in registry wiring options resolved by the CLI layer.
type RegistryConfigs = registry.Configs

// RegistryFilter narrows a registry down to the runtime-relevant selections.
type RegistryFilter = registry.Filter

// DetectorDiscoveryPlan describes how one detector participates in runtime planning.
type DetectorDiscoveryPlan = registry.DetectorDiscoveryPlan

// ComponentOptions records Bomly-owned registry behavior for a component.
type ComponentOptions = registry.ComponentOptions

// Registry wraps the shared registry with scan-specific registration helpers.
type Registry struct {
	*registry.Registry
}

// NewRegistry creates an empty scan registry.
func NewRegistry(configs RegistryConfigs, logger zap.Logger) *Registry {
	return &Registry{Registry: registry.NewRegistry(configs, logger)}
}

func (r *Registry) registerDetector(detector sdk.Detector) {
	if r == nil {
		return
	}
	r.RegisterDetector(detector)
}

func (r *Registry) registerMatcher(matcher sdk.Matcher) {
	if r == nil {
		return
	}
	r.RegisterMatcher(matcher)
}

func (r *Registry) registerAuditor(auditor sdk.Auditor) {
	if r == nil {
		return
	}
	r.RegisterAuditor(auditor)
}

func (r *Registry) registerDetectorDiscoveryPlan(detectorName string, plan DetectorDiscoveryPlan) {
	if r == nil {
		return
	}
	r.RegisterDetectorDiscoveryPlan(detectorName, plan)
}

// Filter returns a copy of the registry filtered by the supplied detector, auditor,
// matcher, and ecosystem selections.
func (r *Registry) Filter(filter RegistryFilter) *Registry {
	if r == nil {
		return nil
	}
	return &Registry{
		Registry: r.Registry.Filter(filter),
	}
}
