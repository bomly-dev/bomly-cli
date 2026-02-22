package scan

import (
	"errors"
	"fmt"

	managedplugin "github.com/bomly-dev/bomly-cli/internal/plugin"
	model "github.com/bomly-dev/bomly-cli/sdk"
)

// PrepareRequest defines the inputs required to build one execution runtime.
type PrepareRequest struct {
	Registry             *Registry
	ExecutionTarget      model.ExecutionTarget
	ForcedPackageManager model.PackageManager
	DetectorFilter       model.DetectorFilter
	AuditorFilter        model.AuditorFilter
	MatcherFilter        model.MatcherFilter
	EcosystemFilter      model.EcosystemFilter
	PluginRoot           string
	PluginPolicy         managedplugin.ExecutionPolicy
}

// Runtime is the prepared execution state reused across resolution, matching, and audit.
type Runtime struct {
	Registry        *Registry
	ExecutionTarget model.ExecutionTarget
	Subprojects     []model.Subproject
	DetectorFilter  model.DetectorFilter
	AuditorFilter   model.AuditorFilter
	MatcherFilter   model.MatcherFilter
	EcosystemFilter model.EcosystemFilter
}

var (
	// ErrNoSubprojects indicates that no compatible subprojects were discovered for the runtime.
	ErrNoSubprojects = errors.New("no subprojects discovered for execution target with the applied filters")
)

// Prepare builds a filtered runtime and plans subprojects from the selected execution target.
func Prepare(req PrepareRequest) (*Runtime, error) {
	if req.Registry == nil {
		return nil, fmt.Errorf("prepare runtime: registry is nil")
	}
	if err := managedplugin.RegisterRuntimePlugins(req.Registry, req.PluginRoot, req.PluginPolicy); err != nil {
		return nil, fmt.Errorf("prepare runtime plugins: %w", err)
	}

	filteredRegistry := req.Registry.Filter(RegistryFilter{
		DetectorFilter:  req.DetectorFilter,
		AuditorFilter:   req.AuditorFilter,
		MatcherFilter:   req.MatcherFilter,
		EcosystemFilter: req.EcosystemFilter,
	})

	subprojects, err := planSubprojects(filteredRegistry, req)
	if err != nil {
		return nil, err
	}

	return &Runtime{
		Registry:        filteredRegistry,
		ExecutionTarget: req.ExecutionTarget,
		Subprojects:     subprojects,
		DetectorFilter:  req.DetectorFilter,
		AuditorFilter:   req.AuditorFilter,
		MatcherFilter:   req.MatcherFilter,
		EcosystemFilter: req.EcosystemFilter,
	}, nil
}
