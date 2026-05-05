// Package runtime prepares the per-execution runtime state used by the scan pipeline.
// It owns subproject discovery and registry filtering. The CLI builds a Request and
// the pipeline consumes the resulting Runtime — neither side runs discovery on its own.
package runtime

import (
	"errors"
	"fmt"

	managedplugin "github.com/bomly-dev/bomly-cli/internal/plugin"
	"github.com/bomly-dev/bomly-cli/internal/scan"
	model "github.com/bomly-dev/bomly-cli/sdk"
)

// Request defines the inputs required to build one execution runtime.
type Request struct {
	Registry             *scan.Registry
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
	Registry        *scan.Registry
	ExecutionTarget model.ExecutionTarget
	Subprojects     []model.Subproject
	DetectorFilter  model.DetectorFilter
	AuditorFilter   model.AuditorFilter
	MatcherFilter   model.MatcherFilter
	EcosystemFilter model.EcosystemFilter
}

// ErrNoSubprojects indicates that no compatible subprojects were discovered for the runtime.
var ErrNoSubprojects = errors.New("no subprojects discovered for execution target with the applied filters")

// Prepare builds a filtered runtime and plans subprojects from the selected execution target.
func Prepare(req Request) (*Runtime, error) {
	if req.Registry == nil {
		return nil, fmt.Errorf("prepare runtime: registry is nil")
	}
	if err := managedplugin.RegisterRuntimePlugins(req.Registry, req.PluginRoot, req.PluginPolicy); err != nil {
		return nil, fmt.Errorf("prepare runtime plugins: %w", err)
	}

	filteredRegistry := req.Registry.Filter(scan.RegistryFilter{
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
