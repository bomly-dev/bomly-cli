package plugin

import (
	"context"

	"github.com/bomly/bomly-cli/internal/scan"
)

// Detector adapts plugin graph resolution to the shared scan.Detector contract.
type Detector struct {
	PluginName          string
	DetectorName        string
	Subcommand          string
	SupportedEcosystems []scan.Ecosystem
	PackageManagers     []scan.PackageManager
	CoreVersion         string
	DiscoverOptions     DiscoverOptions
}

// Descriptor describes the plugin-backed detector.
func (d Detector) Descriptor() scan.DetectorDescriptor {
	detectorName := d.DetectorName
	if detectorName == "" {
		detectorName = d.PluginName + "-plugin-detector"
	}
	supportedEcosystems := append([]scan.Ecosystem(nil), d.SupportedEcosystems...)
	if len(supportedEcosystems) == 0 && d.PluginName != "" {
		supportedEcosystems = []scan.Ecosystem{scan.Ecosystem(d.PluginName)}
	}
	return scan.DetectorDescriptor{
		Name:                detectorName,
		ImplementationType:  scan.PluginDetector,
		SupportedEcosystems: supportedEcosystems,
		SupportedManagers:   d.PackageManagers,
		SupportedModes:      []scan.TargetMode{scan.TargetModeFullGraph, scan.TargetModeComponent},
		Capabilities:        []string{"graph-resolution", "component-targeting"},
	}
}

// Ready reports the detector is always ready — plugin availability is checked during resolve.
func (d Detector) Ready() bool { return true }

// Applicable reports whether the detector applies to the given request.
func (d Detector) Applicable(_ context.Context, _ scan.ResolveGraphRequest) (bool, error) {
	return true, nil
}

// ResolveGraph resolves graph data via the plugin boundary using the JSON envelope protocol.
func (d Detector) ResolveGraph(_ context.Context, req scan.ResolveGraphRequest) (scan.ResolveGraphResult, error) {
	return d.resolveWithEnvelope(req)
}

func (d Detector) resolveWithEnvelope(req scan.ResolveGraphRequest) (scan.ResolveGraphResult, error) {
	plugins, err := Discover(d.DiscoverOptions)
	if err != nil {
		return scan.ResolveGraphResult{}, err
	}

	pluginInfo, ok := findPluginByName(plugins, d.PluginName)
	if !ok {
		return scan.ResolveGraphResult{}, ErrResolverNotFound
	}

	subcommand := d.Subcommand
	if subcommand == "" {
		cmd, ok := pluginInfo.CommandForStage(StageDetect)
		if !ok {
			return scan.ResolveGraphResult{}, ErrResolverNotFound
		}
		subcommand = cmd.Name
	}

	input := DetectInput{
		Subproject: SubprojectInfo{
			Path:           req.ProjectPath,
			PackageManager: req.PackageManager.Name(),
			Ecosystem:      string(req.Ecosystem),
		},
		ExecutionTarget: ExecutionTargetInfo{
			Kind:     string(req.ExecutionTarget.Kind),
			Location: req.ExecutionTarget.Location,
		},
	}

	env, err := RunWithEnvelope(pluginInfo.Path, subcommand, StageDetect, input, req.Stderr, d.CoreVersion, RunOptions{
		WorkingDir: req.ProjectPath,
	})
	if err != nil {
		return scan.ResolveGraphResult{}, err
	}

	output, err := DecodePayload[DetectOutput](env)
	if err != nil {
		return scan.ResolveGraphResult{}, err
	}

	depsGraph, err := graphFromOutput(output.Graph)
	if err != nil {
		return scan.ResolveGraphResult{}, err
	}
	return scan.ResolveGraphResult{
		Graphs: scan.SingleGraphContainer(depsGraph, scan.InferManifestMetadata(req)),
	}, nil
}
