package plugin

import (
	"context"
	"fmt"

	"github.com/bomly/bomly-cli/internal/scan"
)

// PreResolveHook adapts a plugin with a pre-resolve stage to scan.PreResolveHook.
type PreResolveHook struct {
	PluginPath  string
	PluginName  string
	Subcommand  string
	CoreVersion string
	Priority    int
	RunOpts     RunOptions
}

// Descriptor returns the hook metadata.
func (h PreResolveHook) Descriptor() scan.HookDescriptor {
	return scan.HookDescriptor{
		Name:     h.PluginName + "-pre-resolve",
		Priority: h.Priority,
		Stage:    StagePreResolve,
	}
}

// Execute runs the plugin pre-resolve stage via the JSON envelope protocol.
func (h PreResolveHook) Execute(_ context.Context, pctx scan.PreResolveContext) error {
	subprojects := make([]SubprojectInfo, len(pctx.Subprojects))
	for i, sp := range pctx.Subprojects {
		subprojects[i] = SubprojectInfo{
			Path:           sp.ExecutionTarget.Location,
			RelativePath:   sp.RelativePath,
			PackageManager: sp.PackageManager.Name(),
			Ecosystem:      string(sp.Ecosystem),
		}
	}

	input := PreResolveInput{
		ExecutionTarget: ExecutionTargetInfo{
			Kind:     string(pctx.ExecutionTarget.Kind),
			Location: pctx.ExecutionTarget.Location,
		},
		Subprojects: subprojects,
	}

	env, err := RunWithEnvelope(h.PluginPath, h.Subcommand, StagePreResolve, input, pctx.Stderr, h.CoreVersion, h.RunOpts)
	if err != nil {
		return fmt.Errorf("plugin %s pre-resolve: %w", h.PluginName, err)
	}

	output, err := DecodePayload[PreResolveOutput](env)
	if err != nil {
		return fmt.Errorf("plugin %s pre-resolve: %w", h.PluginName, err)
	}
	if !output.Success {
		return fmt.Errorf("plugin %s pre-resolve failed: %s", h.PluginName, output.Message)
	}
	return nil
}
