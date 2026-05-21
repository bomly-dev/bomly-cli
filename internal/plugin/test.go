package plugin

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	plugschema "github.com/bomly-dev/bomly-cli/sdk"
)

// isNotInstalledError reports whether err is the sentinel returned by findInstalled
// when no record matches the requested id.
func isNotInstalledError(err error) bool {
	if err == nil {
		return false
	}
	// findInstalled returns a plain fmt.Errorf with this substring.
	return strings.Contains(err.Error(), "is not installed")
}

// Test probes runtime readiness for one plugin (external or built-in).
// builtins should be the full list returned by ListPluginInfos for the current binary;
// when the id is found only in builtins, the plugin is reported as ready without
// launching an external process.
func Test(ctx context.Context, root, id string, builtins []PluginInfo) (*TestResult, error) {
	var err error
	root, err = resolveRoot(root)
	if err != nil {
		return nil, err
	}
	record, err := findInstalled(root, id)
	if err != nil {
		// Fall back to built-in lookup before propagating the error.
		if isNotInstalledError(err) {
			for _, info := range builtins {
				if info.ID == id && info.BuiltIn {
					if info.ReadyFn != nil {
						ready, probe, readyErr := info.ReadyFn(ctx)
						return &TestResult{
							PluginInfo: info,
							Ready:      ready,
							Probe:      probe,
						}, readyErr
					}
					// No ReadyFn populated — treat as ready (should not happen in normal CLI usage).
					return &TestResult{
						PluginInfo: info,
						Ready:      true,
						Probe:      "builtin",
					}, nil
				}
			}
		}
		return nil, err
	}
	manifest, err := readManifest(record.Path)
	if err != nil {
		return nil, err
	}
	entry, err := entrypointForManifest(manifest)
	if err != nil {
		return nil, err
	}
	fullEntrypoint := filepath.Join(record.Path, entry)

	client, err := startPlugin(launchContext(ctx, nil), fullEntrypoint)
	if err != nil {
		return nil, fmt.Errorf("start plugin runtime for readiness probe: %w", err)
	}
	defer client.Close()

	ready, probe, err := probePluginReadiness(launchContext(ctx, nil), client.Raw(), manifest.Kind)
	if err != nil {
		return nil, err
	}

	return &TestResult{
		PluginInfo: PluginInfo{
			Manifest:   manifest,
			Installed:  record,
			Enabled:    record.Enabled,
			Entrypoint: fullEntrypoint,
		},
		Ready: ready,
		Probe: probe,
	}, nil
}

func probePluginReadiness(ctx context.Context, client plugschema.Client, kind plugschema.PluginKind) (bool, string, error) {
	switch kind {
	case plugschema.PluginKindDetector:
		resp, err := client.DetectorReady(ctx, &plugschema.DetectRequest{})
		if err != nil {
			return false, "detector-ready", fmt.Errorf("run detector readiness probe: %w", err)
		}
		return resp != nil && resp.Ready, "detector-ready", nil
	case plugschema.PluginKindMatcher:
		resp, err := client.MatcherReady(ctx, &plugschema.MatchRequest{})
		if err != nil {
			return false, "matcher-ready", fmt.Errorf("run matcher readiness probe: %w", err)
		}
		return resp != nil && resp.Ready, "matcher-ready", nil
	case plugschema.PluginKindAuditor:
		resp, err := client.AuditorReady(ctx, &plugschema.AuditRequest{})
		if err != nil {
			return false, "auditor-ready", fmt.Errorf("run auditor readiness probe: %w", err)
		}
		return resp != nil && resp.Ready, "auditor-ready", nil
	default:
		return false, "", fmt.Errorf("plugin kind %q does not support runtime readiness probes", kind)
	}
}
