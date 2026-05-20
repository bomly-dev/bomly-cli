package plugin

import (
	"context"
	"fmt"
	"path/filepath"

	plugschema "github.com/bomly-dev/bomly-cli/sdk"
)

// Test probes runtime readiness for one installed plugin.
func Test(ctx context.Context, root, id string) (*TestResult, error) {
	var err error
	root, err = resolveRoot(root)
	if err != nil {
		return nil, err
	}
	record, err := findInstalled(root, id)
	if err != nil {
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
