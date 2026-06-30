package plugin

import (
	"context"
	"fmt"
	"os"
)

// Verify validates one installed managed plugin.
func Verify(ctx context.Context, root, id string) (*VerifyResult, error) {
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
	fullEntrypoint, err := pathInPluginDir(record.Path, entry)
	if err != nil {
		return nil, fmt.Errorf("plugin entrypoint %q must stay within the plugin directory", entry)
	}
	if _, err := os.Stat(fullEntrypoint); err != nil {
		return nil, fmt.Errorf("verify plugin entrypoint: %w", err)
	}
	checks := []string{"manifest exists", "manifest valid", "entrypoint exists"}
	if record.Checksum != "" {
		currentChecksum, err := checksumFile(fullEntrypoint)
		if err != nil {
			return nil, err
		}
		if currentChecksum != record.Checksum {
			return nil, fmt.Errorf("plugin checksum mismatch: expected %s, got %s", record.Checksum, currentChecksum)
		}
		checks = append(checks, "checksum matches")
	}
	installedSnapshot, err := readRuntimeSnapshot(record.Path)
	if err != nil {
		return nil, err
	}
	liveSnapshot, err := fetchRuntimeSnapshot(ctx, fullEntrypoint, manifest.Kind, manifest.ID)
	if err != nil {
		return nil, err
	}
	if err := runtimeSnapshotMatchesManifest(liveSnapshot, manifest); err != nil {
		return nil, err
	}
	if err := runtimeSnapshotMatchesSnapshot(liveSnapshot, installedSnapshot); err != nil {
		return nil, err
	}
	checks = append(checks, "runtime descriptor matches installed snapshot", "plugin API version compatible")
	return &VerifyResult{
		Info: Info{
			Manifest:           manifest,
			DetectorDescriptor: installedSnapshot.DetectorDescriptor,
			MatcherDescriptor:  installedSnapshot.MatcherDescriptor,
			AuditorDescriptor:  installedSnapshot.AuditorDescriptor,
			Installed:          record,
			Entrypoint:         fullEntrypoint,
		},
		Checks: checks,
	}, nil
}

// Enable marks one installed plugin enabled.
func Enable(root, id string) (*InstalledPlugin, error) {
	return updateInstalledPlugin(root, id, func(plugin *InstalledPlugin) error {
		plugin.Enabled = true
		return nil
	})
}

// Disable marks one installed plugin disabled.
func Disable(root, id string) (*InstalledPlugin, error) {
	return updateInstalledPlugin(root, id, func(plugin *InstalledPlugin) error {
		plugin.Enabled = false
		return nil
	})
}

// Uninstall removes one installed external plugin.
func Uninstall(root, id string) error {
	var err error
	root, err = resolveRoot(root)
	if err != nil {
		return err
	}
	record, err := findInstalled(root, id)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(record.Path); err != nil {
		return fmt.Errorf("remove plugin files: %w", err)
	}
	db, err := loadInstalledDB(root)
	if err != nil {
		return err
	}
	db = removeInstalledPlugin(db, id)
	return saveInstalledDB(root, db)
}
