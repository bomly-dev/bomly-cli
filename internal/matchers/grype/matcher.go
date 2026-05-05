// Package grype implements a Matcher that uses the Grype vulnerability library
// (builtin) or the grype CLI binary (external), selected via build tags.
package grype

import (
	"context"
	"os"
	"path/filepath"

	model "github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

const matcherName = "grype"

// Matcher uses the Grype library or CLI to match packages against a vulnerability database.
type Matcher struct {
	// Priority controls the order in which this auditor runs relative to others.
	Priority int
	// DBDir is the directory that contains the Grype vulnerability database.
	// Defaults to the OS cache directory / grype / db.
	DBDir string
	// Logger receives diagnostic messages. Maybe nil (no-op).
	Logger *zap.Logger
	// DistConfigOverride overrides the default distribution config (e.g., LatestURL).
	DistConfigOverride any
}

func appendUniqueVulnerability(existing []model.PackageVulnerability, entry model.PackageVulnerability) []model.PackageVulnerability {
	for _, vulnerability := range existing {
		if vulnerability.Source == entry.Source && vulnerability.ID == entry.ID {
			return existing
		}
	}
	return append(existing, entry)
}

// Descriptor returns the registration metadata for the Grype matcher.
func (a Matcher) Descriptor() model.MatcherDescriptor {
	return model.MatcherDescriptor{
		Name:                matcherName,
		Enabled:             true,
		Origin:              model.BundledOrigin,
		SupportedEcosystems: nil, // nil = all ecosystems
		SupportedModes:      []model.TargetMode{model.TargetModeFullGraph, model.TargetModeComponent},
		Priority:            a.Priority,
		Required:            false,
	}
}

// Ready reports whether the Grype vulnerability database directory exists on disk.
func (a Matcher) Ready() bool {
	info, err := os.Stat(a.dbDir())
	return err == nil && info.IsDir()
}

func (a Matcher) Applicable(_ context.Context, req model.MatchRequest) (bool, error) {
	return true, nil
}

func (a Matcher) dbDir() string {
	if a.DBDir != "" {
		return a.DBDir
	}
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return filepath.Join(".cache", "grype", "db")
	}
	return filepath.Join(cacheDir, "grype", "db")
}

func (a Matcher) logger() *zap.Logger {
	if a.Logger != nil {
		return a.Logger
	}
	return zap.NewNop()
}
