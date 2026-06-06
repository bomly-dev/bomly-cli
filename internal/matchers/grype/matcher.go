// Package grype implements a Matcher that uses the Grype vulnerability library
// (builtin) or the grype CLI binary (external), selected via build tags.
package grype

import (
	"context"
	"os"
	"path/filepath"

	"github.com/bomly-dev/bomly-cli/sdk"
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

func appendOrMergeVulnerability(existing []sdk.Vulnerability, entry sdk.Vulnerability) []sdk.Vulnerability {
	for idx, vulnerability := range existing {
		if vulnerability.Source == entry.Source && vulnerability.ID == entry.ID {
			existing[idx] = mergePackageVulnerability(vulnerability, entry)
			return existing
		}
	}
	return append(existing, entry)
}

// Descriptor returns the registration metadata for the Grype matcher.
func (a Matcher) Descriptor() sdk.MatcherDescriptor {
	return sdk.MatcherDescriptor{
		Name:                matcherName,
		DisplayName:         "Grype",
		Enabled:             true,
		Origin:              sdk.BundledOrigin,
		SupportedEcosystems: nil, // nil = all ecosystems
		Priority:            a.Priority,
		Required:            false,
	}
}

func (a Matcher) dbExists() bool {
	info, err := os.Stat(a.dbDir())
	return err == nil && info.IsDir()
}

func (a Matcher) Applicable(_ context.Context, req sdk.MatchRequest) (bool, error) {
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

func grypeMatcherRuns(matchedPackages, vulnerabilities int) []sdk.MatcherRun {
	return []sdk.MatcherRun{{
		Name:            matcherName,
		DisplayName:     "Grype",
		MatchedPackages: matchedPackages,
		Vulnerabilities: vulnerabilities,
	}}
}
