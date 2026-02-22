// Package grype implements a scan.Auditor that uses the Grype vulnerability library
// (builtin) or the grype CLI binary (external), selected via build tags.
package grype

import (
	"os"
	"path/filepath"

	"github.com/bomly/bomly-cli/internal/scan"
	"go.uber.org/zap"
)

const auditorName = "grype"

// Auditor uses the Grype library or CLI to match packages against a vulnerability database.
type Auditor struct {
	// Priority controls the order in which this auditor runs relative to others.
	Priority int
	// DBDir is the directory that contains the Grype vulnerability database.
	// Defaults to the OS cache directory / grype / db.
	DBDir string
	// Logger receives diagnostic messages. May be nil (no-op).
	Logger *zap.Logger
	// DistConfigOverride overrides the default distribution config (e.g. LatestURL).
	// In builtin mode this is type-asserted to *v6dist.Config. Primarily useful in tests.
	DistConfigOverride any
}

// Descriptor returns the registration metadata for the Grype auditor.
func (a Auditor) Descriptor() scan.AuditorDescriptor {
	return scan.AuditorDescriptor{
		Name:                auditorName,
		ImplementationType:  scan.ThirdPartyDetector,
		SupportedEcosystems: nil, // nil = all ecosystems
		SupportedModes:      []scan.TargetMode{scan.TargetModeFullGraph, scan.TargetModeComponent},
		Priority:            a.Priority,
		Required:            false,
	}
}

// Ready reports whether the Grype vulnerability database directory exists on disk.
func (a Auditor) Ready() bool {
	info, err := os.Stat(a.dbDir())
	return err == nil && info.IsDir()
}

func (a Auditor) dbDir() string {
	if a.DBDir != "" {
		return a.DBDir
	}
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return filepath.Join(".cache", "grype", "db")
	}
	return filepath.Join(cacheDir, "grype", "db")
}

func (a Auditor) logger() *zap.Logger {
	if a.Logger != nil {
		return a.Logger
	}
	return zap.NewNop()
}
