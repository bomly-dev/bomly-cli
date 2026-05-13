package jvmreach

import (
	"context"
	"fmt"
	"os"

	"go.uber.org/zap"
)

// runnerSchemaVersion is the runner's stable identifier for cache
// invalidation. Bump it when the import scanner or the prefix map
// change in a way that would silently change reachability outcomes.
const runnerSchemaVersion = "v1"

// NewRunner returns the in-process Runner — a line-oriented scanner
// that walks the project's JVM source tree and records every imported
// FQN, resolving each through the prefix map to a Maven coordinate set.
func NewRunner(logger *zap.Logger) Runner {
	return libraryRunner{logger: ensureLogger(logger)}
}

type libraryRunner struct{ logger *zap.Logger }

func (libraryRunner) Name() string { return "library" }

func (libraryRunner) Version() string { return runnerSchemaVersion }

func (r libraryRunner) Run(ctx context.Context, projectDir string) (RunnerResult, error) {
	if info, err := os.Stat(projectDir); err != nil || !info.IsDir() {
		return RunnerResult{}, fmt.Errorf("project dir not accessible: %w", err)
	}

	r.logger.Debug("jvmreach: executing in-process runner",
		zap.String("project_dir", projectDir),
		zap.String("schema_version", runnerSchemaVersion))

	artifacts := make(map[string]struct{})
	sourceFiles := 0
	skipped, walkErr := walkSourceFiles(projectDir, func(path string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			r.logger.Debug("jvmreach: skipping unreadable source",
				zap.String("path", path),
				zap.Error(err))
			return nil
		}
		defer f.Close()
		imports, scanErr := scanImports(f)
		if scanErr != nil {
			r.logger.Debug("jvmreach: scan failed (continuing)",
				zap.String("path", path),
				zap.Error(scanErr))
			return nil
		}
		sourceFiles++
		for fqn := range imports {
			for _, coord := range resolveArtifacts(fqn) {
				artifacts[coord] = struct{}{}
			}
		}
		return nil
	})
	if walkErr != nil {
		return RunnerResult{}, walkErr
	}

	r.logger.Debug("jvmreach: in-process runner completed",
		zap.String("project_dir", projectDir),
		zap.Int("source_files", sourceFiles),
		zap.Int("imported_artifacts", len(artifacts)),
		zap.Strings("skipped_dirs", skipped))

	return RunnerResult{
		ImportedArtifacts: artifacts,
		SourceFiles:       sourceFiles,
		SkippedDirs:       skipped,
	}, nil
}
