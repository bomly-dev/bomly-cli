package pyreach

import (
	"context"
	"fmt"
	"os"

	"go.uber.org/zap"
)

// runnerSchemaVersion is the runner's stable identifier for cache
// invalidation. Bumping it invalidates every previously cached entry
// the next time the cache key is built. Reserve bumps for changes to
// the import scanner or the module-to-distribution mapping that
// would silently change reachability outcomes.
const runnerSchemaVersion = "v1"

// NewRunner returns the analyzer's Runner implementation, an
// in-process scanner that walks the project's .py source files and
// records every top-level module imported. Module names are mapped
// to PyPI distribution names through moduleToDistribution; the
// resulting set is what downstream BFS through the dep graph
// expands into the full reachable set.
func NewRunner(logger *zap.Logger) Runner {
	return libraryRunner{logger: ensureLogger(logger)}
}

// libraryRunner is the in-process implementation of Runner. It
// reads source straight off disk; there is no Python interpreter or
// third-party tool involved. The scanner is line-oriented and
// deliberately does not fully parse Python — see importscanner.go
// for the supported subset and the tradeoff.
type libraryRunner struct {
	logger *zap.Logger
}

func (libraryRunner) Name() string { return "library" }

func (libraryRunner) Version() string { return runnerSchemaVersion }

func (r libraryRunner) Run(ctx context.Context, projectDir string) (RunnerResult, error) {
	if info, err := os.Stat(projectDir); err != nil || !info.IsDir() {
		return RunnerResult{}, fmt.Errorf("project dir not accessible: %w", err)
	}

	r.logger.Debug("pyreach: executing in-process runner",
		zap.String("project_dir", projectDir),
		zap.String("schema_version", runnerSchemaVersion))

	imports := make(map[string]struct{})
	sourceFiles := 0
	skipped, walkErr := walkSourceFiles(projectDir, func(path string) error {
		// Cheap cancellation check between files. The walker reads
		// every file synchronously, so this is the natural boundary.
		if err := ctx.Err(); err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			r.logger.Debug("pyreach: skipping unreadable source",
				zap.String("path", path),
				zap.Error(err))
			return nil
		}
		defer func() { _ = f.Close() }()
		fileImports, scanErr := scanImports(f)
		if scanErr != nil {
			r.logger.Debug("pyreach: scan failed for source file (continuing)",
				zap.String("path", path),
				zap.Error(scanErr))
			return nil
		}
		sourceFiles++
		for module := range fileImports {
			dist := moduleToDistribution(module)
			if dist == "" {
				continue
			}
			imports[dist] = struct{}{}
		}
		return nil
	})
	if walkErr != nil {
		// Cancellation is the only error walkSourceFiles propagates.
		return RunnerResult{}, walkErr
	}

	dynamic := detectDynamicImports(projectDir)
	r.logger.Debug("pyreach: in-process runner completed",
		zap.String("project_dir", projectDir),
		zap.Int("source_files", sourceFiles),
		zap.Int("imported_distributions", len(imports)),
		zap.Strings("skipped_dirs", skipped),
		zap.Bool("dynamic_imports_detected", dynamic))

	return RunnerResult{
		ImportedDistributions:  imports,
		SourceFiles:            sourceFiles,
		SkippedDirs:            skipped,
		DynamicImportsDetected: dynamic,
	}, nil
}
