package jsreach

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime/debug"

	"github.com/evanw/esbuild/pkg/api"
	"go.uber.org/zap"
)

// NewRunner returns the analyzer's Runner implementation, backed by
// the vendored github.com/evanw/esbuild/pkg/api library. The runner
// walks the project's entry points in-process and emits a metafile we
// parse for the bare-specifier import set, so users never need an
// esbuild binary on PATH.
func NewRunner(logger *zap.Logger) Runner {
	return libraryRunner{logger: ensureLogger(logger)}
}

// libraryRunner is the in-process implementation of Runner. It does
// not bundle output — PackagesExternal short-circuits package
// resolution so every bare specifier is recorded in the metafile
// without esbuild ever opening node_modules. This is far faster than
// a real bundle pass and keeps us out of the dependency-of-dependency
// rabbit hole; the analyzer expands the resulting set transitively
// through the npm detector's dep graph (see analyzer.go).
//
// The Runner interface is preserved (rather than calling api.Build
// directly from the analyzer) so unit tests can inject a fakeRunner
// for deterministic behaviour without invoking esbuild.
type libraryRunner struct {
	logger *zap.Logger
}

func (libraryRunner) Name() string { return "library" }

func (libraryRunner) Version() string { return esbuildVersion() }

// esbuildVersion reads the linked esbuild version from the Go build
// info so the cache key invalidates automatically on dep upgrades.
// Returns "" when build info is unavailable (uncommon — Go binaries
// always embed it unless built with -trimpath in odd setups).
func esbuildVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, dep := range info.Deps {
		if dep == nil {
			continue
		}
		if dep.Path == "github.com/evanw/esbuild" {
			return dep.Version
		}
	}
	return ""
}

func (r libraryRunner) Run(ctx context.Context, projectDir string) (RunnerResult, error) {
	entries, err := discoverEntryPoints(projectDir)
	if err != nil {
		return RunnerResult{}, fmt.Errorf("discover entry points: %w", err)
	}

	r.logger.Debug("jsreach: executing in-process runner",
		zap.String("project_dir", projectDir),
		zap.Strings("entry_points", entries),
		zap.String("packages_mode", "external"))

	options := api.BuildOptions{
		EntryPoints:       entries,
		AbsWorkingDir:     projectDir,
		Outdir:            filepath.Join(projectDir, ".bomly-jsreach"),
		Bundle:            true,
		Write:             false,
		Metafile:          true,
		Platform:          api.PlatformNode,
		Packages:          api.PackagesExternal,
		LogLevel:          api.LogLevelSilent,
		LogLimit:          0,
		MinifyWhitespace:  false,
		MinifyIdentifiers: false,
		MinifySyntax:      false,
		Loader: map[string]api.Loader{
			".js":   api.LoaderJS,
			".jsx":  api.LoaderJSX,
			".mjs":  api.LoaderJS,
			".cjs":  api.LoaderJS,
			".ts":   api.LoaderTS,
			".tsx":  api.LoaderTSX,
			".json": api.LoaderJSON,
			// Common asset extensions the project may import; mark
			// them as data so esbuild doesn't error on them and
			// doesn't include them as bare specifiers.
			".css":  api.LoaderEmpty,
			".scss": api.LoaderEmpty,
			".sass": api.LoaderEmpty,
			".less": api.LoaderEmpty,
			".png":  api.LoaderEmpty,
			".jpg":  api.LoaderEmpty,
			".jpeg": api.LoaderEmpty,
			".gif":  api.LoaderEmpty,
			".svg":  api.LoaderEmpty,
			".webp": api.LoaderEmpty,
			".woff": api.LoaderEmpty,
			".ttf":  api.LoaderEmpty,
		},
	}

	// Honour cancellation by surfacing it as a runner error. esbuild
	// itself doesn't take a context; we check before/after so a
	// long-running pass still cancels at boundary.
	if err := ctx.Err(); err != nil {
		return RunnerResult{}, err
	}

	result := api.Build(options)
	if err := ctx.Err(); err != nil {
		return RunnerResult{}, err
	}

	if len(result.Errors) > 0 {
		// esbuild errors usually mean syntactically broken sources or
		// genuinely missing files. We log them at debug and keep
		// going; whatever metafile we got back is still useful for a
		// best-effort import set.
		preview := summarizeMessages(result.Errors, 3)
		r.logger.Debug("jsreach: esbuild reported errors (continuing on best-effort)",
			zap.String("project_dir", projectDir),
			zap.Int("error_count", len(result.Errors)),
			zap.String("preview", preview))
	}

	if result.Metafile == "" {
		return RunnerResult{}, fmt.Errorf("esbuild returned an empty metafile (errors: %d)", len(result.Errors))
	}

	imports, sourceFiles, err := extractImportedPackages(result.Metafile)
	if err != nil {
		return RunnerResult{}, err
	}
	dynamic := detectDynamicImports(projectDir)
	r.logger.Debug("jsreach: in-process runner completed",
		zap.String("project_dir", projectDir),
		zap.Int("entry_points", len(entries)),
		zap.Int("source_files", sourceFiles),
		zap.Int("imported_packages", len(imports)),
		zap.Bool("dynamic_imports_detected", dynamic))

	return RunnerResult{
		ImportedPackages:       imports,
		EntryPoints:            entries,
		SourceFiles:            sourceFiles,
		DynamicImportsDetected: dynamic,
	}, nil
}

// summarizeMessages returns the first n esbuild messages joined as a
// single string for debug logging. esbuild messages can contain
// newlines; we keep them inline to stay readable in tail/zap output.
func summarizeMessages(messages []api.Message, n int) string {
	if len(messages) == 0 {
		return ""
	}
	if n > len(messages) {
		n = len(messages)
	}
	out := ""
	for i := 0; i < n; i++ {
		if i > 0 {
			out += "; "
		}
		out += messages[i].Text
	}
	if len(messages) > n {
		out += fmt.Sprintf(" (+%d more)", len(messages)-n)
	}
	return out
}
