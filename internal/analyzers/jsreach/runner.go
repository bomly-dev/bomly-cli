// Package jsreach implements a Tier-3 (package-level) reachability
// analyzer for npm packages. It walks application source files reachable
// from package.json entry points, builds a static import graph, and
// reports each npm PackageVulnerability as Reachable / Unreachable /
// Unknown depending on whether the affected package's bare specifier
// appears in the import set.
//
// Tier-3 caveat: "unreachable" here means "the application does not
// import this package at all, neither directly nor indirectly through
// app source". It does NOT mean "the vulnerability cannot be triggered"
// — for example, a server runtime might dynamically require the package
// based on user input. See docs/REACHABILITY.md for full semantics.
//
// The runner uses the vendored github.com/evanw/esbuild/pkg/api library
// to walk the project's entry points in-process so users never need an
// esbuild binary on PATH. esbuild handles ESM, CJS, TS/TSX/JSX,
// conditional exports, and subpath imports natively. The Runner interface
// is preserved (rather than calling api.Build directly from the analyzer)
// so unit tests can inject a fake runner for deterministic behaviour.
package jsreach

import (
	"context"

	"go.uber.org/zap"
)

// Runner walks an npm project rooted at projectDir and returns the
// bare-specifier import set reachable from its declared entry points.
// Implementations must NEVER panic and should map missing toolchains,
// parse errors, and other recoverable conditions to a (RunnerResult,
// error) pair where the error is descriptive but does not abort the
// pipeline.
type Runner interface {
	// Name returns a stable identifier (e.g. "library") used in
	// telemetry and Reason fields.
	Name() string
	// Version returns the underlying tool version. The result cache
	// folds it into its key so toolchain upgrades invalidate prior
	// entries automatically. Empty string is acceptable; the cache
	// treats it like any other distinct value.
	Version() string
	// Run walks projectDir and returns the bare-specifier import set
	// found across every entry-reachable source file. projectDir must
	// contain a package.json.
	Run(ctx context.Context, projectDir string) (RunnerResult, error)
}

// RunnerResult is the parsed output of one runner pass over a project.
// It carries enough information for the analyzer to map advisories to
// reachable/unreachable/unknown without re-reading any source.
type RunnerResult struct {
	// ImportedPackages is the set of bare specifiers (e.g. "react",
	// "@scope/pkg") imported anywhere in the project's reachable source
	// tree. Subpath imports ("@scope/pkg/util") are normalized to the
	// owning package name.
	ImportedPackages map[string]struct{}
	// EntryPoints is the list of files the runner started its walk
	// from (mostly for logging / debug output).
	EntryPoints []string
	// SourceFiles is the count of project source files the runner
	// visited (for telemetry).
	SourceFiles int
}

// hasResult reports whether the runner produced anything actionable.
// A nil/empty ImportedPackages with no entry points means the runner
// found no project structure to analyse and the analyzer should mark
// every npm vulnerability Unknown.
func (r RunnerResult) hasResult() bool {
	return len(r.EntryPoints) > 0
}

// ensureLogger guarantees a non-nil zap.Logger so call sites can drop
// the standard nil-check boilerplate.
func ensureLogger(l *zap.Logger) *zap.Logger {
	if l != nil {
		return l
	}
	return zap.NewNop()
}
