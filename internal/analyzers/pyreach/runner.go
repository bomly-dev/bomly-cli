// Package pyreach implements a Tier-3 (package-level) reachability
// analyzer for Python packages. It walks application source files
// rooted at a Python project (pyproject.toml / setup.py / requirements.txt
// / Pipfile / poetry.lock / pdm.lock / uv.lock), scans every reachable
// .py file for top-level import statements, maps the imported module
// names to PyPI distribution names, and reports each PackageVulnerability
// as Reachable / Unreachable / Unknown depending on whether the
// distribution appears in the import set (expanded transitively through
// the dep graph).
//
// Tier-3 caveat: "unreachable" here means "the application source does
// not import this package, neither directly nor indirectly through app
// code". It does NOT mean "the vulnerability cannot be triggered" —
// Python is highly dynamic (importlib.import_module on user input,
// plugin discovery via entry points, Django INSTALLED_APPS strings,
// __import__ inside conditional branches). See docs/REACHABILITY.md
// for the full set of caveats.
//
// The runner reads source in-process so users never need a Python
// interpreter or third-party tool on PATH. The Runner interface is
// preserved (rather than calling the scanner directly from the
// analyzer) so unit tests can inject a fake runner for deterministic
// behaviour.
package pyreach

import (
	"context"

	"go.uber.org/zap"
)

// Runner walks a Python project rooted at projectDir and returns the
// set of PyPI distribution names imported anywhere in its reachable
// source tree. Implementations must NEVER panic and should map missing
// inputs, parse errors, and other recoverable conditions to a
// (RunnerResult, error) pair where the error is descriptive but does
// not abort the pipeline.
type Runner interface {
	// Name returns a stable identifier (e.g. "library") used in
	// telemetry and Reason fields.
	Name() string
	// Version returns the runner schema version. The result cache
	// folds it into its key so scanner upgrades invalidate prior
	// entries automatically.
	Version() string
	// Run walks projectDir and returns the imported-distribution set.
	// projectDir must contain at least one of pyproject.toml,
	// setup.py, setup.cfg, requirements*.txt, Pipfile, poetry.lock,
	// pdm.lock, or uv.lock.
	Run(ctx context.Context, projectDir string) (RunnerResult, error)
}

// RunnerResult is the parsed output of one runner pass over a project.
// It carries enough information for the analyzer to map advisories to
// reachable / unreachable / unknown without re-reading any source.
type RunnerResult struct {
	// ImportedDistributions is the set of PyPI distribution names
	// (lowercase, hyphenated form — the canonical form of
	// distribution names) imported anywhere in the project's
	// reachable source tree. Module names are normalized to
	// distribution names through a layered strategy: a static map
	// of well-known mismatches (e.g. yaml -> PyYAML), then the
	// identity normalization (lowercase, "_" -> "-").
	ImportedDistributions map[string]struct{}
	// SourceFiles is the count of project .py files the runner
	// visited (for telemetry).
	SourceFiles int
	// SkippedDirs lists the directory names skipped during the walk
	// (venv/, __pycache__/, etc.) for debug logging.
	SkippedDirs []string
}

// hasResult reports whether the runner produced anything actionable.
// Zero source files means the runner found no project structure to
// analyse and the analyzer should mark every Python vulnerability
// Unknown.
func (r RunnerResult) hasResult() bool {
	return r.SourceFiles > 0
}

// ensureLogger guarantees a non-nil zap.Logger so call sites can drop
// the standard nil-check boilerplate.
func ensureLogger(l *zap.Logger) *zap.Logger {
	if l != nil {
		return l
	}
	return zap.NewNop()
}
