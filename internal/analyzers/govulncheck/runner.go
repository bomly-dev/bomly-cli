// Package govulncheck implements a reachability analyzer for Go modules
// backed by govulncheck (https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck).
//
// The runner is backed by the vendored golang.org/x/vuln/scan library and
// runs the analysis in-process so users never need a govulncheck binary on
// PATH. The Runner interface is preserved (rather than calling scan.Source
// directly from the analyzer) so unit tests can inject a fake runner for
// deterministic behaviour.
package govulncheck

import (
	"context"

	model "github.com/bomly-dev/bomly-cli/sdk"
)

// Runner executes govulncheck against one Go module root and returns the
// findings. Implementations must NEVER panic and should map missing
// toolchains, build failures, and other recoverable conditions to a
// (RunnerResult, error) pair where the error is descriptive but does not
// abort the pipeline.
type Runner interface {
	// Name returns a stable identifier (e.g. "library") for telemetry and
	// Reason fields.
	Name() string
	// Run executes govulncheck rooted at moduleDir and returns the parsed
	// findings. moduleDir must contain a go.mod file.
	Run(ctx context.Context, moduleDir string) (RunnerResult, error)
}

// RunnerResult is the parsed govulncheck output shape consumed by the
// analyzer. Findings are grouped by OSV ID; aliases include CVE/GHSA
// identifiers when govulncheck supplies them.
type RunnerResult struct {
	// Findings keyed by canonical OSV ID (e.g. "GO-2023-2049").
	Findings map[string]Finding
	// ImportedModules is the set of module paths the application
	// transitively imports, keyed by module path. Used to distinguish
	// package-level reachability ("imported but no symbol called") from
	// "not imported at all".
	ImportedModules map[string]struct{}
}

// Finding captures one vulnerability govulncheck found in the module
// (or determined to be present-but-unreachable). Each entry collapses
// every "trace" govulncheck emitted for the same OSV ID.
type Finding struct {
	OSV        string
	Aliases    []string
	FixedIn    string
	Modules    []string
	Symbols    []model.AffectedSymbol
	CallPaths  []model.CallPath
	ImportedBy bool // app source imports the affected module/package
	CalledBy   bool // app source calls into an affected symbol
}

// hasResult reports whether the runner returned anything actionable for
// this OSV ID. False results signal "no info" rather than "unreachable".
func (f Finding) hasResult() bool {
	return f.OSV != "" && (f.CalledBy || f.ImportedBy)
}
