// Package jvmreach implements a Tier-3 (package-level) reachability
// analyzer for JVM-ecosystem packages (Maven, Gradle, SBT). It walks
// application source files rooted at a JVM project, scans every
// reachable .java / .kt / .kts / .scala / .groovy file for top-of-file
// import statements, maps the imported FQN prefixes to Maven artifact
// coordinates (`groupId:artifactId`), and reports each
// PackageVulnerability as Reachable / Unreachable / Unknown depending
// on whether the artifact appears in the import set (expanded
// transitively through the dep graph).
//
// Tier-3 caveat: "unreachable" here means "the application source does
// not import this artifact, neither directly nor indirectly through
// app code". It does NOT mean "the vulnerability cannot be triggered"
// — JVM apps use reflection, ServiceLoader, classpath scanning, Spring
// component scanning, and OSGi/JPMS dynamic loading, all of which are
// invisible to a static scanner. See docs/REACHABILITY.md for the
// full set of caveats.
//
// The runner reads source in-process. The Runner interface is
// preserved so unit tests can inject a fake runner for deterministic
// behaviour.
package jvmreach

import (
	"context"

	"go.uber.org/zap"
)

// Runner walks a JVM project rooted at projectDir and returns the set
// of Maven artifact coordinates (`groupId:artifactId`) imported
// anywhere in its reachable source tree. Implementations must NEVER
// panic and should map missing inputs, parse errors, and other
// recoverable conditions to a (RunnerResult, error) pair where the
// error is descriptive but does not abort the pipeline.
type Runner interface {
	// Name returns a stable identifier (e.g. "library") used in
	// telemetry and Reason fields.
	Name() string
	// Version returns the runner schema version. The result cache
	// folds it into its key so scanner upgrades invalidate prior
	// entries automatically.
	Version() string
	// Run walks projectDir and returns the imported-artifact set.
	// projectDir must look like a JVM project root (pom.xml,
	// build.gradle(.kts), build.sbt, or settings.gradle(.kts)).
	Run(ctx context.Context, projectDir string) (RunnerResult, error)
}

// RunnerResult is the parsed output of one runner pass over a project.
type RunnerResult struct {
	// ImportedArtifacts is the set of Maven coordinates ("group:artifact",
	// lowercase) that the prefix map resolved from source-level
	// imports. The analyzer matches graph packages against this set
	// before walking transitive deps.
	ImportedArtifacts map[string]struct{}
	// SourceFiles is the count of project source files visited
	// (.java / .kt / .kts / .scala / .groovy).
	SourceFiles int
	// SkippedDirs lists directory names skipped during the walk
	// (target/, build/, .gradle/, etc.) for debug logging.
	SkippedDirs []string
	// DynamicImportsDetected is true when the runner observed
	// reflection-based class loading the static scanner cannot
	// follow: Class.forName(name) on a variable, ClassLoader.loadClass,
	// ServiceLoader.load, ResourceBundle.getBundle on a variable. When
	// true, an "unreachable" verdict is necessarily incomplete and the
	// per-vuln Reachability.DynamicImportsDetected flag is set.
	DynamicImportsDetected bool
}

func (r RunnerResult) hasResult() bool { return r.SourceFiles > 0 }

func ensureLogger(l *zap.Logger) *zap.Logger {
	if l != nil {
		return l
	}
	return zap.NewNop()
}
