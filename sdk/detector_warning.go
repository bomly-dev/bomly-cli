package sdk

// DetectorWarningType classifies a detector warning by what it means for the
// run. It is the field policy decisions branch on: see DegradesCoverage.
type DetectorWarningType string

const (
	// DetectorWarningResolutionFailure means a detector chain failed for a
	// subproject and the scan continued without that subproject's dependencies.
	DetectorWarningResolutionFailure DetectorWarningType = "resolution-failure"
	// DetectorWarningFallback means a fallback detector produced the graph after
	// the planned primary detector failed, so transitive dependencies may be
	// missing.
	DetectorWarningFallback DetectorWarningType = "fallback"
	// DetectorWarningPackageManager means the graph is sound, but the project's
	// package-manager configuration will break or degrade an install elsewhere —
	// typically in CI.
	DetectorWarningPackageManager DetectorWarningType = "package-manager"
)

// DegradesCoverage reports whether the warning means the dependency graph may
// be incomplete, and therefore that findings may be missing. Consumers that
// require complete coverage before recording a decision — writing a finding
// baseline, for example — gate on this rather than on the presence of any
// warning: a package-manager mismatch says nothing about coverage.
func (t DetectorWarningType) DegradesCoverage() bool {
	switch t {
	case DetectorWarningResolutionFailure, DetectorWarningFallback:
		return true
	default:
		return false
	}
}

// DetectorWarningCode identifies the specific check that produced a warning.
// It is empty for warnings the engine synthesizes from a detector failure,
// where Type already carries the full meaning.
type DetectorWarningCode string

const (
	// DetectorWarningCodeLockfileFormat means the committed lockfile's format
	// version disagrees with the package-manager version the project declares.
	DetectorWarningCodeLockfileFormat DetectorWarningCode = "lockfile-format-mismatch"
	// DetectorWarningCodeLockfileUnsupported means the project commits a
	// lockfile the declared package manager does not read.
	DetectorWarningCodeLockfileUnsupported DetectorWarningCode = "lockfile-unsupported"
	// DetectorWarningCodeEnginesConstraint means a declared engines constraint
	// contradicts another declaration in the same project.
	DetectorWarningCodeEnginesConstraint DetectorWarningCode = "engines-constraint-mismatch"
	// DetectorWarningCodeInstallGate means an install policy rejects versions by
	// age or publish date, so a freshly published fix version cannot install.
	DetectorWarningCodeInstallGate DetectorWarningCode = "install-policy-gate"
)

// DetectorWarning is one non-fatal problem found while detecting dependencies.
// Detectors return warnings alongside the graphs they resolve; the engine adds
// the ones it observes around them (a failed chain, a fallback). Every warning
// travels the same way to every surface, so a consumer never has to know which
// of the two produced it.
//
// Source names the detector or tool the warning is about ("maven-detector",
// "pnpm"). Subproject and Manifest locate it when known; the engine fills in
// Subproject, so detectors only set Manifest.
type DetectorWarning struct {
	Type       DetectorWarningType `json:"type"`
	Code       DetectorWarningCode `json:"code,omitempty"`
	Source     string              `json:"source,omitempty"`
	Subproject string              `json:"subproject,omitempty"`
	Manifest   string              `json:"manifest,omitempty"`
	Message    string              `json:"message"`
}

// DegradesCoverage reports whether this warning means the graph may be
// incomplete. It is shorthand for Type.DegradesCoverage.
func (w DetectorWarning) DegradesCoverage() bool {
	return w.Type.DegradesCoverage()
}
