package registry

// registerGovulncheckAnalyzer is a placeholder until the govulncheck analyzer
// implementation lands in internal/analyzers/govulncheck. The placeholder
// allows the registry plumbing to compile and lets unrelated test runs
// continue while the analyzer is developed in a follow-up commit on the
// same branch.
func (r *Registry) registerGovulncheckAnalyzer() {
	// no-op
}
