package sdk

import "time"

// PackageScorecard holds the latest OpenSSF Scorecard run attached to a
// package by the scorecard matcher. A nil value means no run was attached
// (no resolvable source repo, the OSSF has not scored the project, or the
// matcher was not selected).
type PackageScorecard struct {
	// Source identifies where the data came from (e.g. "api.scorecard.dev").
	Source string `json:"source,omitempty"`
	// Repository is the canonical repo identifier scored, e.g.
	// "github.com/kubernetes/kubernetes".
	Repository string `json:"repository,omitempty"`
	// CommitSHA is the repo commit the run scored.
	CommitSHA string `json:"commitSha,omitempty"`
	// ScorecardVersion is the version of the Scorecard tool that produced
	// the run.
	ScorecardVersion string `json:"scorecardVersion,omitempty"`
	// RunDate is when the run was performed.
	RunDate time.Time `json:"runDate,omitempty"`
	// AggregateScore is the overall Scorecard aggregate, 0.0–10.0.
	// A negative value (typically -1) indicates "unscored".
	AggregateScore float64 `json:"aggregateScore"`
	// Checks holds per-check results in the order returned by Scorecard.
	Checks []PackageScorecardCheck `json:"checks,omitempty"`
}

// PackageScorecardCheck describes a single Scorecard check result.
type PackageScorecardCheck struct {
	// Name is the Scorecard check name, e.g. "Branch-Protection".
	Name string `json:"name"`
	// Score is 0–10, or -1 when the check is inconclusive.
	Score int `json:"score"`
	// Reason is the short summary Scorecard emits for the check.
	Reason string `json:"reason,omitempty"`
	// Documentation links to the canonical documentation page for the check.
	Documentation string `json:"documentation,omitempty"`
}

// Clone returns a deep copy of the scorecard payload, including its checks.
func (s *PackageScorecard) Clone() *PackageScorecard {
	if s == nil {
		return nil
	}
	clone := *s
	if len(s.Checks) > 0 {
		clone.Checks = append([]PackageScorecardCheck(nil), s.Checks...)
	}
	return &clone
}
