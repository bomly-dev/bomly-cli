package scorecard

import (
	"time"

	"github.com/bomly-dev/bomly-cli/sdk"
)

// mapProject converts an api.scorecard.dev Project payload into the
// neutral sdk.PackageScorecard shape attached to packages.
func mapProject(repo string, p *Project) *sdk.PackageScorecard {
	if p == nil {
		return nil
	}
	repoName := p.Repo.Name
	if repoName == "" {
		repoName = repo
	}
	out := &sdk.PackageScorecard{
		Source:           sourceName,
		Repository:       repoName,
		CommitSHA:        p.Repo.Commit,
		ScorecardVersion: p.Scorecard.Version,
		AggregateScore:   p.Score,
	}
	if ts, err := time.Parse(time.RFC3339, p.Date); err == nil {
		out.RunDate = ts.UTC()
	} else if ts, err := time.Parse("2006-01-02", p.Date); err == nil {
		out.RunDate = ts.UTC()
	}
	if len(p.Checks) > 0 {
		out.Checks = make([]sdk.PackageScorecardCheck, 0, len(p.Checks))
		for _, c := range p.Checks {
			out.Checks = append(out.Checks, sdk.PackageScorecardCheck{
				Name:          c.Name,
				Score:         c.Score,
				Reason:        c.Reason,
				Documentation: c.Documentation.URL,
			})
		}
	}
	return out
}

const sourceName = "api.scorecard.dev"
