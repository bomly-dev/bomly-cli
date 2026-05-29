// Package scorecard implements an sdk.Matcher that enriches packages with
// upstream-project security-posture data from the OpenSSF Scorecard public
// API (api.scorecard.dev). The matcher is opt-in via --matchers +scorecard
// and never modifies the dependency graph; it only annotates packages.
package scorecard

// Project is the JSON wire shape returned by
// GET https://api.scorecard.dev/projects/{host}/{owner}/{repo}. Only the
// fields the matcher consumes are decoded; unknown fields are ignored.
type Project struct {
	Date      string         `json:"date"`
	Repo      ProjectRepo    `json:"repo"`
	Scorecard ProjectVersion `json:"scorecard"`
	Score     float64        `json:"score"`
	Checks    []ProjectCheck `json:"checks"`
}

// ProjectRepo identifies the scored repository commit.
type ProjectRepo struct {
	Name   string `json:"name"`
	Commit string `json:"commit"`
}

// ProjectVersion identifies the Scorecard tool version that produced the run.
type ProjectVersion struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

// ProjectCheck is one Scorecard check result.
type ProjectCheck struct {
	Name          string             `json:"name"`
	Score         int                `json:"score"`
	Reason        string             `json:"reason"`
	Details       []string           `json:"details"`
	Documentation ProjectCheckDocRef `json:"documentation"`
}

// ProjectCheckDocRef points at the canonical documentation for a check.
type ProjectCheckDocRef struct {
	Short string `json:"short"`
	URL   string `json:"url"`
}
