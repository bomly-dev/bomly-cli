package detectors

import sdk "github.com/bomly-dev/bomly-sdk"

// RefineOrigins merges refined origins onto existing ones, dropping any
// existing origin the refinement supersedes.
//
// A union alone is wrong when the two describe the same place at different
// precision. SwiftPM and pub both assert a repository while parsing the
// manifest, then read the lockfile and learn the revision that repository was
// pinned at; a plain union leaves both, and the component publishes one VCS
// reference with a revision and one without -- a consumer reading the first
// gets a floating reference to a pinned dependency.
//
// Supersession is deliberately narrow: same repository, same artifact URL, and
// the existing origin states no revision while the refinement does. Two
// genuinely different places still both survive, because that disagreement is
// the dependency-confusion signal ADR-0041 keeps.
//
// This belongs in the SDK next to MergeOrigins, which owns what merging an
// origin means (ADR-0040); it is here because v0.8.0's merge is a plain union
// and the CLI adoption cannot wait for the next SDK release. Tracked as
// bomly-dev/bomly-sdk#35.
func RefineOrigins(existing, refined []sdk.DependencyOrigin) []sdk.DependencyOrigin {
	kept := make([]sdk.DependencyOrigin, 0, len(existing))
	for _, origin := range existing {
		if supersededBy(origin, refined) {
			continue
		}
		kept = append(kept, origin)
	}
	return sdk.MergeOrigins(kept, refined)
}

func supersededBy(origin sdk.DependencyOrigin, refinements []sdk.DependencyOrigin) bool {
	if origin.Revision != "" || origin.Repository == "" {
		return false
	}
	for _, refinement := range refinements {
		if refinement.Revision != "" &&
			refinement.Repository == origin.Repository &&
			refinement.ArtifactURL == origin.ArtifactURL {
			return true
		}
	}
	return false
}
