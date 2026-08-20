package detectors

import "github.com/bomly-dev/bomly-sdk"

// FoldOrigin settles package origin when two records of one package become one
// node. Call it at every such point -- graph deduplication, name indexes,
// dependency-group merges -- so the surviving node never reports one record's
// answer as though the other did not exist.
//
// survivor is the node that will remain; replaced is the record it stands in
// for. Which is which does not affect the outcome, because reconciliation is
// symmetric: records that agree keep their origin, a record asserting nothing
// leaves an existing one standing, and records that disagree cancel and stay
// cancelled. The argument names say what is happening rather than what the
// caller must get right.
//
// This exists because the rule was repeatedly rediscovered one call site at a
// time: a lockfile listing one package twice, two dependency groups naming
// different sources, two manifests resolving one package differently. Each
// missed site published whichever record happened to be walked first as if it
// were the only one. Route new folds through here rather than writing the
// reconciliation by hand.
func FoldOrigin(survivor, replaced *sdk.Dependency) {
	if survivor == nil || replaced == nil {
		return
	}
	survivor.Origin = sdk.ReconcileOrigin(survivor.Origin, replaced.Origin)
}
