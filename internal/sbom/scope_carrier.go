package sbom

import (
	"sort"

	"github.com/bomly-dev/bomly-sdk"
)

// This file reads Bomly's own scope carrier out of an ingested document and
// collects the tokens this build could not read, so they reach a user instead
// of vanishing (ADR-0037).
//
// The carrier is a `bomly:scopes` CycloneDX property and the `scope=` field of
// the SPDX package comment. Both hold the same value, and the SDK owns what it
// means in both directions -- nothing here parses a token.

// unknownScopeTokens returns the scope tokens a carrier named that this build
// does not recognize.
//
// The read is lenient because the strict one was a forward-compatibility trap:
// a newer Bomly writing one token an older one does not know made the older
// one drop the whole assertion. CycloneDX could fall back to its native
// scalar; SPDX has no scalar, so a component the document scoped
// "runtime,future" ended up unscoped altogether -- the loss
// bomly-dev/bomly-sdk#64 recorded, closed by the SDK's DecodeScopeSetLenient.
//
// A carrier that is malformed outright -- an empty entry, a token that is not
// shaped like a scope token at all -- yields nothing rather than a list of
// junk to warn about. The SDK draws that line; this only reports what it
// hands back.
func unknownScopeTokens(carrier string) []string {
	decoded, err := sdk.DecodeScopeSetLenient(carrier)
	if err != nil {
		return nil
	}
	return decoded.Unknown
}

// mergeUnknownScopeTokens folds tokens into a document's collected set,
// deduplicated and sorted.
//
// Sorted because the list reaches a log line and a test golden, and one
// document's components are read in map order in one codec and slice order in
// the other; an unstable list would make the same document warn differently
// between runs.
func mergeUnknownScopeTokens(collected, tokens []string) []string {
	if len(tokens) == 0 {
		return collected
	}
	seen := make(map[string]struct{}, len(collected)+len(tokens))
	for _, token := range collected {
		seen[token] = struct{}{}
	}
	for _, token := range tokens {
		if _, duplicate := seen[token]; duplicate {
			continue
		}
		seen[token] = struct{}{}
		collected = append(collected, token)
	}
	sort.Strings(collected)
	return collected
}
