package sbom

import (
	"github.com/bomly-dev/bomly-sdk"
)

// publishableDigest puts a component digest through the SDK's gate and returns
// the canonical algorithm and trimmed value, or reports that the digest cannot
// be published at all.
//
// The gate, not the rendering: spdxChecksumAlgorithm and cycloneDXHashAlgorithm
// render a canonical algorithm in their format's spelling, and each asks the
// SDK registry rather than a list of its own. That registry is sourced from
// spdx/tools-golang's and cyclonedx-go's own constants and guarded against
// upstream additions in the SDK; the hand-written switches that stood in those
// two spots knew nine and eight algorithms against the registry's nineteen, so
// a component carrying BLAKE2b, BLAKE3, MD2/MD4/MD6, ADLER32, or Streebog had
// its checksum silently dropped by the gate that exists to reject
// unpublishable values.
//
// Digest.Normalized is that gate, the same one ingest clears in
// ingestedDigests, rather than an algorithm lookup beside a non-empty check. A
// component's digests can be built in memory by a detector or a plugin without
// ever passing through the SDK's JSON hooks, so a value carrying a control
// character, an interior Unicode space, or invalid UTF-8 reaches here intact --
// and encoding/json rewrites invalid UTF-8 as U+FFFD, so such a digest changes
// as it is serialized. A digest that changes when written is worse than no
// digest.
//
// What the gate deliberately does not check is length per algorithm:
// ecosystems publish digests in hex, in base64 (npm's "sha512-..." integrity
// strings), and over subjects that are not files (a Go module "h1:" dirhash),
// so a per-algorithm hex length would reject values that are correct for their
// ecosystem.
//
// What none of this does is scope the algorithm to a target's spec version.
// CycloneDX added Streebog in 1.7, and cyclonedx-go owns that: EncodeVersion
// converts through SpecVersion.supportsHashAlgorithm, which strips a hash the
// requested version cannot name. Repeating that table here would be the same
// transcription these helpers exist to remove.
// TestCycloneDXHashesAreScopedToTheTargetSpecVersion pins the behavior.
func publishableDigest(d Digest) (sdk.DigestAlgorithm, string, bool) {
	normalized, publishable := sdk.Digest{
		Algorithm: sdk.DigestAlgorithm(d.Algorithm),
		Value:     d.Value,
	}.Normalized()
	if !publishable {
		return "", "", false
	}
	return normalized.Algorithm, normalized.Value, true
}
