package sbom

import (
	"github.com/bomly-dev/bomly-sdk"
)

// publishableDigest puts a component digest through the SDK's gate and renders
// its algorithm in one format's spelling, or reports that the digest cannot be
// published here.
//
// name is a method expression -- sdk.DigestAlgorithm.SPDXName or
// sdk.DigestAlgorithm.CycloneDXName -- so both encoders ask the same registry
// the same question and only the rendering differs. The registry is sourced
// from spdx/tools-golang's and cyclonedx-go's own constants and guarded
// against upstream additions in the SDK; a switch transcribed here is correct
// until a specification grows a member, and then it silently drops the
// digests that use it. This package had two such switches, and between them
// they omitted BLAKE2b, BLAKE3, MD2/MD4/MD6, ADLER32, and Streebog.
//
// Digest.Normalized is the gate, the same one ingest clears in
// ingestedDigests, rather than an algorithm lookup beside a non-empty check.
// A component's digests can be built in memory by a detector or a plugin
// without ever passing through the SDK's JSON hooks, so a value carrying a
// control character, a space, or invalid UTF-8 reaches here intact -- and a
// digest that corrupts the document it lands in is worse than no digest. What
// the gate deliberately does not check is length per algorithm: ecosystems
// publish digests in hex, in base64 (npm's "sha512-..." integrity strings),
// and over subjects that are not files (a Go module "h1:" dirhash), so a
// per-algorithm hex length would reject values that are correct for their
// ecosystem.
//
// Three failure modes collapse to one answer for a caller: a digest the SDK
// will not publish, an algorithm no format defines, and an algorithm this
// format has no member for are all "omit this digest". None has a spelling
// that would validate, and SPDX and CycloneDX each close their hash
// enumeration.
//
// What this does not do is scope the algorithm to a target's spec version.
// CycloneDX added Streebog in 1.7, and cyclonedx-go owns that: EncodeVersion
// converts through SpecVersion.supportsHashAlgorithm, which strips a hash the
// requested version cannot name. Repeating that table here would be the same
// transcription this function exists to remove.
// TestCycloneDXHashesAreScopedToTheTargetSpecVersion pins the behavior.
func publishableDigest(d Digest, name func(sdk.DigestAlgorithm) string) (spelling, value string, ok bool) {
	normalized, publishable := sdk.Digest{
		Algorithm: sdk.DigestAlgorithm(d.Algorithm),
		Value:     d.Value,
	}.Normalized()
	if !publishable {
		return "", "", false
	}
	spelling = name(normalized.Algorithm)
	if spelling == "" {
		return "", "", false
	}
	return spelling, normalized.Value, true
}
