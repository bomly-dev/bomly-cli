package sbom

import (
	"strings"

	"github.com/bomly-dev/bomly-sdk"
)

// publishableDigest resolves a component digest's algorithm through the SDK
// registry and renders it in one format's spelling, or reports that the digest
// cannot be published here.
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
// Both failure modes collapse to the same answer for a caller: an algorithm
// no format defines, and an algorithm this format has no member for, are both
// "omit this digest". Neither has a spelling that would validate, and SPDX and
// CycloneDX each close their hash enumeration.
func publishableDigest(d Digest, name func(sdk.DigestAlgorithm) string) (spelling, value string, ok bool) {
	value = strings.TrimSpace(d.Value)
	if value == "" {
		return "", "", false
	}
	algorithm, err := sdk.ParseDigestAlgorithm(d.Algorithm)
	if err != nil {
		return "", "", false
	}
	spelling = name(algorithm)
	if spelling == "" {
		return "", "", false
	}
	return spelling, value, true
}
