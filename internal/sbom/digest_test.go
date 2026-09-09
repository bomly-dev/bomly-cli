package sbom

import (
	"encoding/json"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/bomly-dev/bomly-cli/internal/testnodes"
	"github.com/bomly-dev/bomly-sdk"
	"github.com/spdx/tools-golang/spdx/v2/common"
	v23 "github.com/spdx/tools-golang/spdx/v2/v2_3"
)

// digestFixtureGraph builds a one-package graph carrying the digests a caller
// hands it, spelled however the caller spelled them.
func digestFixtureGraph(t *testing.T, digests []sdk.Digest) *sdk.Graph {
	t.Helper()

	g := sdk.New()
	dep := testnodes.DepFrom(sdk.DependencyNode{
		Coordinates: sdk.Coordinates{Name: "left-pad", Version: "1.3.0", Ecosystem: sdk.EcosystemNPM},
		Digests:     digests,
	})
	if err := g.AddNode(dep); err != nil {
		t.Fatalf("add node: %v", err)
	}
	return g
}

// TestMarshalDepGraphJSON_SPDX23ChecksumsCoverTheWholeRegistry pins the
// algorithms a hand-written switch used to omit. SPDX 2.3 defines BLAKE3 and
// the BLAKE2b family; a document carrying one had its checksum silently
// dropped, because the export switch was a transcription of the vocabulary
// rather than a call into it.
func TestMarshalDepGraphJSON_SPDX23ChecksumsCoverTheWholeRegistry(t *testing.T) {
	g := digestFixtureGraph(t, []sdk.Digest{
		{Algorithm: sdk.DigestAlgorithmBLAKE3, Value: "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"},
		// Spelled the way a CycloneDX document would spell it: the export
		// resolves the spelling rather than matching it.
		{Algorithm: "BLAKE2b-256", Value: "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"},
		{Algorithm: "SHA-256", Value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{Algorithm: "nuget-content-hash", Value: "abc123"},
	})

	out, err := MarshalDepGraphJSON(g, TargetSPDX23JSON, BuildOptions{ProjectRoot: &ProjectRoot{Name: "demo"}}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal spdx: %v", err)
	}
	var d v23.Document
	if err := json.Unmarshal(out, &d); err != nil {
		t.Fatalf("unmarshal spdx: %v", err)
	}

	got := map[common.ChecksumAlgorithm]string{}
	for _, p := range d.Packages {
		if p == nil || p.PackageName != "left-pad" {
			continue
		}
		for _, checksum := range p.PackageChecksums {
			got[checksum.Algorithm] = checksum.Value
		}
	}
	for _, want := range []common.ChecksumAlgorithm{common.BLAKE3, common.BLAKE2b_256, common.SHA256} {
		if got[want] == "" {
			t.Fatalf("expected a %s checksum on the exported package, got %+v", want, got)
		}
	}
	// An algorithm no format defines still has nowhere to go: SPDX closes the
	// enumeration, so the digest is dropped rather than written unvalidatable.
	if len(got) != 3 {
		t.Fatalf("expected exactly the three registered checksums, got %+v", got)
	}
}

// TestMarshalDepGraphJSON_CycloneDXHashesCoverTheWholeRegistry is the same
// check on the other encoder, plus the asymmetry between the two vocabularies:
// SHA224 is an SPDX member CycloneDX has no spelling for, so a document
// ingested from SPDX cannot carry it out as CycloneDX.
func TestMarshalDepGraphJSON_CycloneDXHashesCoverTheWholeRegistry(t *testing.T) {
	g := digestFixtureGraph(t, []sdk.Digest{
		{Algorithm: sdk.DigestAlgorithmBLAKE3, Value: "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"},
		{Algorithm: "blake2b-256", Value: "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"},
		{Algorithm: "SHA256", Value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{Algorithm: sdk.DigestAlgorithmSHA224, Value: "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"},
	})

	out, err := MarshalDepGraphJSON(g, TargetCycloneDX16JSON, BuildOptions{ProjectRoot: &ProjectRoot{Name: "demo"}}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal cyclonedx: %v", err)
	}
	var bom cdx.BOM
	if err := json.Unmarshal(out, &bom); err != nil {
		t.Fatalf("unmarshal cyclonedx: %v", err)
	}

	got := map[cdx.HashAlgorithm]string{}
	if bom.Components != nil {
		for _, comp := range *bom.Components {
			if comp.Name != "left-pad" || comp.Hashes == nil {
				continue
			}
			for _, hash := range *comp.Hashes {
				got[hash.Algorithm] = hash.Value
			}
		}
	}
	for _, want := range []cdx.HashAlgorithm{cdx.HashAlgoBlake3, cdx.HashAlgoBlake2b_256, cdx.HashAlgoSHA256} {
		if got[want] == "" {
			t.Fatalf("expected a %s hash on the exported component, got %+v", want, got)
		}
	}
	if len(got) != 3 {
		t.Fatalf("expected the SPDX-only SHA224 digest to be dropped, got %+v", got)
	}
}

// TestCycloneDXEmittedHashes_RendersCycloneDXSpelling covers the reference
// hashes an assertion carries. The SDK holds an algorithm in its canonical
// form, which is not what CycloneDX calls it: emitting that form directly
// wrote "sha256" where the schema defines "SHA-256", so an ingested document
// changed on its second export.
func TestCycloneDXEmittedHashes_RendersCycloneDXSpelling(t *testing.T) {
	hashes := cycloneDXEmittedHashes([]sdk.Digest{
		{Algorithm: "SHA-256", Value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{Algorithm: sdk.DigestAlgorithmBLAKE2b256, Value: "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"},
		// SPDX-only, so this reference claim cannot be published here.
		{Algorithm: sdk.DigestAlgorithmADLER32, Value: "0424016d"},
	})
	if hashes == nil {
		t.Fatal("expected hashes")
	}
	if len(*hashes) != 2 {
		t.Fatalf("expected the ADLER32 claim dropped, got %+v", *hashes)
	}
	if (*hashes)[0].Algorithm != cdx.HashAlgoSHA256 {
		t.Fatalf("expected CycloneDX's spelling, got %q", (*hashes)[0].Algorithm)
	}
	if (*hashes)[1].Algorithm != cdx.HashAlgoBlake2b_256 {
		t.Fatalf("expected CycloneDX's spelling, got %q", (*hashes)[1].Algorithm)
	}
}

// TestExportProjectsEveryRegisteredDigestAlgorithm is the guard on the
// delegation. Referencing the SDK registry makes a rename a compile error but
// says nothing about an addition -- and an addition is how these vocabularies
// lose data: a spelling the table never learned is dropped by the gate that
// exists to reject unpublishable values. Enumerating the registry rather than
// listing algorithms here means a member added upstream, or a switch written
// back in by hand, fails this test instead of disappearing at runtime.
func TestExportProjectsEveryRegisteredDigestAlgorithm(t *testing.T) {
	const value = "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"

	for _, algorithm := range sdk.DigestAlgorithms() {
		digest := Digest{Algorithm: string(algorithm), Value: value}

		checksums := spdxChecksums([]Digest{digest})
		switch spelling := algorithm.SPDXName(); spelling {
		case "":
			if len(checksums) != 0 {
				t.Errorf("%s has no SPDX member but exported %+v", algorithm, checksums)
			}
		default:
			if len(checksums) != 1 {
				t.Errorf("%s: expected one SPDX checksum, got %+v", algorithm, checksums)
			} else if string(checksums[0].Algorithm) != spelling {
				t.Errorf("%s: exported as %q, want %q", algorithm, checksums[0].Algorithm, spelling)
			}
		}

		hashes := cycloneDXHashes([]Digest{digest})
		switch spelling := algorithm.CycloneDXName(); spelling {
		case "":
			if len(hashes) != 0 {
				t.Errorf("%s has no CycloneDX member but exported %+v", algorithm, hashes)
			}
		default:
			if len(hashes) != 1 {
				t.Errorf("%s: expected one CycloneDX hash, got %+v", algorithm, hashes)
			} else if string(hashes[0].Algorithm) != spelling {
				t.Errorf("%s: exported as %q, want %q", algorithm, hashes[0].Algorithm, spelling)
			}
		}
	}
}

// TestCycloneDXHashesAreScopedToTheTargetSpecVersion settles where version
// scoping lives. CycloneDX added Streebog in 1.7, so a 1.6 document naming it
// carries a value outside a closed enumeration -- but cyclonedx-go already
// owns that conversion: EncodeVersion strips a hash the requested version
// cannot name, through SpecVersion.supportsHashAlgorithm.
//
// The test exists so the question is answered by the encoder's actual output
// rather than re-argued from the mapping's shape. A version table written into
// publishableDigest would be a second copy of the library's, wrong the day
// CycloneDX adds an algorithm -- which is the defect this whole change removes.
func TestCycloneDXHashesAreScopedToTheTargetSpecVersion(t *testing.T) {
	g := digestFixtureGraph(t, []sdk.Digest{
		{Algorithm: sdk.DigestAlgorithmStreebog256, Value: "3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb"},
		{Algorithm: sdk.DigestAlgorithmSHA256, Value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	})

	for _, tc := range []struct {
		target Target
		want   []cdx.HashAlgorithm
	}{
		// Streebog is absent below 1.7, and SHA-256 rides along to show the
		// component still carries the hashes the version does define.
		{TargetCycloneDX14JSON, []cdx.HashAlgorithm{cdx.HashAlgoSHA256}},
		{TargetCycloneDX15JSON, []cdx.HashAlgorithm{cdx.HashAlgoSHA256}},
		{TargetCycloneDX16JSON, []cdx.HashAlgorithm{cdx.HashAlgoSHA256}},
		{TargetCycloneDX17JSON, []cdx.HashAlgorithm{cdx.HashAlgoStreebog256, cdx.HashAlgoSHA256}},
	} {
		out, err := MarshalDepGraphJSON(g, tc.target, BuildOptions{ProjectRoot: &ProjectRoot{Name: "demo"}}, EncodeOptions{})
		if err != nil {
			t.Fatalf("%s: marshal: %v", tc.target, err)
		}
		var bom cdx.BOM
		if err := json.Unmarshal(out, &bom); err != nil {
			t.Fatalf("%s: unmarshal: %v", tc.target, err)
		}
		var got []cdx.HashAlgorithm
		if bom.Components != nil {
			for _, comp := range *bom.Components {
				if comp.Name != "left-pad" || comp.Hashes == nil {
					continue
				}
				for _, hash := range *comp.Hashes {
					got = append(got, hash.Algorithm)
				}
			}
		}
		if len(got) != len(tc.want) {
			t.Fatalf("%s: got %v, want %v", tc.target, got, tc.want)
		}
		for i, want := range tc.want {
			if got[i] != want {
				t.Fatalf("%s: got %v, want %v", tc.target, got, tc.want)
			}
		}
	}
}

// TestExportRefusesADigestTheSDKWillNotPublish covers values that reach the
// encoders without having passed the SDK's JSON hooks: a detector or a plugin
// can build DependencyNode.Digests in memory, and a value carrying whitespace,
// a control character, or invalid UTF-8 would otherwise be written straight
// into the document. encoding/json rewrites invalid UTF-8 as U+FFFD, so such a
// digest changes as it is serialized -- worse than no digest at all.
//
// A short value for a long algorithm is deliberately NOT in this list. The SDK
// checks a digest's shape, not its length per algorithm, because ecosystems
// publish digests in hex, in base64, and over subjects that are not files.
func TestExportRefusesADigestTheSDKWillNotPublish(t *testing.T) {
	for _, tc := range []struct {
		name   string
		digest Digest
	}{
		{"embedded space", Digest{Algorithm: "sha256", Value: "e3b0c442 98fc1c14"}},
		{"control character", Digest{Algorithm: "blake3", Value: "af1349b9\x00f5f9a1a6"}},
		{"invalid utf-8", Digest{Algorithm: "sha512", Value: "e3b0c442\xff\xfe"}},
		// An em space, not an ASCII one: the SDK's check is Unicode-aware,
		// and a trailing ASCII space is trimmed rather than refused.
		{"interior unicode whitespace", Digest{Algorithm: "sha256", Value: "e3b0c442\u200398fc1c14"}},
		{"empty after trimming", Digest{Algorithm: "sha256", Value: "   "}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if checksums := spdxChecksums([]Digest{tc.digest}); len(checksums) != 0 {
				t.Errorf("SPDX exported %+v", checksums)
			}
			if hashes := cycloneDXHashes([]Digest{tc.digest}); len(hashes) != 0 {
				t.Errorf("CycloneDX exported %+v", hashes)
			}
		})
	}

	// The counterpart: a base64 SRI value is shorter than the algorithm's hex
	// form and must still publish.
	sri := Digest{Algorithm: "sha512", Value: "pkJf8Ni4YWlKDgODlNGxi/z1Wd0/hkJH8N4Rq+Cd1lTv7ZZKPXm8mTzcp2xEVSlHoQlUwjzUKh2nGSHTMEUUpg=="}
	if checksums := spdxChecksums([]Digest{sri}); len(checksums) != 1 {
		t.Fatalf("expected the base64 SRI digest to publish, got %+v", checksums)
	}
}
