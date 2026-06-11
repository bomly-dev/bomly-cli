# SBOM Attestations

> **Experimental.** SBOM attestations are opt-in and under active development. The MVP creates and verifies local Sigstore-style DSSE bundles around in-toto statements, but certificate identity verification and registry attachment are not part of the first release.

An SBOM attestation binds an SBOM to the thing it describes. Verification checks that:

- The attestation signature is valid.
- The requested subject digest matches the attested subject.
- The embedded SBOM is SPDX 2.3 or CycloneDX JSON and parses successfully.

An attestation does not prove the SBOM is complete or correct. It proves that a signer made a claim about a subject. Trust still depends on who signed it and how the SBOM was produced.

## Create an attestation

Generate an SBOM first, then attest it:

```bash
bomly scan -o spdx=sbom.spdx.json
bomly sbom attest \
  --sbom sbom.spdx.json \
  --subject dir:. \
  --output sbom.att.json \
  --keyless
```

The experimental `--keyless` mode creates a self-contained local bundle for convenient testing and CI artifact integrity checks. It is not an identity-backed Fulcio/OIDC signature yet.

For a durable local signing key, pass an ECDSA P-256 PEM private key:

```bash
bomly sbom attest \
  --sbom sbom.spdx.json \
  --subject git \
  --output sbom.att.json \
  --key signing-key.pem
```

Key-signed attestations do not embed the public verification key. Keep the matching public key and pass it during verification.

## Verify an attestation

Verify the bundle against the same subject:

```bash
bomly sbom verify \
  --attestation sbom.att.json \
  --subject dir:.
```

For an attestation created with `--key`, pass the matching ECDSA P-256 PEM public key:

```bash
bomly sbom verify \
  --attestation sbom.att.json \
  --subject git \
  --key signing-key.pub.pem
```

To extract the verified embedded SBOM:

```bash
bomly sbom verify \
  --attestation sbom.att.json \
  --subject git \
  --extract-sbom verified.spdx.json
```

`--extract-sbom` writes only after signature, subject, predicate, and SBOM checks pass.
Bundles preserve the original SBOM bytes for extraction, including JSON key ordering and whitespace, without duplicating the SBOM as a second parsed JSON object in the predicate.

## How verification works

An attestation is not an encrypted file. Anyone who has the attestation bundle can decode and read the signed payload, including the embedded SBOM. The key is used to prove authenticity, not secrecy.

Think of the bundle as three parts:

| Part | What it means |
| --- | --- |
| Payload | The readable claim: subject digest, SBOM digest, predicate type, and embedded SBOM bytes |
| Signature | A tamper-proof seal over that exact payload |
| Public key or identity material | Information used to check who made the seal |

The private key creates the signature. The public key checks the signature. The public key does not hide or unlock the payload.

Verification answers this question:

> Was this exact SBOM attestation signed by the holder of the expected private key, and does it describe the exact subject I asked Bomly to verify?

Bomly verifies an SBOM attestation in this order:

1. Decode the readable DSSE payload from the bundle.
2. Verify the signature over that exact payload.
3. Resolve the requested subject, such as `file:<path>`, `dir:<path>`, `git`, or `container:<image@sha256:...>`.
4. Hash the requested subject.
5. Compare that digest to the subject digest inside the signed payload.
6. Confirm the predicate type is Bomly's experimental SBOM predicate.
7. Decode the embedded SBOM bytes.
8. Parse the SBOM as supported SPDX or CycloneDX JSON.
9. Hash the embedded SBOM and compare it to the signed SBOM digest.
10. Write `--extract-sbom` only after all checks pass.

If someone changes the subject digest, SBOM bytes, predicate type, or any other signed payload field, the signature check fails. If someone signs a new fake payload with a different key, verification fails unless you trust and pass that signer's public key.

This means:

- Decoding the payload proves nothing by itself.
- A valid signature proves the payload was not changed after signing.
- A trusted public key tells Bomly which signer you expected.
- An attestation proves a signed claim about an SBOM and subject; it does not prove the SBOM is complete, correct, or secret.

## Subjects

| Subject | Use for | Behavior |
| --- | --- | --- |
| `file:<path>` | Release archives, binaries, package files | Hashes the file bytes with SHA-256 |
| `dir:<path>` | Local source folders and monorepos | Computes one deterministic tree digest over regular files |
| `git` | CI source snapshots | Requires a clean worktree and hashes a deterministic `git archive HEAD` view |
| `container:<image@sha256:...>` | Container scan results | Accepts digest references only; tags are rejected |

For folders with multiple subprojects, Bomly creates one attestation for the whole folder snapshot. The SBOM is treated as one document describing the full scan result. If you need per-subproject attestations, scan each subpath separately.

## Limitations

- The feature is experimental and the bundle shape may evolve.
- Container subjects must use `image@sha256:<digest>`; Bomly does not resolve tags for attestation subjects.
- Certificate identity verification flags are reserved for future identity-backed Sigstore bundles.
- Registry attachment is deferred. Store the SBOM and attestation as CI/release artifacts for now.
- The tree digest excludes VCS metadata and any SBOM or attestation output path passed to the command when those outputs live inside the subject folder.

## See also

- [SBOM formats](SBOM.md)
- [CI integration](CI_INTEGRATION.md)
- [Output formats](OUTPUT_FORMATS.md)
