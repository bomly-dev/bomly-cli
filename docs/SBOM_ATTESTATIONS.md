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

## Verify an attestation

Verify the bundle against the same subject:

```bash
bomly sbom verify \
  --attestation sbom.att.json \
  --subject dir:.
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
