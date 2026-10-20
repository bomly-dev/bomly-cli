# ADR-0035: License emission is classified by validation, not by field

- **Date:** 2026-08-25
- **Revised:** 2026-10-19
- **Status:** Accepted

## Context

CycloneDX and SPDX distinguish a checked license identifier, an expression,
and free text a machine cannot reason about. Bomly's export chose among them
by which model field happened to be set, which recorded where a value came
from, not what shape it had: a lockfile's plain `MIT` was published as free
text, a registry's `non-standard` as an unparseable expression, and a
package with two licenses produced two `expression` entries, which CycloneDX
forbids. Underneath, the SPDX expression parser panics on some malformed
input, and license strings arrive from untrusted lockfiles and registries.

## Decision

- Every license value is classified by validating it: a recognized SPDX list
  entry becomes an identifier in canonical spelling, a value that parses
  becomes an expression, anything else is free text.
- Several licenses on one component are listed, not related. CycloneDX emits
  one entry per license; `MIT AND Apache-2.0` is never claimed of a package
  that may be offered under either. A source that knows the relationship
  states it in one expression, which passes through.
- SPDX 2.3 holds one expression per package, so there the set composes with
  `AND`, overstating obligations rather than understating them. This is the
  one deliberate cross-format difference, and `docs/SBOM.md` records it.
- An unrecognized value in SPDX mints a deterministic `LicenseRef-*` with the
  original text in `hasExtractedLicensingInfos`, so nothing is dropped and
  every set composes.
- SPDX `licenseConcluded` is always `NOASSERTION`: Bomly analyzes no package
  contents and has no conclusion to offer; `licenseDeclared` carries what the
  source asserted.
- Classification, composition, deprecated-identifier canonicalization and
  `LicenseRef` minting live in `bomly-sdk/spdxkit`, which carries the
  parser's panic guard. No package under `internal/` imports the parser.

## Rejected

Selecting the output field by the model field that was populated; making the
two formats agree by asserting `AND` in CycloneDX.

## Consequences

- Non-SPDX declared licenses export as free text, which is what makes the
  documents validate.
- A cross-format comparison scores a multi-license component as a mismatch;
  accuracy outranks the similarity number.

Enforced by: the `depguard` rule `internal-kits` in `.golangci.yml`;
`FuzzSPDXLicenseValue` in the SDK.
