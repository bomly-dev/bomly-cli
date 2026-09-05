# ADR-0035: License emission is validated, not assumed

- **Date:** 2026-08-25
- **Status:** Accepted

## Context

CycloneDX and SPDX both distinguish a checked SPDX license identifier from a
license expression from free text a machine cannot reason about. Bomly's export
did not: it published a license as an `expression` whenever the intermediate
model happened to carry an `SPDXExpression`, and as a free-text `name`
otherwise.

Which field is populated says where a license came from, not what shape it has.
Detection-time licenses carry only `Value`: the npm and pnpm parsers read a
lockfile's plain `"MIT"` and set nothing else. Registry licenses carry both,
because the deps.dev matcher copies one string into `Value` and
`SPDXExpression` alike — "non-standard" as readily as "MIT".

Selecting on the field therefore got both directions wrong. A package whose
lockfile declared `MIT` was published as free text, because detection set no
expression. Unrecognized registry text was published as an `expression` that
does not parse, because the matcher set one. Two licenses produced two
`expression` entries, which CycloneDX does not allow. And SPDX, holding one
expression per package, kept `licenses[0]` and dropped the rest without
saying so.

Underneath, the SPDX expression parser Bomly depends on panics rather than
returning an error on some malformed input — `(((` dereferences a nil operator.
The license auditor already fed registry values straight into it, so a package
declaring that string crashed a scan. Validating on the export path would have
been a second call site for the same defect.

## Decision

Every license value is classified by validating it, not by which field carried
it. One SPDX list entry becomes CycloneDX `license.id` in its canonical
spelling; a value that parses as an expression becomes `expression`; anything
else stays free text in `license.name`.

Several licenses on one component are *listed*, not related. A source reporting
`["MIT", "Apache-2.0"]` says which licenses it found, not whether both apply or
either may be chosen, so CycloneDX emits one entry per license — a list asserts
no relationship — and `MIT AND Apache-2.0` is never claimed of a package that
may be offered under either. A source that knows the relationship states it in
one value (`Apache-2.0 OR MIT`, how registries record dual licensing), which
arrives as a single expression and passes through untouched.

SPDX 2.3 is the exception, because it holds one expression per package and has
no form for an unrelated list. There the licenses join with `AND`: conservative
in that it overstates obligations rather than understating them, but still more
than the source said. This is the one deliberate cross-format difference, and
it is recorded in `docs/SBOM.md`. CycloneDX composes only when a member is
itself compound, where listing would degrade a real expression to free text.

A set that mixes valid expressions with free text cannot compose while the
free text stays free text, so CycloneDX falls back to one entry per license.
SPDX no longer falls back at all: the unrecognized member becomes a
`LicenseRef-*`, which is a valid expression element, so the set composes
whole. See the note below.

SPDX `licenseConcluded` is always `NOASSERTION`. Concluded is the document
creator's own determination, and Bomly has none to offer: every license it
holds is declared by a lockfile or a registry — `LicenseType` has no other
value — and no stage analyzes package contents. SPDX names exactly this case,
`NOASSERTION` when the creator made no attempt to determine the field, and
Syft resolves it the same way for metadata-derived licenses. Nothing is lost,
because `licenseDeclared` still carries what the source asserted, and ingest
skips `NOASSERTION` and falls through to it.

All SPDX expression parsing goes through `internal/licenseexpr`, which recovers
from the parser's panics and reports the value as one it could not parse. No
other package under `internal/` may import the parser directly.

## Consequences

Values that never were valid expressions are now published as free text rather
than as `expression`. This is a visible change in output for packages whose
declared license is not SPDX, and it is the point: the previous documents
failed CycloneDX expression validation.

Multi-license packages gain licenses in SPDX that were previously dropped. The
two exports of one scan agree wherever a format can express the same thing;
they differ for a multi-license component, where CycloneDX lists and SPDX must
compose. A cross-format comparison will score that as a mismatch. Accuracy is
worth more than the similarity number: making the documents agree would mean
asserting a relationship in CycloneDX that no source stated.

`TestNoDirectSPDXExpressionUse` fails when any package under `internal/` imports
the SPDX parser directly, so the panic guard cannot be bypassed by a new call
site writing the call out by hand. `FuzzSPDXLicenseValue` exercises
classification and composition over untrusted values on the export path; it is
what found the parser panic. The auditor is covered by the wrapper's own tests
rather than by that target, which does not call it: routing the auditor through
`licenseexpr` is what fixes its crash.

One limitation was knowingly left in place, and has since been resolved --
see the note below.


## Note (2026-09-05): the SPDX free-text limitation is resolved

This ADR recorded that SPDX has no free-text license field, so an unrecognized
value was written verbatim into `licenseDeclared` where it is not a valid
expression, and that representing it as a `LicenseRef` was the correct fix but
a separate decision. That decision is taken: bomly-cli#410.

An unrecognized value now mints a `LicenseRef-*` and the original text travels
with the document in `hasExtractedLicensingInfos`. Unlike `NOASSERTION` this
loses nothing -- ingest reads the text back -- and unlike the old behavior the
field holds something SPDX defines.

It also retires the mixed-validity fallback this ADR described. A `LicenseRef`
is a valid expression element, so a set mixing recognized and unrecognized
values composes whole instead of keeping the first value and dropping the
rest. That fallback was the quieter half of the defect: it dropped licenses a
source had actually declared, and said so only in a comment.

Minting is `bomly-sdk/spdxkit`'s, not this repository's. The identifier has to
be deterministic, collision-free across components assembled without
coordination, and confined to the characters the SPDX idstring grammar allows;
`MintLicenseRef` answers all three by hashing the whitespace-normalized text.
What stays here is the policy this ADR is about -- which values are classified
how, and that classification is by validation rather than by the field a value
arrived in.

The body above refers to `internal/licenseexpr`, the CLI-local wrapper that
contained the parser's panics when this was decided. That package is gone
(bomly-cli#428): `bomly-sdk/spdxkit` carries the same six functions and the
same panic guard, and no package under `internal/` may import the parser
directly. Read those references as naming the kit. The decision this ADR
records is unchanged -- only where the code that implements it lives.
