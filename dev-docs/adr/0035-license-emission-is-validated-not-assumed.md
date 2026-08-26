# ADR-0035: License emission is validated, not assumed

- **Date:** 2026-08-25
- **Status:** Accepted

## Context

CycloneDX and SPDX both distinguish a checked SPDX license identifier from a
license expression from free text a machine cannot reason about. Bomly's export
did not: it published a license as an `expression` whenever the intermediate
model happened to carry an `SPDXExpression`, and as a free-text `name`
otherwise.

The two fields do not correspond to those two shapes. Sources write whatever
they have into both: the deps.dev matcher sets `Value` and `SPDXExpression` to
the same string, "non-standard" as readily as "MIT". So a package licensed
`MIT` was published as free text, unrecognized text was published as an
expression that does not parse, and two licenses produced two `expression`
entries, which CycloneDX does not allow. SPDX, holding one expression per
package, kept `licenses[0]` and dropped the rest without saying so.

Underneath, the SPDX expression parser Bomly depends on panics rather than
returning an error on some malformed input — `(((` dereferences a nil operator.
The license auditor already fed registry values straight into it, so a package
declaring that string crashed a scan. Validating on the export path would have
been a second call site for the same defect.

## Decision

Every license value is classified by validating it, not by which field carried
it. One SPDX list entry becomes CycloneDX `license.id` in its canonical
spelling; a value that parses as an expression becomes `expression`; anything
else stays free text in `license.name`. Several declared licenses compose into
one `AND` expression — a package offered under several licenses is bound by all
of them — and both formats publish the same composed string. A set that mixes
valid expressions with free text cannot compose without producing something
that does not parse, so CycloneDX falls back to one entry per license and SPDX
to the first value.

SPDX `licenseConcluded` repeats `licenseDeclared`. The values come from a
lockfile or a registry that asserts them, so concluding from them reads
evidence rather than inventing a claim; `NOASSERTION` would discard data Bomly
holds.

All SPDX expression parsing goes through `internal/licenseexpr`, which recovers
from the parser's panics and reports the value as one it could not parse. No
other package under `internal/` may import the parser directly.

## Consequences

Values that never were valid expressions are now published as free text rather
than as `expression`. This is a visible change in output for packages whose
declared license is not SPDX, and it is the point: the previous documents
failed CycloneDX expression validation.

Multi-license packages gain licenses in SPDX that were previously dropped, and
the two exports of one scan now agree on every licensed component.

`TestNoDirectSPDXExpressionUse` fails when any package under `internal/` imports
the SPDX parser directly, so the panic guard cannot be bypassed by a new call
site writing the call out by hand. `FuzzSPDXLicenseValue` exercises
classification and composition over untrusted values; it is what found the
parser panic, and it covers the auditor's crash as a side effect of the
centralization.
