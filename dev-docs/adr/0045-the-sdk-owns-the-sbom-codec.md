# ADR-0045: The SDK owns the SBOM codec

- **Date:** 2026-09-13
- **Status:** Accepted

## Context

The SBOM codec — the SPDX 2.3 and CycloneDX encoding and decoding of a
dependency graph — exists three times: `bomly-cli/internal/sbom`,
`bomly-plugin-grype-matcher/internal/sbom`, and
`bomly-plugin-syft-detector/internal/sbom`. Issue #459 measured the three
copies against each other. The two plugin copies were extracted from the CLI
on the same day, took the same two SDK-adoption commits independently, and
differ from each other in comment prose only; a shared typo
(`parseSPDXYcosystem`) survives in all three. The CLI copy is a strict
superset that has taken fifteen commits of fixes since the extraction, and two
of them — LicenseRef minting for unrecognized license strings (#429) and
reading the end-of-life claim back (#438) — landed on code paths the plugins
share and did not reach them at the time. The grype matcher's external path
could therefore hand the `grype` binary an SPDX document with an invalid
`licenseDeclared` expression.

This is the defect class ADR-0040 exists to prevent: shared meaning kept in
more than one place drifts, and the drift is found by a user rather than by
the tree. The SDK already requires both format libraries the codec needs
(`cyclonedx-go`, `spdx/tools-golang`) and already owns the SBOM vocabulary —
digest names, scope mapping, external references, document assertions. The
codec's package closure adds no `go.mod` entry to the SDK's.

Three options were costed in #459. The SDK could own the full CLI codec; it
could own a minimal core with the CLI keeping a richer layer on top; or it
could own only the two functions the plugins call and leave the CLI copy in
place. The middle option is the one that produced this situation and is
rejected on that ground. The third is the smallest change and the largest
immediate saving, but it leaves the CLI and the SDK as two implementations
of the same formats, which is the same defect one release later.

## Decision

bomly-sdk owns the SBOM codec, in full. The CLI's `internal/sbom` — its
document model, both format codecs, strict ingest, the graph projection in
both directions, and `internal/graphview`, which is pure graph-traversal
semantics — moves into the SDK as one public package. The plugins delete
their copies and call the SDK. The CLI deletes its copy and calls the SDK,
keeping only what is presentation or command surface: rendering, output
specs, the scan command's build options, and the smoke goldens that pin the
bytes.

The move is executed as the release train the SDK's own ordering rule
requires and nothing shorter: the SDK releases the package; both plugin
repositories adopt it and release; then the CLI pins the new SDK and both
new plugin tags in one change, with `make generate` for schema and document
drift and a golden refresh. Minimum version selection compiles the plugin
modules against the CLI's SDK pin, so the plugins must adopt and release
before the CLI does; the order cannot be shortened.

Before the train starts, the plugin copies are made a genuine subset of what
the SDK will own: identical to each other, carrying the CLI's correctness
fixes, and free of the `anchore/syft` import the plugin codec uses only to
recognize a format it then refuses. Those are landable in the plugin
repositories today and need no SDK release.

## Consequences

- The SDK takes on a permanent contract surface of roughly thirty-six
  declarations: the document model, the targets, build and encode options,
  the marshal and unmarshal entry points, the projections, and the sentinel
  errors. The SDK is public and pinned by every plugin author, so this
  surface cannot be walked back the way an `internal/` package can. That is
  the price of one codec, accepted knowingly, and it is why the decision is
  recorded here rather than made inside a pull request.
- The CLI's 152 codec tests, five fuzz targets and smoke goldens move with
  the code or stay as consumers of it. Any behavioural difference introduced
  while lifting shows up as golden churn, and churn is where a regression
  hides; the lift is therefore behaviour-preserving by construction and
  measured against the goldens before and after.
- A half-migration is worse than the status quo: if the train stalls between
  the SDK release and the CLI adoption, there are four implementations. The
  train is started only when there is room for an SDK minor plus two plugin
  minors before the next CLI release.
- The cheapest guard against re-drift until the train lands is a check in
  each plugin repository that fails when its `internal/sbom` diverges from
  the other's, so the next unreviewed edit is a build failure rather than a
  discovery six months later.
- `dev-docs/ARCHITECTURE.md`, `CLAUDE.md` and `AGENTS.md` update their
  package tables when the CLI package is deleted, not before.

> **Amended 2026-09-15:** the train ran. bomly-sdk v0.12.0 carries `sbom`
> and `graphview`; bomly-plugin-grype-matcher#12 and
> bomly-plugin-syft-detector#11 drop their copies; this repository deletes
> `internal/sbom` and `internal/graphview` and pins the release. "Behaviour-
> preserving by construction" held for the goldens, not for the code: review
> of bomly-sdk#88 fixed data-loss defects every copy had shipped (ref-less
> CycloneDX components overwriting each other, a primary component listed
> only in metadata dropped on ingest, vulnerabilities, lifecycle and
> composition lost on a direct round trip, non-ASCII and repeated SPDX
> identifiers, and more), and every CLI smoke golden was re-run against the
> reviewed SDK with no drift. A syft-json document is now recognized and
> refused with `sbom.ErrSyftJSONUnsupported`, naming the conversion. The
> declared-versus-concluded license split is still open as bomly-sdk#90.
