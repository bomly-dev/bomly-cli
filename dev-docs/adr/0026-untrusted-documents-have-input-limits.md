# ADR-0026: Untrusted input is bounded before decoding and parsed strictly

- **Date:** 2026-07-27
- **Revised:** 2026-10-19 (folds the strict-parsing half of ADR-0039)
- **Status:** Accepted

## Context

Bomly decodes documents it did not write: repository manifests and
lockfiles, SBOMs, baselines, configuration, matcher API responses, cache
entries, remote checkouts. Each is a place where an oversized document can
exhaust memory, or an ambiguous one can make two readers disagree about what
it says.

## Decision

- Every untrusted document has a byte limit checked both on the size
  reported at open and on the bytes actually read, so a file that grows
  during the read cannot bypass it. A parser never receives a partial
  over-limit document. Entry-count limits accompany byte limits where a
  document is a list. The limits and their values are listed in
  `dev-docs/SECURITY_ASSURANCE.md`.
- A failed matcher response exposes only the HTTP status; upstream bodies
  never reach errors or logs. Corrupt or oversized cache entries degrade to
  a miss.
- A remote Git materialization has a deadline, fetches no submodules or LFS
  objects, and the completed checkout is validated before discovery: bounded
  path count, regular-file bytes and depth, and no symlink whose lexical
  target escapes the checkout. Transfer bytes cannot be capped portably and
  are left to an operating-system quota.
- SBOM ingest parses strictly. A repeated member name, invalid UTF-8, or an
  escaped lone UTF-16 surrogate is rejected with an error naming the class;
  these are exactly the documents RFC 8259 says readers will not agree on.
  The codec lives in `bomly-sdk/sbom`, and nothing in this repository parses
  strictly on its own.
- The plugin wire (`bomly.plugin.v1`) keeps lenient decoding: enabled
  plugins are trusted native processes, and its compatibility contract is
  frozen fixtures. Tightening it is a protocol decision.

## Rejected

Trusting the size reported at open alone; repairing a malformed document
into a best-effort reading.

## Consequences

- Strict ingest rejects some documents older versions accepted; each
  rejection names the offending key or byte sequence.
- The hidden benchmark's clone runner is outside the customer boundary and
  does not inherit checkout validation.

Enforced by: the `depguard` rule scoping `encoding/json/v2` to the SDK codec
in `.golangci.yml`; the SDK's ingest fuzz targets.
