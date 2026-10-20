# ADR-0033: Occurrence facts are detector-asserted from explicit evidence, never inferred

- **Date:** 2026-08-24
- **Revised:** 2026-10-19 (folds ADR-0016 and the source rule of ADR-0014; narrowed by ADR-0041)
- **Status:** Accepted

## Context

An SBOM should say where each package came from, and a scan should say
whether a dependency is direct and whether it came from a registry, a
repository or a path. The obvious place to derive origin is export, which
sees every package: classify the lockfile's resolved URL by shape. That was
built and abandoned after about twenty review rounds. `ResolvedURL` means a
different thing per ecosystem, every shape heuristic had an ecosystem
counterexample, and an opaque token and a content hash cannot be told apart.

## Decision

- **Origin** is asserted by the detector that read the structured source
  field, as at most one artifact URL or one repository URL plus resolved
  revision, on the typed `DependencyOrigin`. Registry and index roots are not
  representable. `ResolvedURL` stays beside it as raw evidence and is never
  published.
- One rule, `sdk.NormalizeOriginURL`, governs every published origin:
  absolute http(s), host, path, no userinfo, canonical host and port,
  re-serialized from the parse. The repository form drops query and fragment;
  the artifact form rejects a query outright, since a query on a download
  link marks a signed or tokenized URL. It runs when recorded, at the wire,
  and when export reads it.
- Origins accumulate. A node carries `Origins []DependencyOrigin`,
  union-merged, never reconciled, never tie-broken. Two different origins on
  one node are a fact to display (the shape of a dependency-confusion
  signal), not a reason to split identity (ADR-0041).
- **Source** (registry, git, path, workspace) is classified only from
  explicit evidence such as Cargo source prefixes, Bundler sections and lock
  source tables. Where a format does not record it, the source stays unknown.
  The engine and auditors never infer a source from an ecosystem, name or
  URL.
- **Relationship**: a lockfile component whose parent chain cannot be
  recovered attaches under its owning module with relationship `unknown`,
  never `direct`; its known descendants stay transitive.
- Origin is written on export and never read back on ingest, because it
  describes what a manifest said. It does not appear in scan, diff or
  explain documents.

## Rejected

Export-time classification of `ResolvedURL`; a credential-prefix or
secret-shape heuristic (the URL grammar check already fails local paths, ssh
remotes and credentialed URLs).

## Consequences

- An external detector plugin asserts origin exactly as a built-in does.

Enforced by: `TestExportNeverReadsResolvedURL` in `bomly-sdk/sbom`; the
`nodeinsert` analyzer in `internal/tools/guardcheck`.
