# ADR-0049: A pinned origin is one VCS locator in every export

- **Date:** 2026-10-19
- **Status:** Accepted

## Context

A detector that resolves a package from a repository at a revision records
both on the node's origin (ADR-0033). SPDX export wrote the pair as the
version-control locator its section 7.7 defines, `git+<url>@<revision>`;
CycloneDX export wrote only the repository URL, because its external
references have no revision field. On Bomly's own CycloneDX export every
SHA-pinned GitHub Action therefore carried its commit only as a `SHA-1`
hash, which a validator classed as a weak content digest, and nothing said
the value was a version-control object identifier. The vendored CycloneDX
schema defines `vcs` only as "Version Control System" with an IRI `url`; it
neither offers a revision slot nor restricts the URL, so the mapping is
Bomly's policy.

## Decision

- A repository origin pinned to a revision is written as one string in both
  exports, the locator `git+<url>@<revision>`, which SPDX defines and the
  package-URL `vcs_url` qualifier shares. In SPDX it is the download
  location; in CycloneDX it is the URL of the `vcs` external reference. An
  origin with no revision keeps the plain repository URL in CycloneDX. One
  grammar, `bomly-sdk/sbom.vcsLocator`, serves both encoders, and a
  repository already carried by an origin is not written again without its
  revision.
- The synthesized project root carries a description, set by the CLI from
  the execution target, saying why it has no content hash: a source tree is
  described from its manifests and is not a distributed artifact; a container
  image is inventoried from its filesystem. It goes in the description field
  both formats define, where a reader looks first.
- The hash stays as `SHA-1`. A Git object identifier is one, and relabelling
  it would misstate what was computed; the locator beside it says the value
  is a commit.

## Rejected

Dropping the revision on the CycloneDX side for the format's convenience;
relabelling the commit hash to satisfy digest-strength scoring.

## Consequences

- CycloneDX documents change for every component whose detector recorded a
  revision (Python and cargo git sources, SwiftPM and pub pins, GitHub
  Actions). Unpinned and enrichment-sourced `vcs` references are unchanged.
- The codec does not ingest CycloneDX `vcs` references, so the locator is
  never read back as a repository URL with `@<revision>` in its path; SPDX
  ingest already splits the locator.
- A tag or branch reference stays as written with no hash; resolving it to a
  commit needs the network and stays outside the manifest detector.
- A validator wanting a stronger statement about a pinned action needs a
  content digest of the action's tree, which no manifest records.

Enforced by: the SBOM export goldens in `test/smoke` and the codec tests in
`bomly-sdk/sbom`.
