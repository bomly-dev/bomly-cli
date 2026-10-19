# ADR-0049: A pinned origin is one VCS locator in every export

- **Date:** 2026-10-19
- **Status:** Accepted

## Context

A detector that resolves a package from a repository at a revision records
both on the node's origin (ADR-0033). The SPDX export wrote the pair in the
version-control locator form the specification defines in section 7.7,
`git+<url>@<revision>`. The CycloneDX export wrote only the repository URL,
on the reasoning that CycloneDX external references have no revision field.
Issue #508 measured the result on Bomly's own CycloneDX export: every
SHA-pinned GitHub Action carried its commit only as a `SHA-1` hash, which a
CISA 2026 validator classed as a weak content digest, and nothing in the
component said the value was a version-control object identifier.

bomly-cli#518 made the detector record the origin. What remained was the
codec's decision to drop the revision on one side. The vendored CycloneDX
schema defines the `vcs` reference type only as "Version Control System" and
types the `url` as an IRI reference; it neither offers a revision slot nor
restricts what the URL may carry. Where a specification is silent, the
mapping is Bomly's policy, and the policy had been chosen for the format's
convenience rather than the reader's.

The synthesized primary component raised the same question from the other
side: it describes a source tree, which has no content hash, and the document
did not say so. The SPDX package `comment` could not carry the explanation,
because Bomly's codec parses that field back as the `bomly:` scope and type
carrier.

## Decision

A repository origin pinned to a revision is written as one string in both
exports: the version-control locator `git+<url>@<revision>`, which SPDX 2.3
section 7.7 defines and the package-URL `vcs_url` qualifier shares. In SPDX
it is the download location, as before; in CycloneDX it is the URL of the
`vcs` external reference. An origin with no revision keeps the plain
repository URL in CycloneDX, because that is a location a reader can open and
the locator grammar adds nothing to it. `bomly-sdk/sbom.vcsLocator` holds the
grammar for both encoders, and a repository already carried by an origin is
not written a second time without its revision.

The synthesized project root carries a description, set by the CLI from the
execution target: a source tree is described from its manifests and lockfiles
and is not a distributed artifact, so no content hash applies to it; a
container image is inventoried from its filesystem rather than an archive. It
is rendered in the field both formats define for a component's description,
so a consumer reading either document finds the reason where it looks first.

The hash itself stays. A Git object identifier is a SHA-1, both formats name
that algorithm, and relabelling it would misstate what was computed. The
locator beside it is what says the value is a commit rather than a content
digest.

## Consequences

- CycloneDX documents change for every component whose detector recorded a
  revision: Python git sources, cargo git dependencies, SwiftPM and pub pins,
  and GitHub Actions references. Unpinned and enrichment-sourced `vcs`
  references are unchanged.
- The codec does not ingest CycloneDX `vcs` references (the laundering rule
  in `isOriginDerivedReferenceType`), so the locator cannot be read back as a
  repository URL with `@<revision>` in its path. SPDX ingest already splits
  the locator.
- Resolving a tag or branch reference to a commit needs the network and stays
  outside the manifest detector; such a reference carries the repository and
  the ref as written, and no hash.
- Validators that score hash strength are free to keep scoring a SHA-1 as
  weak. Bomly answers with the locator, not by relabelling the hash; a
  validator that wants a stronger statement about a pinned action needs a
  content digest of the action's tree, which no manifest records.
