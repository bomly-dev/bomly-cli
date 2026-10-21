# ADR-0041: Identity is the canonical PURL on typed graph nodes

- **Date:** 2026-08-29
- **Revised:** 2026-10-19 (folds ADR-0021; supersedes ADR-0036)
- **Status:** Accepted

## Context

"What makes two nodes the same node?" had no single owner. `StableID()`
collided across ecosystems, a dozen call sites minted IDs by string
concatenation, three rewrite sites disagreed, and one untyped struct played
every role: root project, workspace module, manifest file, third-party
package. ADR-0036 answered with a bespoke identity grammar and content
address; ten hardening rounds proved it could be made robust, and that it
should not exist beside the industry's own identifier.

## Decision

- The graph is a sealed union of three node kinds. A **manifest node** is a
  structural file record identified by path, never matched. A **module
  node** is one of the project's own artifacts (the root, each workspace or
  reactor member), identified by declaring manifest path plus PURL or name;
  first-party ownership is the kind, not a flag. A **dependency node** is one
  resolved third-party package, the unit of matching. Constructors are the
  gate: a dependency node that cannot mint a valid PURL is a construction
  error, never an empty ID.
- Dependency identity is the canonical package URL, all of it and only it.
  The library decides syntactic validity, a `purlkit` table transcribed from
  the specification decides per-type structure, and unknown types pass on
  syntax. Qualifiers are identity, except the three URL-valued evidence
  qualifiers (`repository_url`, `download_url`, `vcs_url`), which relocate
  into origins. A missing version is accepted with a warning.
- Origin is metadata, not identity: a node carries a union-merged origins
  list (ADR-0033). There are no occurrence suffixes, ordinals or content
  addresses.
- Two nodes are the same when kind and identity match; merging unions scopes,
  locations, origins and edges. The readable graph ID is the identity itself.
- The wire adds one `omitempty` `kind` field. A payload without it infers the
  kind from legacy fields; an unrecognized kind, or an identity that cannot
  mint a PURL, is a decode error.
- A name that leaves the process (an advisory lookup, a cache key, an SBOM
  component name) uses `Coordinates.EcosystemName()`, which rejoins `Org` and
  `Name` only for ecosystems whose databases key on the joined form. OS
  packages keep the bare name because `Org` there is the distro.

## Rejected

ADR-0036's facet grammar and content address, never shipped. Splitting identity on
origin: resolvers pick one source per package and version, and
cross-manifest attribution lives in the per-entry graphs.

## Consequences

- A same-version registry package and git fork share a node unless the
  detector expresses the source in the PURL; matching is PURL-keyed, so no
  advisory precision is lost.
- Folding by PURL unions edge sets, so path traversal is PURL-granular.

Enforced by: the SDK constructors and wire fixtures; the `purlstring` and
`nodeinsert` analyzers in `internal/tools/guardcheck`.
