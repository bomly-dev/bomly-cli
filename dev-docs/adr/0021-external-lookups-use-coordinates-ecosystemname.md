# ADR-0021: External lookups use `Coordinates.EcosystemName()`, never the bare `Name`

- **Date:** 2026-07-25
- **Status:** Accepted

`Coordinates` stores identity as `Org` + `Name` following the PURL namespace/name split, so `Name` alone is `postcss` for both `postcss` and `@tailwindcss/postcss`. Anything that leaves the process under a name — Grype's DB search, the OSV name-keyed query, name-derived cache keys, SBOM component names, the bare specifiers `jsreach` matches imports against — must use `EcosystemName()`, which rebuilds the ecosystem-native form (`@org/name` for npm, `org:name` for the Maven family, `org/name` for Go, Composer, Swift, and GitHub Actions).

Rejoining is opt-in per ecosystem and every other ecosystem keeps the bare `Name`, because `Org` is only sometimes part of the package name. For OS packages it is the distro that shipped the package (`pkg:apk/alpine/libcrypto3` → `Org: "alpine"`) while Grype's distro-namespace matchers query `libcrypto3`, so a blanket join would trade the npm false positives for missing every OS advisory — the exact data the distro/upstream plumbing below exists to reach. Adding an ecosystem to the join list is a claim about how its advisory databases key packages, and belongs with a test.

This is a correctness boundary, not a formatting preference. Grype searches its DB strictly by the name it is handed and reconstructs a namespace only for Java (from the PURL, in its own resolver), so the bare name made every scoped npm package inherit the same-named unscoped package's advisories, attached to the scoped PURL, with remediation pointing at versions that do not exist for it (issue #319). `DisplayName()` produces a similar string but stays presentation-only and is explicitly not an identity; `QualifiedName()` is the internal `org:name` key. Prefer the PURL wherever a lookup accepts one — `EcosystemName` is for the interfaces that only take a name.
