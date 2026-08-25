# ADR-0023: Grype OS-package distro comes from the PURL, not pipeline plumbing

- **Date:** 2026-07-25
- **Status:** Accepted

Grype's OS matchers (apk, dpkg, rpm, portage, pacman) are distro-namespace
driven: a package that reaches them without a distro matches nothing, and
because Bomly passes no CPEs and leaves `UseCPEs` false the stock matcher does
not pick up the slack — container OS packages came back clean rather than
unchecked (issue #316). The builtin matcher
(`bomly-plugin-grype-matcher`, `plugin/purl_builtin.go`) derives the distro, and the upstream
source package, from the `distro=` and `upstream=` PURL qualifiers Syft records,
mirroring Grype's own PURL provider.

The alternative was carrying the detected `linux.Release` from the Syft detector
through the graph container, consolidation, and the match stage into
`grypepkg.Context`. The PURL is the better carrier: it is already the registry
key so nothing new has to be threaded through four stages, it survives SBOM
input where no live distro detection is possible, and it keeps a per-package
distro (correct for a graph consolidated from more than one image) instead of a
single scan-wide one. The cost is that OS matching depends on the qualifier
being present — true for image scans and for SBOMs produced from them, false
for hand-written PURLs, which is documented in `docs/matchers/grype.md`.
