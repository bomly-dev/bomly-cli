# Detectors

Detectors are the part of Bomly that read a project, container, or SBOM and turn the evidence into a dependency graph.

Bomly plans detector work before a scan starts. It looks for package-manager evidence such as lockfiles, manifests, workflow files, or SBOM documents, then runs the best detector chain for each discovered subproject. Native detectors run first when Bomly can produce a richer graph itself. Syft-backed detection fills coverage gaps and container/image scenarios.

## When Detectors Run

- `bomly scan` runs detectors to build the graph.
- `bomly explain` reuses the same detector planning before finding dependency paths.
- `bomly diff` runs detectors for each side of the comparison unless you diff SBOM files.
- Detector plugins participate in the same planning flow when they declare package-manager evidence.

## Detector Chains

A detector chain is the ordered list Bomly tries for a package manager. The first detector is preferred. A later detector is a fallback when the preferred detector is not ready, not applicable, or cannot produce graph data.

Some detectors can run an ecosystem tool such as `npm`, `go`, `mvn`, `dart`, `swift`, or `sbt`. Bomly does not install package managers for you. Use `--install-first` only when you want detectors that support it to run their normal dependency-install command before resolving the graph.

## Generated Ecosystem Guides

The pages in `docs/detectors/ecosystems/` are generated from Bomly's registry. Each page lists supported package managers, evidence patterns, chain order, install-first support, and the native commands users may need on `PATH`.
