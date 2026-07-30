## What Syft gives you

Syft catalogs packages by pattern-matching files: OS package databases, installed-package manifests, and lockfiles it recognizes. It reports what is present, not how those packages relate to each other.

That difference matters for the rest of the pipeline:

- `bomly explain` needs edges to walk a path from your project to a package. Syft-catalogued packages have no edges, so there is no path to show.
- Scope filters like `--direct-only` rely on the direct/transitive distinction, which comes from the graph. Syft results carry no such distinction.
- Vulnerability and license enrichment work normally — matchers key off the package coordinates, which Syft does provide.

## When Syft runs

Syft is the last entry in almost every detector chain. It runs when the native detector ahead of it cannot produce graph data — no lockfile present, the build tool is missing from `PATH`, or the ecosystem has no native detector at all.

For container images it does most of the work: Bomly scans the layers, and native detectors only apply where a recognizable lockfile made it into the image.

## Turning it off

Syft is a normal detector, so the standard selector grammar applies:

```bash
# Drop the Syft fallback — native detectors only
bomly scan --detectors -syft-detector

# Use only Syft
bomly scan --detectors syft-detector
```

Dropping Syft means a project it was covering resolves nothing, and the scan exits 3 with "no detector chain produced a graph". That is usually what you want in CI when a flat package list would pass a gate that a real graph would fail.

## See also

- [Support matrix](../SUPPORT_MATRIX.md) — every ecosystem and package manager, native and Syft-backed
- [Scan targets](../SCAN_TARGETS.md) — container images and the other input shapes Syft handles
- [Detectors](../DETECTORS.md) — chains, selection, and the native-vs-Syft comparison
