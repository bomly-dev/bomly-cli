# Dependency graph evidence

Bomly's findings depend on the graph produced before enrichment or audit.
These public cases check the graph first: package identity, version,
relationship, scope, source, and the manifest that owns each occurrence.

The cases use complete public example repositories at recorded Git commits.
Their normalized JSON results are checked into `test/smoke/testdata/golden`.
The evidence catalog records a SHA-256 checksum for every result, so an
expected change must also update the public evidence record.

## What is covered

| Case | Input evidence | Detector path | What the case checks |
| --- | --- | --- | --- |
| `graph-npm` | `package-lock.json` | npm lockfile detector | Package inventory, versions, scopes, and placement |
| `graph-pnpm` | `pnpm-lock.yaml` | pnpm lockfile detector | Package inventory and placement |
| `graph-yarn` | `yarn.lock` | Yarn lockfile detector | Package inventory and placement |
| `graph-bun` | `bun.lock` | Native Bun detector | Package inventory and placement |
| `graph-go` | `go.mod` and Go tool output | Go detector | Build-tool-backed module graph |
| `graph-python` | Pinned requirements lock | pip detector | Resolved Python package graph |
| `graph-maven` | `pom.xml` and Maven output | Maven detector | Build-tool-backed JVM graph |

This is placement evidence, not just a list of package names. The Node cases
retain duplicate versions as separate package identities and keep occurrences
attached to the dependency paths represented by each lockfile.

## Reproduce a case

From a Bomly CLI checkout:

```sh
make evidence CASE=graph-npm
```

The command verifies the catalog and prints the exact focused smoke command:

```sh
go test -tags smoke ./test/smoke/ -v -count=1 -timeout 15m \
  -run 'TestScan$/scan-npm$'
```

The smoke test builds Bomly, clones the recorded public input, selects the
named detector, normalizes only documented volatile fields, and compares the
result with the checked-in JSON.

## Example review workflow

A maintainer updates a lockfile and wants to confirm that Bomly still sees the
same dependency structure:

1. Run the matching graph case before changing the detector.
2. Make the detector change.
3. Run the case again.
4. Review every golden change as a package, relationship, scope, source, or
   manifest-placement change.
5. Update the catalog checksum only when the new graph is intentional.

This makes a changed count a starting point for review, not the conclusion.
The actual package and occurrence records explain what changed.

## Degraded and unknown evidence

Bomly can fall back when a preferred detector cannot run. A fallback is not
silently treated as equivalent: the result records which detector failed,
which detector ran, and whether coverage was reduced. Unresolved package
placement remains `unknown`; a synthetic link to a manifest helps navigation
but does not become a direct or transitive parent claim.

The graph cases above pin their detector selector. If that detector is not
ready or fails, the smoke test fails instead of accepting a differently shaped
fallback result.

## Limits

- A case proves the checked repository and lockfile shape, not every format
  version ever produced by that package manager.
- Build-tool-backed cases depend on compatible local tools and may need
  registry access to resolve artifacts.
- A fallback inventory can contain useful packages while carrying less
  relationship or source evidence than a native graph.
- Project roots, workspaces, local paths, Git dependencies, and arbitrary URL
  dependencies stay in the graph but are not queried as published registry
  packages.
- Graph evidence does not prove advisory accuracy. Matching is a later step
  with separate evidence and limits.
