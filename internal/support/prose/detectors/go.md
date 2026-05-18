## Scan your Go module

Bomly's native Go detector reads `go.mod` and the resolved module graph and produces a full transitive dependency graph with edges. It does not require `go.sum` to be present, but a missing `go.sum` may force network resolution.

```bash
bomly scan --path .
```

The full pipeline is offline. Add `--enrich` for OSV/KEV/license data, `--audit --fail-on high` to gate CI, and `--reachability` for symbol-tier reachability via the vendored `govulncheck` library.

```bash
bomly scan --enrich --audit --reachability --fail-on high
```

## Prerequisites

- Go **1.21 or later** on `PATH`. Bomly does not bundle a Go toolchain.
- A `go.mod` at the root of every module you want resolved. Bomly walks down from the scan target and treats every directory containing `go.mod` as a separate subproject.
- `GOPROXY` reachable if a module needs to be downloaded to resolve the graph. To avoid network during the scan, run `go mod download` first or vendor with `go mod vendor`.
- For reachability: a buildable module (the `govulncheck` library compiles your code). Build failures surface as `reachability.status=unknown` with a `reason` like `build-failed`, `missing-toolchain`, or `module-resolution-failed`.

## Multi-module workspaces

Each `go.mod` directory under the scan root is a separate subproject. Bomly resolves each module independently and consolidates the resulting graphs into one report. Go workspace files (`go.work`) are honored.

## Reachability — what `govulncheck` tells you

The Go analyzer is **Tier-1 (symbol)**: it builds a real call graph and reports a vulnerability as reachable only if your code can reach the specific vulnerable function or method. This is significantly stronger than the Tier-3 import-graph closure used for other ecosystems.

`reachability.status = reachable` means there is a static call path from your binary's entry point to the vulnerable symbol. Reflection (`reflect.Value.Call`, etc.) and dynamic plugin loading are blind spots.

```bash
# Only fail on high-or-above advisories that are actually called
bomly scan --reachability --enrich --audit \
  --fail-on high --fail-on reachable
```

## Examples

### Fix a direct vulnerability

1. `bomly scan --enrich --audit` flags `github.com/example/lib v1.2.3` as `CVE-2024-xxxxx`.
2. Find the fixed version in the finding's `fixed_version` field or on the advisory page.
3. Bump in `go.mod`: `go get github.com/example/lib@v1.2.4` then `go mod tidy`.
4. Re-scan to confirm the finding is gone.

### Fix a transitive vulnerability

Use a `replace` directive in `go.mod` to override the transitive version until the direct dependency upgrades:

```go
require example.com/parent v1.0.0

replace github.com/example/lib => github.com/example/lib v1.2.4
```

Run `go mod tidy`, re-scan, and remove the `replace` once `parent` releases a fix.

### Vendor mode

If your repository commits `vendor/`, Bomly resolves the graph from `vendor/modules.txt` without network. Both `go build -mod=vendor` and `go build -mod=mod` projects work.

## Limitations

- **`cgo` files are parsed but their C dependencies are not in the graph.** Bomly tracks Go modules, not system libraries linked via `cgo`.
- **`go generate` is not invoked.** Generated files must be committed for the detector to see them.
- **Pre-release suffixes (`-rc1`, `-beta.2`, pseudo-versions)** are passed through verbatim and compared lexicographically; advisory ranges that use semver pre-release ordering may produce false positives at the boundary.
- **GOPRIVATE modules** are resolved through your local `GOPROXY` configuration. Bomly does not authenticate to private proxies on its own.
