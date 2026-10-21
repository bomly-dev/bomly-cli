## How `gomod` resolves

`go-detector` is the only native Go detector, and it is a **build-tool primary** chain. There is no committed-lockfile fallback. To resolve a graph, Bomly runs the Go toolchain.

| Step | Command | Working dir |
| --- | --- | --- |
| Resolve graph | `go list -deps -json all` (with `-tags <tags>` when `BOMLY_GO_TAGS` is set) | the directory containing `go.mod` |

The output is a JSON stream of module and package descriptions, which Bomly turns into a transitive dependency graph with edges.

`go list` **may download modules** during a plain scan. If `go.sum` is incomplete, or a module version is not in the local module cache, the Go toolchain fetches it from `GOPROXY`. That is the toolchain's behavior, not Bomly's, and the same downloads happen when you run `go build`. See [Network and privacy](../../NETWORK.md) for the shared rule. To keep the scan offline, do one of these:

- Commit a complete `go.sum` (run `go mod tidy` and commit the result).
- Fill the module cache with `go mod download` before scanning.
- Vendor everything with `go mod vendor`, so the toolchain reads `vendor/modules.txt`.

## Prerequisites

- A Go toolchain on `PATH`. Bomly does not bundle one.
- A `go.mod` in the scanned directory. Each `go.mod` is its own subproject; to find modules in nested directories, pass `--recursive`.
- `GOPROXY` reachable when `go.sum` is incomplete or the module cache is cold.
- Set `BOMLY_GO_TAGS=integration,e2e` to resolve the graph with build tags applied. Without it, the default tag set is used.

## Examples

### Fix a direct vulnerability

1. `bomly scan --enrich --audit` reports `github.com/example/lib v1.2.3` as `CVE-2024-xxxxx`.
2. Find the fixed version in the finding's `fixed_in` field or on the advisory page.
3. Bump it with `go get github.com/example/lib@v1.2.4`, then run `go mod tidy`.
4. Re-scan to confirm the finding is gone.

### Fix a transitive vulnerability

Use a `replace` directive in `go.mod` to override the transitive version until the direct dependency upgrades:

```go
require example.com/parent v1.0.0

replace github.com/example/lib => github.com/example/lib v1.2.4
```

Run `go mod tidy`, re-scan, and remove the `replace` once `parent` releases a fix.

## Multiple modules

The detector resolves one module per `go.mod` and does not expand `go.work` workspaces itself, which is why the table above says no multi-module resolution. To scan several modules in one repository, pass `--recursive` so each `go.mod` directory becomes a subproject. Bomly resolves each one and merges the graphs into one report. The Go toolchain still honors a `go.work` file when it resolves each module.

## Vendored mode

If your repository commits `vendor/`, the Go toolchain reads `vendor/modules.txt` and never uses the network.

## `--install-first`

With `--install-first`, Bomly runs `go mod download` before resolving the graph. That fills the module cache from `GOPROXY`, so the following `go list` runs offline. Use it in CI on a clean checkout:

```bash
bomly scan --install-first
```

To append flags to that command, repeat `--install-arg`. This requires `--detectors go-detector`:

```bash
# Verbose download output for CI debugging
bomly scan --install-first --detectors go-detector --install-arg -x
```

## Reachability (experimental)

With `--analyze`, the `govulncheck` analyzer builds a real call graph and reports a vulnerability as reachable only when your code can reach the vulnerable function or method. Reflection and dynamic plugin loading are blind spots. It needs a buildable module. A build failure appears as `reachability.status=unknown` with a reason such as `build-failed`, `missing-toolchain`, or `module-resolution-failed`. See [Reachability](../../REACHABILITY.md) for the tier model and its caveats.

```bash
bomly scan --analyze --enrich --audit \
  --fail-on high --fail-on reachable
```

## Limitations

- **C dependencies linked through cgo are not in the graph.** Bomly tracks Go modules, not system libraries.
- **`go generate` is not run.** Generated files must be committed for the detector to see them.
- **Pre-release suffixes** (`-rc1`, `-beta.2`, pseudo-versions) are passed through as written. Advisory ranges that use semver pre-release ordering may produce false positives at the boundary.
- **Private modules** (`GOPRIVATE`) resolve through your local `GOPROXY` configuration. Bomly does not authenticate to private proxies on its own.
