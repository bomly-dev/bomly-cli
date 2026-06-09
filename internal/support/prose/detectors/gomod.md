## How `gomod` resolves

`gomod` is the only native Go detector. It is a **build-tool primary** chain — there is no committed-lockfile fallback. To resolve a graph, Bomly shells out to the Go toolchain.

| Step | Command | Working dir |
| --- | --- | --- |
| Resolve graph | `go list -deps -json all` (with `-tags <tags>` if `BOMLY_GO_TAGS` is set) | every directory containing a `go.mod` |

The output is a JSON stream of module + package descriptors, which Bomly parses into a transitive dependency graph with edges.

## Network behavior

⚠️ `go list -deps -json all` **may download modules** during normal scan, before `--enrich`:

- If `go.sum` is missing or incomplete, the Go toolchain will fetch the missing modules from `GOPROXY` (default: `proxy.golang.org`).
- If a referenced module version is not in the local module cache (`$GOMODCACHE`, usually `$GOPATH/pkg/mod`), the Go toolchain will fetch it.

To keep the scan fully offline:

- Commit a complete `go.sum` (run `go mod tidy` and commit the result).
- Or pre-populate the module cache with `go mod download` before scanning.
- Or vendor everything with `go mod vendor` and Bomly will read from `vendor/modules.txt`.

This is a Go-toolchain behavior, not a Bomly choice. The same network calls happen when you run `go build` or `go test` locally.

## Prerequisites

- Go **1.21 or later** on `PATH`. Bomly does not bundle a Go toolchain.
- A `go.mod` at the root of every module you want resolved. Bomly walks down from the scan target and treats every directory containing `go.mod` as a separate subproject.
- `GOPROXY` reachable if your `go.sum` is incomplete or the module cache is cold.
- Set `BOMLY_GO_TAGS=integration,e2e` to evaluate the graph with build tags applied. Without the env var, the default tag set is used.

## `--install-first`

`gomod` supports `--install-first`. When passed, Bomly runs `go mod download` before resolving the graph, populating the local module cache so the subsequent `go list -deps -json all` runs without network.

⚠️ **`--install-first` downloads modules from `GOPROXY`.** Use it in CI on a clean checkout to make the resolution phase deterministic and offline.

```bash
bomly scan --install-first
```

### Customizing the install command

Append flags to `go mod download` with repeatable `--install-arg`. Requires `--detectors go-detector` so the args target this detector unambiguously.

```bash
# Verbose download output for CI debugging
bomly scan --install-first --detectors go-detector --install-arg -x
```

## Multi-module workspaces

Each `go.mod` directory under the scan root is a separate subproject. Bomly resolves each module independently and consolidates the resulting graphs into one report. Go workspace files (`go.work`) are honored by the Go toolchain.

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

### Vendored mode

If your repository commits `vendor/`, the Go toolchain reads from `vendor/modules.txt` and skips network entirely.

## Reachability (experimental)

> **Experimental.** Reachability is opt-in via `--analyze`. The feature is stable in shape but may evolve; ecosystem coverage is expanding.

For Go, the analyzer is `govulncheck` at **Tier-1 (symbol)** — it builds a real call graph and reports a vulnerability as reachable only if your code can reach the specific vulnerable function or method. Reflection (`reflect.Value.Call`, etc.) and dynamic plugin loading are blind spots.

`govulncheck` requires a buildable module. Build failures surface as `reachability.status=unknown` with a `reason` like `build-failed`, `missing-toolchain`, or `module-resolution-failed`.

```bash
bomly scan --analyze --enrich --audit \
  --fail-on high --fail-on reachable
```

## Limitations

- **`cgo` files are parsed but their C dependencies are not in the graph.** Bomly tracks Go modules, not system libraries linked via `cgo`.
- **`go generate` is not invoked.** Generated files must be committed for the detector to see them.
- **Pre-release suffixes (`-rc1`, `-beta.2`, pseudo-versions)** are passed through verbatim; advisory ranges that use semver pre-release ordering may produce false positives at the boundary.
- **GOPRIVATE modules** are resolved through your local `GOPROXY` configuration. Bomly does not authenticate to private proxies on its own.
