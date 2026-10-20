## How `pnpm` resolves

The chain is **lockfile-first**. The `pnpm` detector parses `pnpm-lock.yaml` directly and produces a full transitive graph. The build-tool strategy runs `pnpm list` instead. The Syft fallback runs only when neither strategy produces a graph.

| Detector | Runs by default | Strategy | Command |
| --- | --- | --- | --- |
| `pnpm` (lockfile strategy) | Yes | Lockfile parser | None |
| `pnpm` (buildtool strategy) | Fallback | Build tool | `pnpm list --json --depth Infinity` |
| `syft-detector` | Final fallback | File recognition | None (Syft is built in) |

The lockfile strategy reads one file and runs nothing, so it never uses the network. The build-tool strategy reads local state when the lockfile is complete. If the lockfile is incomplete and `node_modules` is empty, pnpm may fail or, depending on its configuration, fetch missing packages. See [Network and privacy](../../NETWORK.md) for the shared rule.

## Prerequisites

- A committed `pnpm-lock.yaml`. Lockfile **version 6 or higher** gives full graph detail.
- No Node.js or pnpm installation is required to scan. Bomly parses the lockfile directly.
- For `--install-first`: `pnpm` on `PATH`.

## Examples

### Pin a transitive vulnerability

Use `pnpm.overrides` in `package.json` or `overrides` in `pnpm-workspace.yaml`:

```yaml
# pnpm-workspace.yaml
overrides:
  lodash: "4.17.21"
```

Re-lock with `pnpm install` and re-scan.

## Workspaces

Bomly scans each pnpm workspace as a separate subproject. Dependencies marked `injected: true` are followed as regular edges.

## `--install-first`

With `--install-first`, Bomly runs `pnpm i` (the short form of `pnpm install`) in the project directory before resolving the graph. That downloads packages from the npm registry. Use it only when the lockfile is missing or stale:

```bash
bomly scan --install-first
```

To append flags to that command, repeat `--install-arg`. This requires `--detectors pnpm`:

```bash
# Refuse to update the lockfile (fail if it would change)
bomly scan --install-first --detectors pnpm \
  --install-arg --frozen-lockfile
```

## Reachability (experimental)

With `--analyze`, the `jsreach` analyzer reports a pnpm package as reachable when app source imports it, directly or through the dependency graph. It reads the package patterns in `pnpm-workspace.yaml` and follows imports between sibling packages without depending on installed symlinks. Unreachable is a triage signal, not proof of safety; see [Reachability](../../REACHABILITY.md#unreachable-is-not-safe).

## Limitations

- **Symlinked `node_modules`** is pnpm's storage model. Bomly reads the lockfile, not the filesystem layout, so this does not affect the graph.
- **Subpath imports collapse to the package name** for reachability.
- **Lockfiles before version 6** (pnpm 5 and earlier) parse with less detail.

## Configuration

`pnpm` is one detector with two internal strategies, `lockfile` and `buildtool`. Its config block controls their order and whether `--install-first` applies to it:

```yaml
plugins:
  detectors:
    pnpm:
      # Reorder or subset the strategies (default: lockfile, buildtool)
      strategy: [lockfile, buildtool]
      # Set to false to skip this detector when --install-first is passed
      installFirst: true
```

The older detector names `pnpm-detector` and `pnpm-native` still work as selector aliases of `pnpm`.
