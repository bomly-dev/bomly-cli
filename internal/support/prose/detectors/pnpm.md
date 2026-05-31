## How `pnpm` resolves

The default chain is **lockfile-first**: `pnpm-detector` parses `pnpm-lock.yaml` directly and produces a full transitive graph. The native variant shells out to `pnpm list`; Syft is the final fallback.

| Detector | Runs by default | Strategy | Command |
| --- | --- | --- | --- |
| `pnpm-detector` | Yes | Lockfile parser | None |
| `pnpm-native-detector` | Fallback | Build tool | `pnpm list --json --depth Infinity` |
| `syft-detector` | Final fallback | Cataloger | (Syft internal) |

## Network behavior

✅ The default `pnpm-detector` is **fully offline-safe**. It reads `pnpm-lock.yaml` and does not run any subprocess.

⚠️ `pnpm-native-detector` runs `pnpm list`. With a complete lockfile, pnpm produces the graph from local state without network calls. If the lockfile is incomplete and `node_modules` is cold, pnpm may fail or, depending on configuration, fetch missing packages.

## Prerequisites

- A committed `pnpm-lock.yaml`. Lockfile **version 6 or higher** is required for full graph fidelity.
- No Node.js or pnpm installation is required to scan. Bomly parses the lockfile directly.
- For `--install-first`: `pnpm` on `PATH`.

## `--install-first`

`pnpm` supports `--install-first`. When passed, Bomly runs `pnpm i` in the project directory before resolving the graph.

⚠️ **`--install-first` downloads packages from the npm registry.** Use it only when the lockfile is missing or stale.

```bash
bomly scan --install-first
```

### Customizing the install command

Append flags to `pnpm install` with repeatable `--install-arg`. Requires `--detectors pnpm-detector`.

```bash
# Refuse to update the lockfile (fail if it would change)
bomly scan --install-first --detectors pnpm-detector \
  --install-arg --frozen-lockfile
```

## Examples

### Pin a transitive vulnerability

Use `pnpm.overrides` in `package.json` or `pnpm-workspace.yaml`:

```yaml
# pnpm-workspace.yaml
overrides:
  lodash: "4.17.21"
```

Re-lock: `pnpm install`. Re-scan.

### Workspace monorepos

Bomly scans each pnpm workspace as a separate subproject. `injected: true` dependencies are followed as regular edges.

## Reachability (experimental)

> **Experimental.** Reachability is opt-in via `--reachability`. The feature is stable in shape but may evolve; ecosystem coverage is expanding.

For pnpm packages, the analyzer is `jsreach` at **Tier-3 (package)** — same caveats as npm. See [REACHABILITY.md](../../REACHABILITY.md#unreachable-is-not-safe).

`jsreach` reads `pnpm-workspace.yaml` package patterns automatically and follows imports between consumed sibling packages without depending on installed symlinks.

## Limitations

- **Symlinked `node_modules`** are pnpm's storage model; Bomly relies on the lockfile, not the filesystem layout, so this works correctly.
- **Subpath imports collapse to the package name** for reachability.
- **Pre-v6 lockfiles** (pnpm v5 and earlier) parse but with reduced detail.
