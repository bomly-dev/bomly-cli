## How `yarn` resolves

The default chain is **lockfile-first**: `yarn` (lockfile strategy) parses `yarn.lock` (classic v1 or Berry v2/v3/v4) and produces a full transitive graph. The native variant shells out to `yarn list`; Syft is the final fallback.

| Detector | Runs by default | Strategy | Command |
| --- | --- | --- | --- |
| `yarn` (lockfile strategy) | Yes | Lockfile parser | None |
| `yarn` (buildtool strategy) | Fallback | Build tool | `yarn list --json` |
| `syft-detector` | Final fallback | Cataloger | (Syft internal) |

## Network behavior

✅ The default `yarn` (lockfile strategy) is **fully offline-safe**. It reads `yarn.lock` and does not run any subprocess.

⚠️ `yarn` (buildtool strategy) runs `yarn list`. With a complete lockfile and an installed `node_modules` directory, yarn produces output from local state.

## Prerequisites

- A committed `yarn.lock`. Both classic v1 (`# yarn lockfile v1` header) and Berry v6+ are supported.
- No Node.js or Yarn installation is required to scan. Bomly parses the lockfile directly.
- For `--install-first`: `yarn` on `PATH`.

## `--install-first`

`yarn` supports `--install-first`. When passed, Bomly runs `yarn install` before resolving the graph.

⚠️ **`--install-first` downloads packages from the npm registry.** Use it only when the lockfile is missing or stale.

```bash
bomly scan --install-first
```

### Customizing the install command

Append flags to `yarn install` with repeatable `--install-arg`. Requires `--detectors yarn`.

```bash
# Refuse to update the lockfile and skip optional deps
bomly scan --install-first --detectors yarn \
  --install-arg --frozen-lockfile --install-arg --ignore-optional
```

## Examples

### Pin a transitive vulnerability

Use `resolutions` in `package.json`:

```json
{
  "resolutions": {
    "**/lodash": "4.17.21"
  }
}
```

Re-lock: `yarn install`. Re-scan.

### Berry workspaces

Bomly walks Berry workspaces and scans each as a subproject. Plug-and-Play (`.pnp.cjs`) projects are read through the lockfile, not the runtime resolver — graph fidelity matches the lockfile.

## Reachability (experimental)

> **Experimental.** Reachability is opt-in via `--analyze`. The feature is stable in shape but may evolve; ecosystem coverage is expanding.

For Yarn packages, the analyzer is `jsreach` at **Tier-3 (package)** — same caveats as npm. See [REACHABILITY.md](../../REACHABILITY.md#unreachable-is-not-safe).

`jsreach` reads workspace arrays and Yarn-style `workspaces.packages` objects automatically, then follows imports between consumed sibling packages by package name.

## Limitations

- **Yarn Berry workspaces with `injected: true`** dependencies are followed as regular edges.
- **`portal:` and `link:` protocols** point to local checkouts; their internal dependencies are read from the local package, not the registry.
- **Subpath imports collapse to the package name** for reachability.

## Configuration

`yarn` is one merged detector with two internal strategies (`lockfile`, `buildtool`). Its `plugins.detectors.yarn` config block accepts:

```yaml
plugins:
  detectors:
    yarn:
      # Reorder or subset the internal actions (default: lockfile, buildtool)
      strategy: [lockfile, buildtool]
      # Opt this detector out of --install-first even when the flag is passed
      installFirst: true
```

The historical detector names (`yarn-detector`, `yarn-native`) remain selector aliases of `yarn`.
