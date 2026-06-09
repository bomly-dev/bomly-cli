## How `npm` resolves

The default chain is **lockfile-first**: `npm-detector` parses `package-lock.json` directly and produces a full transitive graph with edges, scope (`runtime` / `development`), and resolved versions. If the native variant is preferred (chain reorders to favor it), `npm-native-detector` runs `npm ls` instead. The Syft fallback runs only when no native detector applies.

| Detector | Runs by default | Strategy | Command |
| --- | --- | --- | --- |
| `npm-detector` | Yes | Lockfile parser | None |
| `npm-native-detector` | Fallback | Build tool | `npm ls --all --json --package-lock-only` |
| `syft-detector` | Final fallback | Cataloger | (Syft internal) |

## Network behavior

✅ The default `npm-detector` is **fully offline-safe**. It reads `package-lock.json` and does not run any subprocess.

⚠️ `npm-native-detector` runs `npm ls`. With `--package-lock-only`, npm does not consult `node_modules` or fetch from the registry; the lockfile is authoritative. If `package-lock.json` is missing or incomplete, npm may emit warnings but does not download packages.

## Prerequisites

- A committed `package-lock.json`. Lockfile format **version 2 or higher** (`"lockfileVersion": 2` or `3`) is required for full edge fidelity; version 1 lockfiles parse but with reduced detail.
- No Node.js installation is required to scan. Bomly parses the lockfile directly.
- For `--install-first`: `npm` on `PATH`.

## `--install-first`

`npm` supports `--install-first`. When passed, Bomly runs `npm i` in the project directory before resolving the graph.

⚠️ **`--install-first` downloads packages from the npm registry.** This is the opposite of offline-safe — it modifies `node_modules/` and may fetch hundreds of MB. Use it only when the lockfile is missing or stale and you want Bomly to refresh it.

```bash
bomly scan --install-first
```

### Customizing the install command

Append flags to `npm install` with repeatable `--install-arg`. Requires `--detectors npm-detector` so the args target this detector unambiguously.

```bash
# Tolerate peer-dependency conflicts on a legacy project
bomly scan --install-first --detectors npm-detector \
  --install-arg --legacy-peer-deps --install-arg --no-audit
```

## Examples

### Fix a direct vulnerability

1. Bump in `package.json`: change the affected range to one that includes the fix.
2. Re-lock: `npm install`.
3. Re-scan to confirm.

### Pin a transitive vulnerability

Use npm `overrides` (npm v8.3.0 or higher):

```json
{
  "overrides": {
    "lodash": "4.17.21"
  }
}
```

Re-lock, re-scan.

### Workspaces

Bomly walks the workspace tree and scans each workspace as a separate subproject. The consolidated graph shows which workspace introduced each shared dependency.

```bash
bomly scan --path ./monorepo
bomly explain lodash --path ./monorepo
```

## Reachability (experimental)

> **Experimental.** Reachability is opt-in via `--analyze`. The feature is stable in shape but may evolve; ecosystem coverage is expanding.

For npm packages, the analyzer is `jsreach` at **Tier-3 (package)**. It walks app source from `package.json` entry points and reports a package as reachable when there is any path from app source to that package through the npm dep graph. See [REACHABILITY.md](../../../REACHABILITY.md#unreachable-is-not-safe) — Tier-3 "unreachable" is a triage signal, not a safety guarantee.

In workspace monorepos, `jsreach` automatically follows imports between consumed sibling packages by workspace package name. Unused siblings do not widen the reachable set.

## Limitations

- **`npm link`-ed packages are not in the lockfile** and therefore not in the graph. Run a normal `install` before scanning.
- **Optional and peer dependencies** are recorded with their lockfile flags, but enforcement of peer-dep version constraints is not re-evaluated.
- **Subpath imports collapse to the package name** for reachability. `import 'lodash/get'` and `import 'lodash/fp'` both attribute to `lodash`.
- **Lockfile v1** (npm v5–v6) parses but with reduced edge fidelity. Upgrade to npm v7+ for full graph data.
