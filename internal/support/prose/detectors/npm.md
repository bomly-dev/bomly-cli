## Scan your npm / pnpm / yarn project

Bomly has native detectors for all three Node.js package managers. Each parses the lockfile directly and produces a full transitive graph with edges, scope (runtime / development), and resolved versions.

```bash
bomly scan --path .
```

The detector that runs is chosen by the lockfile present:

| Lockfile | Detector |
| --- | --- |
| `package-lock.json` (npm v5+ format) | `npm-detector` |
| `pnpm-lock.yaml` | `pnpm-detector` |
| `yarn.lock` (v1 classic or v2/v3/v4 Berry) | `yarn-detector` |

`package.json` alone (no lockfile) falls back to Syft for a flat package list. To get a full graph, generate a lockfile first (`npm install`, `pnpm install`, or `yarn install`).

## Prerequisites

- A committed lockfile in **version 3 or higher** for npm (`"lockfileVersion": 3`). Older npm lockfiles parse but with reduced edge fidelity.
- For pnpm: lockfile version 6.0 or higher.
- For yarn: classic v1 (`# yarn lockfile v1` header) or Berry v6+.
- No Node.js installation is required to scan. Bomly parses lockfiles directly.
- For `--install-first`: `npm`, `pnpm`, or `yarn` on `PATH` (Bomly will run the install command before resolving).

## Reachability — what `jsreach` tells you

The JavaScript analyzer is **Tier-3 (package)**. It walks your application source from `package.json` entry points (`main`, `module`, `browser`, `exports`, `bin`, plus implicit `index.*` / `app.js` / `server.js` / `main.js` fallbacks) and reports a package as reachable when there is any path from app source to that package through the npm dep graph.

Importantly, "unreachable" is not "safe" — dynamic `require(userInput)`, plugin loaders, and worker threads are invisible. See [REACHABILITY.md](../../REACHABILITY.md#unreachable-is-not-safe).

```bash
bomly scan --enrich --audit --reachability --fail-on high --fail-on reachable
```

## Examples

### Fix a direct vulnerability

1. Bump in `package.json`: change the affected range to one that includes the fix.
2. Re-lock: `npm install`, `pnpm install`, or `yarn install`.
3. Re-scan to confirm the finding is gone.

### Pin a transitive vulnerability

Use npm `overrides`, pnpm `pnpm.overrides`, or yarn `resolutions` to force a fixed version of a transitive dependency without waiting for the parent to release:

```json
// package.json — npm v8.3.0 or higher
{
  "overrides": {
    "lodash": "4.17.21"
  }
}
```

```yaml
# pnpm-workspace.yaml
overrides:
  lodash: "4.17.21"
```

```json
// package.json — yarn classic and Berry
{
  "resolutions": {
    "**/lodash": "4.17.21"
  }
}
```

Re-lock, re-scan.

### Workspace monorepos

Bomly walks the workspace tree and scans each workspace as a separate subproject. The consolidated graph shows which workspace introduced each shared dependency. This works for npm workspaces, pnpm workspaces, and yarn workspaces.

```bash
bomly scan --path ./monorepo
bomly explain lodash --path ./monorepo   # shows which workspace pulled it in
```

## Limitations

- **`npm link`-ed packages are not in the lockfile** and therefore not in the graph. Run a normal `install` before scanning.
- **Optional and peer dependencies** are recorded with their lockfile flags, but enforcement of peer-dep version constraints is not re-evaluated — Bomly trusts what the lockfile says was installed.
- **Subpath imports collapse to the package name**. `import 'lodash/get'` and `import 'lodash/fp'` both attribute to `lodash`; if an advisory affects only `lodash/template`, jsreach still reports `lodash` as reachable when any subpath is imported.
- **TypeScript path mappings (`paths` in `tsconfig.json`)** are not resolved by jsreach. Use real package names for code you want analyzed.
- **`pnpm` workspaces with `injected: true`** dependencies are followed as regular edges.
