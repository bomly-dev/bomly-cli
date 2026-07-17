## How `bun` resolves

`bun-detector` parses committed text `bun.lock` files directly. Versions 0 and 1 are supported, including JSONC comments and trailing commas, workspaces, aliases, package tuple metadata, dependency groups, and duplicate package versions. No Bun installation or subprocess is required for this primary path.

| Detector | Position | Technique | Command |
| --- | --- | --- | --- |
| `bun-detector` | Primary | Lockfile parser | None |
| `bun-native-detector` | Fallback for installed or legacy projects | Build tool | `bun pm ls --all` |
| `syft-detector` | Final fallback | Multiple | Embedded or external Syft |

### Offline behavior

✅ Native `bun.lock` parsing is fully offline-safe. Download URLs in the lockfile are recorded as package provenance and are never fetched.

⚠️ When a text lockfile is unavailable, the Bun CLI fallback reads the installed package tree without fetching packages. It preserves nested edges, resolves workspace identities, and recovers unique direct dependencies from `package.json`; hoisted packages whose parent cannot be proven are retained with an `unknown` relationship. If Bun is unavailable or the project is not installed, the Syft fallback handles `bun.lockb` with reduced graph fidelity.

### Requirements and migration

- Commit `bun.lock` for deterministic native scans.
- `bun.lockb` repositories can migrate without installing dependencies: `bun install --save-text-lockfile --frozen-lockfile --lockfile-only`.
- Install-first can run `bun install` only when explicitly requested; normal detection never installs dependencies.

### Workspace behavior

Each entry in the lockfile's `workspaces` object becomes its own manifest-scoped graph. Workspace links point to application nodes and published packages remain distinct even when they share a display name with a workspace.

### Limitations

- The unstable binary `bun.lockb` format is intentionally not decoded by core.
- `bun pm ls --all` exposes a hoisted installed tree. The CLI fallback preserves displayed child edges but does not invent parents for top-level transitives: unresolved parents remain `unknown` and still participate in matching, audit, policy, and output stages.
- Registry metadata enrichment requires `--enrich`; lockfile parsing itself performs no network calls.
