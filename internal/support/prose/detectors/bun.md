## How `bun` resolves

`bun-detector` parses committed text `bun.lock` files directly. Versions 0 and 1 are supported, including JSONC comments and trailing commas, workspaces, aliases, package tuple metadata, dependency groups, and duplicate package versions. No Bun installation or subprocess is required.

| Detector | Position | Technique | Command |
| --- | --- | --- | --- |
| `bun-detector` | Primary | Lockfile parser | None |
| `syft-detector` | Fallback for `bun.lockb` | Multiple | Embedded or external Syft |

### Offline behavior

✅ Native `bun.lock` parsing is fully offline-safe. Download URLs in the lockfile are recorded as package provenance and are never fetched.

⚠️ Legacy binary `bun.lockb` files use the Syft fallback. This preserves package inventory but may not retain the workspace, scope, and dependency-edge fidelity of the native text parser.

### Requirements and migration

- Commit `bun.lock` for deterministic native scans.
- `bun.lockb` repositories can migrate without installing dependencies: `bun install --save-text-lockfile --frozen-lockfile --lockfile-only`.
- Bomly never installs or invokes Bun during detection.

### Workspace behavior

Each entry in the lockfile's `workspaces` object becomes its own manifest-scoped graph. Workspace links point to application nodes and published packages remain distinct even when they share a display name with a workspace.

### Limitations

- The unstable binary `bun.lockb` format is intentionally not decoded by core.
- Registry metadata enrichment requires `--enrich`; lockfile parsing itself performs no network calls.
