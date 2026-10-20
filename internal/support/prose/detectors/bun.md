## How `bun` resolves

`bun-detector` parses the text lockfile `bun.lock` directly. It supports lockfile versions 0 and 1, including JSON comments and trailing commas, workspaces, aliases, package metadata, dependency groups, and duplicate package versions. No Bun installation or subprocess is needed for this path.

| Detector | Position | Strategy | Command |
| --- | --- | --- | --- |
| `bun-detector` | Primary | Lockfile parser | None |
| `bun-native-detector` | Fallback for installed or legacy projects | Build tool | `bun pm ls --all` |
| `syft-detector` | Final fallback | File recognition | None (Syft is built in) |

The lockfile parser never uses the network. Download URLs in the lockfile are recorded as package origin and never fetched. The Bun CLI fallback reads the installed package tree without fetching packages. See [Network and privacy](../../NETWORK.md) for the shared rule.

When no text lockfile exists, the Bun CLI fallback keeps nested edges, resolves workspace identities, and recovers direct dependencies from `package.json`. A hoisted package whose parent cannot be proven keeps an `unknown` relationship. If Bun is missing or the project is not installed, the Syft fallback reads the binary `bun.lockb` with less graph detail.

## Prerequisites

- Commit `bun.lock` for deterministic native scans.
- A repository with only `bun.lockb` can migrate without installing dependencies: `bun install --save-text-lockfile --frozen-lockfile --lockfile-only`.

## Workspaces

Each entry in the lockfile's `workspaces` object becomes its own manifest-scoped graph. Workspace links point to application nodes. A published package stays distinct even when it shares a display name with a workspace.

## `--install-first`

With `--install-first`, Bomly runs `bun install` before resolving the graph. Normal detection never installs dependencies.

## Limitations

- **The binary `bun.lockb` format is not decoded** by the native detector. Its format is unstable, so only Syft reads it.
- **`bun pm ls --all` shows a hoisted installed tree.** The CLI fallback keeps the child edges it shows but does not invent parents for top-level transitive packages. Those parents stay `unknown` and still take part in matching, audit, policy, and output.
