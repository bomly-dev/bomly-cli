## How `uv` resolves

`uv-detector` is **lockfile-first**. A readable `uv.lock` is the preferred source because it is deterministic and carries transitive dependency data. Bomly falls back to inspecting a uv environment only when a lockfile exists but cannot be parsed.

| Path | Strategy | Command |
| --- | --- | --- |
| `uv.lock` present | Lockfile parser | None |
| Lockfile unreadable | Frozen sync and inspect | `uv sync --frozen --no-install-project`, `uv pip install pip`, then `uv run --no-sync python -m pip inspect --local` |
| Lockfile missing | Fail | None |

The `--frozen` flag stops uv from updating the lockfile, and `--no-sync` stops the inspect command from changing the environment. Bomly accepts the inspected graph only when it contains the packages the uv project declares.

The lockfile parser runs nothing and never uses the network. The frozen sync fallback **may download** packages from PyPI or configured indexes. It does not update the lockfile or the project manifest. See [Network and privacy](../../NETWORK.md) for the shared rule.

## Prerequisites

- A committed `uv.lock`.
- A `pyproject.toml`, which is the evidence that triggers the detector.
- For `--install-first`: `uv` on `PATH`.

## Examples

### Fix a direct vulnerability

Raise the range in `pyproject.toml`:

```toml
[project]
dependencies = [
  "requests>=2.32.0",
]
```

Re-lock with `uv lock --upgrade-package requests` and re-scan.

### Pin a transitive vulnerability

Upgrade the one package in the lockfile:

```bash
uv lock --upgrade-package urllib3
```

Or add a constraint in `pyproject.toml`:

```toml
[tool.uv]
constraint-dependencies = ["urllib3>=2.2.2"]
```

Re-lock and re-scan.

## Workspaces

uv workspaces are scanned per workspace member. Each member is its own subproject.

## `--install-first`

With `--install-first`, Bomly runs `uv sync --frozen --no-install-project`, then `uv pip install pip`, before resolving the graph. That can download packages from PyPI and writes to the uv-managed environment without changing `uv.lock`.

```bash
bomly scan --install-first
```

To append flags to the sync command, repeat `--install-arg`. This requires `--detectors uv-detector`. Bomly records the command, with secrets removed, in the scan JSON under the manifest's resolution metadata.

```bash
# Refuse to update the lockfile; sync exactly what is locked
bomly scan --install-first --detectors uv-detector \
  --install-arg --frozen
```

## Source details

Bomly reads registry, Git, URL, path, and editable sources from each package's source table in `uv.lock`. An entry without source evidence stays unknown.

## Reachability (experimental)

With `--analyze`, the `pyreach` analyzer reports a package as reachable when app source imports it. Unreachable is a triage signal, not proof of safety; see [Reachability](../../REACHABILITY.md#unreachable-is-not-safe).

## Limitations

- **The uv lockfile format still evolves.** Track upstream changes if you pin Bomly versions in CI.
- **No lockfile, no graph.** Bomly refuses to inspect an unprepared uv environment when `uv.lock` is missing, because that can produce stale or unrelated dependencies.
