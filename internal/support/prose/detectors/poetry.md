## How `poetry` resolves

`poetry-detector` is **hybrid (lockfile-first)**: it parses `poetry.lock` directly and only falls back to `poetry run pip inspect` if the lockfile cannot be read.

| Path | Strategy | Command |
| --- | --- | --- |
| `poetry.lock` present | Lockfile parser | None |
| Lockfile missing or unreadable | Build tool | `poetry run python -m pip inspect` |

## Network behavior

✅ Both paths are **offline-safe**. The lockfile parser reads a committed file; `pip inspect` reads from the local Poetry virtualenv.

## Prerequisites

- One of:
  - A committed `poetry.lock` (strongly recommended), **or**
  - A Poetry-managed virtualenv (`poetry install` has been run).
- `pyproject.toml` for evidence pattern matching.
- For `--install-first`: `poetry` on `PATH`.

## `--install-first`

`poetry` supports `--install-first`. When passed, Bomly runs `poetry install --no-root` before resolving the graph.

⚠️ **`--install-first` downloads packages from PyPI** and writes to the Poetry-managed virtualenv. Use it on a clean checkout.

```bash
bomly scan --install-first
```

### Customizing the install command

Append flags to `poetry install --no-root` with repeatable `--install-arg`. Requires `--detectors poetry-detector`.

```bash
# Production-only graph: skip dev dependencies and a specific group
bomly scan --install-first --detectors poetry-detector \
  --install-arg --without --install-arg dev \
  --install-arg --without --install-arg docs
```

## Examples

### Fix a direct vulnerability

```toml
[tool.poetry.dependencies]
requests = "^2.32.0"
```

`poetry lock --no-update --regenerate`. Re-scan.

### Pin a transitive vulnerability

Add the transitive dep at the top level so the resolver respects your version:

```toml
[tool.poetry.dependencies]
urllib3 = ">=2.2.2"
```

Re-lock and re-scan.

## Reachability (experimental)

> **Experimental.** Reachability is opt-in via `--analyze`. The feature is stable in shape but may evolve; ecosystem coverage is expanding.

For Poetry-managed packages, the analyzer is `pyreach` at **Tier-3 (package)**. See [REACHABILITY.md](../../REACHABILITY.md#unreachable-is-not-safe).

## Limitations

- **Poetry 1.x and 2.x** lockfile formats are both supported.
- **Optional extras** (`requests[socks]`) are recorded as a single distribution; extras-specific transitives appear in the lockfile and graph normally.
- **Private indexes** (Poetry `source` configuration) require `~/.config/pypoetry/auth.toml` set up locally.
