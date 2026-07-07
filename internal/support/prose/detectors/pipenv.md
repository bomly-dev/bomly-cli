## How `pipenv` resolves

`pipenv-detector` is **project-env first with a lockfile fallback**. It prefers an inspected Pipenv virtualenv because that includes transitive edges from package metadata, but it validates the environment against the selected `Pipfile` / `Pipfile.lock` before returning it.

| Path | Strategy | Command |
| --- | --- | --- |
| Existing Pipenv venv | Project environment | `pipenv run python -m pip inspect --local` |
| No valid venv and `Pipfile.lock` present | Locked sync + inspect | `pipenv sync` (plus `--dev` unless `--scope runtime`), then `pipenv run python -m pip inspect --local` |
| Sync unavailable or invalid | Manifest-only fallback | Parse `Pipfile.lock` (no exec) |

The inspected graph is accepted only when declared packages are present in the virtualenv. If the environment is stale or belongs to another project, Bomly rejects it and tries the locked sync path before falling back to `Pipfile.lock`.

## Network behavior

✅ The `Pipfile.lock` parser is offline and does not execute Pipenv.

⚠️ The sync path can download packages from PyPI or configured indexes, but it installs into Pipenv's managed virtualenv and should not update the lockfile.

## Prerequisites

- One of:
  - A valid Pipenv-managed virtualenv, **or**
  - A committed `Pipfile.lock`.
- For `--install-first`: `pipenv` on `PATH`.

## `--install-first`

`pipenv` supports `--install-first`. With a lockfile, Bomly runs `pipenv sync` before resolving the graph, adding `--dev` unless `--scope runtime` is selected. Without a lockfile, Bomly falls back to `pipenv install`.

⚠️ **`--install-first` can download packages from PyPI** and creates / updates the Pipenv-managed virtualenv.

```bash
bomly scan --install-first
```

### Customizing the install command

Append flags to the Pipenv install/sync command with repeatable `--install-arg`. Requires `--detectors pipenv-detector`. Bomly records the sanitized command in scan JSON under the manifest's resolution metadata.

```bash
# Include dev dependencies; fail fast on a lockfile drift
bomly scan --install-first --detectors pipenv-detector \
  --install-arg --dev --install-arg --deploy
```

## Reachability (experimental)

> **Experimental.** Reachability is opt-in via `--analyze`. The feature is stable in shape but may evolve; ecosystem coverage is expanding.

For Pipenv-managed packages, the analyzer is `pyreach` at **Tier-3 (package)**. See [REACHABILITY.md](../../../REACHABILITY.md#unreachable-is-not-safe).

## Limitations

- **Pipenv 2024+** lock format is preferred; older formats parse but with reduced detail.
- **`[dev-packages]`** is recorded with `development` scope.
- **Lockfile fallback is flatter.** `Pipfile.lock` does not encode parent-child edges, so the fallback graph is less precise than a validated virtualenv inspection.
