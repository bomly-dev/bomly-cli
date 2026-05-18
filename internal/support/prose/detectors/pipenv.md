## How `pipenv` resolves

`pipenv-detector` is **hybrid**: it prefers `pipenv run pip inspect` when a Pipenv virtualenv exists and falls back to parsing `Pipfile.lock` directly when the venv is missing.

| Path | Strategy | Command |
| --- | --- | --- |
| Venv present | Build tool | `pipenv run python -m pip inspect` |
| No venv | Lockfile parser | Parse `Pipfile.lock` (no exec) |

## Network behavior

✅ Both paths are **offline-safe**. `pip inspect` reads from the local virtualenv; the lockfile parser reads a committed file.

## Prerequisites

- One of:
  - A Pipenv-managed virtualenv (run `pipenv install` once and Bomly can inspect it), **or**
  - A committed `Pipfile.lock`.
- For `--install-first`: `pipenv` on `PATH`.

## `--install-first`

`pipenv` does **not** support `--install-first` today. Run `pipenv install` yourself before scanning, or commit `Pipfile.lock` for the offline path.

## Reachability (experimental)

> **Experimental.** Reachability is opt-in via `--reachability`. The feature is stable in shape but may evolve; ecosystem coverage is expanding.

For Pipenv-managed packages, the analyzer is `pyreach` at **Tier-3 (package)**. See [REACHABILITY.md](../../REACHABILITY.md#unreachable-is-not-safe).

## Limitations

- **Pipenv 2024+** lock format is preferred; older formats parse but with reduced detail.
- **`[dev-packages]`** is recorded with `development` scope; gate on `--fail-on-scope runtime` for production-only policy.
