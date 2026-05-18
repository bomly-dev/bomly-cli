## Scan your Python project

Bomly has native detectors for pip, Pipenv, Poetry, and uv. PDM lockfiles and bare `setup.py` projects fall through to Syft. Native detectors produce a full transitive graph with PyPI distribution names (already normalized per PEP 503).

```bash
bomly scan --path .
```

The detector that runs is chosen by the manifest present:

| Manifest | Detector |
| --- | --- |
| `Pipfile` + `Pipfile.lock` | `pipenv-detector` |
| `pyproject.toml` + `poetry.lock` | `poetry-detector` |
| `pyproject.toml` + `uv.lock` | `uv-detector` |
| `requirements*.txt` (compiled by `pip-compile` or `uv pip compile`) | `pip-detector` |
| `pyproject.toml` + `pdm.lock` | `syft-detector` (Syft fallback) |
| `setup.py` only | `syft-detector` (Syft fallback) |

For full graph fidelity (edges, scopes, exact versions), commit a lock file produced by the tool you use.

## Prerequisites

- A committed lock file for one of the supported tools. `requirements.txt` files must include exact pins (`==`); unpinned requirements are accepted but produce a less precise graph.
- No Python toolchain on `PATH` is required to scan. Bomly parses lock files directly.
- For reachability: every `.py` file under the project root is scanned. Generated sources (e.g. from `protoc`, gRPC stubs, ORM migrations) must be on disk for the analyzer to see them.
- For Poetry projects with a custom source index, configure `~/.config/pypoetry/auth.toml` if private packages are involved. Bomly does not authenticate to PyPI mirrors itself.

## Reachability — what `pyreach` tells you

The Python analyzer is **Tier-3 (package)**. It walks every `.py` file under the project root, records `import x` and `from x import …` statements, maps module names to PyPI distribution names through a static override map plus PEP 503 normalization, and expands the result transitively through the dep graph.

Module-to-distribution mismatches Python forces on every static analyzer (`yaml → PyYAML`, `cv2 → opencv-python`, `sklearn → scikit-learn`, `bs4 → beautifulsoup4`, `PIL → Pillow`, `jwt → PyJWT`, …) are handled by a curated table in `internal/analyzers/pyreach/moduletodist.go`. Missing entries produce false-negatives for direct imports; add the mapping in a one-line PR.

Importantly, "unreachable" is not "safe" — `importlib.import_module(name)` on user input, Django `INSTALLED_APPS` strings, entry-point plugin discovery, and `__import__` are invisible. See [REACHABILITY.md](../../REACHABILITY.md#unreachable-is-not-safe).

```bash
bomly scan --enrich --audit --reachability --fail-on high --fail-on reachable
```

## Examples

### Fix a direct vulnerability

Bump in `pyproject.toml` (Poetry):

```toml
[tool.poetry.dependencies]
requests = "^2.32.0"
```

Re-lock: `poetry lock --no-update --regenerate`. Re-scan.

For pip-tools: edit `requirements.in`, then `pip-compile --upgrade-package requests`. For uv: `uv lock --upgrade-package requests`.

### Pin a transitive vulnerability

pip-tools and uv let you constrain a transitive dep without touching the parent's declaration:

```text
# constraints.txt
urllib3>=2.2.2
```

```bash
pip-compile --constraint constraints.txt requirements.in
```

For Poetry, add the transitive dep at the top level so the resolver respects your version:

```toml
[tool.poetry.dependencies]
urllib3 = ">=2.2.2"
```

### Multi-package monorepo

Bomly scans every directory containing a Python lock file as a subproject and consolidates. If your monorepo uses a single shared lockfile at the root and many `pyproject.toml` files under `packages/*`, the lockfile-bearing root is treated as one subproject and the per-package `pyproject.toml` files are parsed as additional manifests.

## Limitations

- **Editable installs** (`pip install -e ./local-pkg`) are reflected in the lockfile but their internal dependencies are read from the local package, not PyPI.
- **`setup.py`-only projects** fall through to Syft for a flat package list. Generate a `requirements.txt` with `pip freeze` for full coverage.
- **Submodule imports collapse to the distribution.** `from urllib3.util import retry` flags the whole `urllib3` distribution as reachable. Symbol-tier resolution for Python is a future phase.
- **Stdlib modules** (`os`, `sys`, `json`, `pathlib`, …) are dropped from the import set.
- **Optional extras** (`requests[socks]`) are recorded as a single distribution; extras-specific transitive deps appear in the dep graph normally if the lockfile includes them.
- **PDM lockfiles** are currently Syft-only. A native PDM detector is tracked for a future phase.
