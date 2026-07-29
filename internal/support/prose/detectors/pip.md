## How `pip` resolves

`pip-detector` is **lockfile/isolated-env first**. It never accepts an unrelated ambient Python environment as the selected project's graph.

| Path | Strategy | Command |
| --- | --- | --- |
| `requirements.lock` present and readable | Lockfile parser | None |
| No lockfile | Isolated install + inspect | `python -m venv <tmp>/bomly-pyvenv-*`, then `<venv>/python -m pip install -r <requirements-file>`, then `<venv>/python -m pip inspect --local` |

The isolated virtualenv lives under the OS temp directory and is keyed by the project path. Bomly recreates it before installing so stale packages cannot leak into the scan, then inspects that venv directly. Ambient site-packages are never accepted as the project graph.

Direct vs. transitive comes from what your project declares by name — requirements files, the dependency tables in `pyproject.toml`, the `Pipfile` — plus the installer's `REQUESTED` marker. Lockfiles never count as declarations: they record the whole resolved closure, so reading them here would make every transitive package look direct. Everything else in the environment is wired under its parents using each distribution's `Requires-Dist` metadata.

A `requirements.txt` project carries no name of its own, so the graph's root node is named from the first of: `pyproject.toml`'s declared project name, the subproject directory (in a recursive monorepo scan), the scanned repository name (for a `--url` target), or the project directory. Bomly's own `bomly-git-*` clone directories are never used — they are random per run.

## Network behavior

✅ `requirements.lock` parsing is offline and does not execute Python.

⚠️ Without `requirements.lock`, Bomly installs into its isolated temp virtualenv so the graph is accurate. That can download packages from PyPI or the indexes declared by your install args. The only commands Bomly runs there are `python -m venv`, `pip --version`, your requirements install, and `pip inspect` — it never installs or upgrades pip itself.

## Prerequisites

- `python` on `PATH` with `pip` installed (`python -m pip --version` must work).
- **pip 22.2 or newer**, which is the first release with `pip inspect`. `python -m venv` seeds the virtualenv with the ambient interpreter's pip, so an old system Python (macOS ships 3.9 with pip 21.x) produces a venv that cannot inspect itself. Bomly checks this before installing and fails with the pip version and this requirement named, rather than a bare exit status; the detector chain then falls back, so the scan still completes with a reduced graph. Bomly never installs or upgrades pip for you — fix it with `python -m pip install --upgrade pip` for that interpreter, or put a newer Python on `PATH`.
- A `requirements.txt`, `requirements-dev.txt`, `requirements.in`, `requirements.lock`, or any `*requirements*.txt` file in the scan path acts as the evidence pattern that triggers `pip-detector`.

## `--install-first`

`pip` supports `--install-first`, but the detector also performs the same isolated install automatically when no readable `requirements.lock` exists. When install-first is used, Bomly runs the install step before graph resolution; otherwise the detector runs it as part of resolution.

The install target is Bomly's temp virtualenv, not the worktree or the active system Python. Bomly installs the primary requirements file and additionally installs `requirements-dev.txt` when present unless `--scope runtime` is selected.

⚠️ The install can download packages from PyPI and any configured indexes, but it should not modify project files.

```bash
bomly scan --install-first
```

The requirements file Bomly installs is chosen automatically from common names. Prefer committing `requirements.lock` when you need fully offline scans.

### Customizing the install command

Append flags to `<venv>/python -m pip install -r <requirements>` with repeatable `--install-arg`. Requires `--detectors pip-detector`. Bomly records the sanitized install command in scan JSON under the manifest's resolution metadata.

```bash
# Install from a private index in CI
bomly scan --install-first --detectors pip-detector \
  --install-arg --index-url --install-arg https://pypi.example.com/simple

# Honor hash-checking mode declared in requirements.txt
bomly scan --install-first --detectors pip-detector \
  --install-arg --require-hashes
```

## Examples

### Fix a direct vulnerability

Pin in `requirements.txt`:

```text
requests==2.32.4
```

Re-scan. Bomly will install the pinned requirements into its isolated temp virtualenv when no lockfile is present.

### Pin a transitive vulnerability

With pip-tools, add a constraint:

```text
# constraints.txt
urllib3>=2.2.2
```

```bash
pip-compile --constraint constraints.txt requirements.in
```

Re-scan.

## Source details

Pinned packages in `requirements.lock` are registry packages. On the inspection
path, Bomly uses pip's `direct_url` record to identify Git, URL, and local-file
installs. Missing or malformed source data stays unknown.

## Reachability (experimental)

> **Experimental.** Reachability is opt-in via `--analyze`. The feature is stable in shape but may evolve; ecosystem coverage is expanding.

For pip-managed packages, the analyzer is `pyreach` at **Tier-3 (package)**. It walks every `.py` file under the project root, records imports, and maps module names to PyPI distribution names. See [REACHABILITY.md](../../../REACHABILITY.md#unreachable-is-not-safe) and the module-to-distribution map in `internal/analyzers/pyreach/moduletodist.go`.

## Limitations

- **Install failures are explicit.** If Bomly cannot create the isolated virtualenv, install the selected requirements file, or inspect the venv, the detector fails instead of falling back to ambient Python.
- **Multiple Python installations** only affect which interpreter creates the isolated virtualenv. The project graph comes from the temp venv, not from ambient site-packages.
- **Editable installs** (`pip install -e ./local-pkg`) are reflected in the inspection; their internal dependencies come from the local package's metadata.
