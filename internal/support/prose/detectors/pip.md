## How `pip` resolves

`pip-detector` does **not** parse `requirements.txt` directly. Instead it asks the active Python environment what is currently installed:

| Step | Command | Working dir |
| --- | --- | --- |
| Resolve graph | `python -m pip inspect` | the project root |

`pip inspect` returns a JSON document describing every package installed in the Python environment Bomly invokes, along with its declared dependencies. Bomly builds the graph from that.

## Network behavior

✅ The default `pip-detector` is **fully offline-safe**. `pip inspect` reads from the local Python environment and makes no network calls.

⚠️ **It only sees what is installed.** If you have not run `pip install -r requirements.txt` (or equivalent) in the current environment, the inspection returns an empty graph and the scan will produce no packages for the project.

## Prerequisites

- `python` on `PATH` with `pip` installed (`python -m pip --version` must work).
- The project's dependencies must already be installed in the active Python environment. The detector inspects whatever virtualenv / system Python is reachable.
- A `requirements.txt`, `requirements-dev.txt`, `requirements.in`, `requirements.lock`, or any `*requirements*.txt` file in the scan path acts as the evidence pattern that triggers `pip-detector`.

## `--install-first`

`pip` does **not** support `--install-first` today. Pre-install dependencies in the active Python environment before scanning (`pip install -r requirements.txt`), or scan a virtualenv where they are already installed.

## Examples

### Fix a direct vulnerability

Pin in `requirements.txt`:

```text
requests==2.32.4
```

`pip install -r requirements.txt` then re-scan.

### Pin a transitive vulnerability

With pip-tools, add a constraint:

```text
# constraints.txt
urllib3>=2.2.2
```

```bash
pip-compile --constraint constraints.txt requirements.in
pip install -r requirements.txt
```

Re-scan.

## Reachability (experimental)

> **Experimental.** Reachability is opt-in via `--reachability`. The feature is stable in shape but may evolve; ecosystem coverage is expanding.

For pip-managed packages, the analyzer is `pyreach` at **Tier-3 (package)**. It walks every `.py` file under the project root, records imports, and maps module names to PyPI distribution names. See [REACHABILITY.md](../../REACHABILITY.md#unreachable-is-not-safe) and the module-to-distribution map in `internal/analyzers/pyreach/moduletodist.go`.

## Limitations

- **No environment, no graph.** Unlike a lockfile parser, `pip-detector` needs the dependencies to already be installed. Use `--install-first` to install in CI, or pre-install in your virtualenv before scanning.
- **Multiple Python environments** require pointing Bomly at the right `python`. The detector uses the first `python` on `PATH`; activate the virtualenv before running Bomly, or pass `PYTHON_BIN` if you set up that env var in your environment.
- **Editable installs** (`pip install -e ./local-pkg`) are reflected in the inspection; their internal dependencies come from the local package's metadata.
