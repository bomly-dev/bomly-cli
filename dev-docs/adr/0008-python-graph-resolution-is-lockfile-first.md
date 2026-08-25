# ADR-0008: Python graph resolution is lockfile-first, validated, and provenance-backed

- **Date:** 2026-07-07
- **Status:** Accepted

Python build-tool inspection can accidentally read the wrong environment: `pip inspect --local` reports every package in the interpreter it is pointed at, even if that interpreter belongs to unrelated tooling. Bomly therefore treats Python graph resolution as accurate-or-fail:

1. **Deterministic lock parsers first.** `requirements.lock`, `poetry.lock`, and `uv.lock` are parsed directly when possible. `Pipfile.lock` remains the Pipenv fallback because it is flat but project-owned.
2. **Project-owned environments only.** When a detector inspects an environment, it must be a project-managed environment prepared by the package manager or Bomly itself, not an arbitrary ambient interpreter.
3. **Isolated pip installs.** Plain pip projects without `requirements.lock` are installed into a clean, project-scoped virtualenv under the temp dir — keyed by a hash of the absolute working dir — and then inspected from that venv. Ambient site-packages are never accepted as the project graph.
4. **Resolution provenance.** Manifest metadata carries the resolution method, sanitized install command, and install working directory into scan JSON so users can see exactly how a graph was produced.

The smoke/benchmark Python targets rely on the fast-paths for determinism: `scan-python-poetry` uses the committed `poetry.lock` fast-path, and `scan-python-pip` commits a `requirements.lock`. The venv isolation remains the correctness backstop for real-world pip projects scanned without a committed lock.

Two consequences of inspecting an environment rather than reading a manifest:

- **Shape is reconstructed, not reported.** `pip inspect` returns a flat installed set. Edges come from each distribution's `requires_dist`; the direct set comes from what the project declares by name, plus the installer's `REQUESTED` marker for what those declarations cannot name (`-r` includes, environments populated by another front-end). Anything the root cannot reach is re-parented onto it, so a `requires_dist` cycle cannot strand a component. Treating every installed distribution as direct — the pre-fix behavior — reported pure transitives as top-level dependencies.
- **Declarations are hand-authored files only.** `directPythonDeclarations` reads requirements files, the dependency tables of `pyproject.toml`, and the `Pipfile`. Lockfiles — including `requirements.lock` — are excluded on purpose: they record the resolved closure, where a transitive package appears exactly like a direct one. Since the inspect path is shared by pip, Poetry, uv, and Pipenv, admitting `poetry.lock` or `uv.lock` here would recreate the all-direct bug for those detectors. This is a deliberately narrower question than `declaredPythonDependencies`, which asks only whether a package belongs to the project at all (used to keep declared tool packages).
- **`pip inspect` needs pip ≥ 22.2.** `python -m venv` seeds the virtualenv from the ambient interpreter, so an old system Python yields a venv that cannot inspect itself. Bomly diagnoses this before the install and fails with the pip version and the requirement named, which surfaces through the fallback notice instead of a bare `exit status 1`. It does not upgrade pip: installing package managers is out of scope (see Non-Negotiables), and mutating the environment before resolution would add an unpinned network write to every scan.

Python roots are named, not labeled `root`: `pyproject.toml`'s project name, else the subproject directory, else the scanned repository, else the project directory. Bomly's own `bomly-git-*` clone directories are never used — they are random per run, which would make remote-target output non-deterministic.
