## How `pipenv` resolves

`pipenv-detector` is **project environment first, with a lockfile fallback**. It prefers an inspected Pipenv virtual environment because that includes transitive edges from package metadata. It checks that environment against the project's `Pipfile` and `Pipfile.lock` before using it.

| Path | Strategy | Command |
| --- | --- | --- |
| Existing Pipenv environment | Project environment | `pipenv run python -m pip inspect --local` |
| No valid environment and `Pipfile.lock` present | Locked sync and inspect | `pipenv sync` (plus `--dev` unless `--scope runtime`), then `pipenv run python -m pip inspect --local` |
| Sync unavailable or invalid | Manifest-only fallback | Parse `Pipfile.lock` (no command) |

Bomly accepts the inspected graph only when the declared packages are present in the environment. If the environment is stale or belongs to another project, Bomly rejects it and tries the sync path before falling back to `Pipfile.lock`.

The `Pipfile.lock` parser runs nothing and never uses the network. The sync path **may download** packages from PyPI or configured indexes. It installs into Pipenv's managed environment and does not update the lockfile. See [Network and privacy](../../NETWORK.md) for the shared rule.

## Prerequisites

- A valid Pipenv-managed virtual environment, or a committed `Pipfile.lock`.
- For `--install-first`: `pipenv` on `PATH`.
- Inspecting a Pipenv environment needs **pip 22.2 or newer** inside it, because `pip inspect` does not exist before that. Older environments fall back to parsing `Pipfile.lock`.

## Examples

Scan a project with a committed lockfile and gate on high findings:

```bash
bomly scan --enrich --audit --fail-on high
```

## `--install-first`

With a lockfile, `--install-first` runs `pipenv sync` before resolving the graph, adding `--dev` unless you pass `--scope runtime`. Without a lockfile, Bomly runs `pipenv install` instead. Either command can download packages from PyPI and creates or updates the Pipenv-managed environment.

```bash
bomly scan --install-first
```

To append flags to that command, repeat `--install-arg`. This requires `--detectors pipenv-detector`. Bomly records the command, with secrets removed, in the scan JSON under the manifest's resolution metadata.

```bash
# Include dev dependencies; fail fast on lockfile drift
bomly scan --install-first --detectors pipenv-detector \
  --install-arg --dev --install-arg --deploy
```

## Source details

Bomly reads registry, Git, URL, and local-file sources from `Pipfile.lock`. When it inspects an environment instead, it uses pip's `direct_url` record.

## Reachability (experimental)

With `--analyze`, the `pyreach` analyzer reports a package as reachable when app source imports it. Unreachable is a triage signal, not proof of safety; see [Reachability](../../REACHABILITY.md#unreachable-is-not-safe).

## Limitations

- **The Pipenv 2024 lock format is preferred.** Older formats parse with less detail.
- **`[dev-packages]`** entries get the `development` scope.
- **The lockfile fallback is flatter.** `Pipfile.lock` does not record parent-child edges, so that graph is less precise than an inspected environment.
