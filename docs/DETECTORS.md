# Detectors

Detectors turn a project, container, or SBOM into a dependency graph. Every scan starts with a detector.

A detector knows one or more package managers. Given evidence on disk — a lockfile, a manifest, a workflow file, an SBOM document — it produces packages, versions, and the edges between them. Bomly ships native detectors for the most common ecosystems and falls back to Syft for broad coverage of everything else.

## When detectors run

- `bomly scan` runs detectors to build the graph.
- `bomly explain` reuses the same detector planning before walking dependency paths.
- `bomly diff` runs detectors for each side of the comparison, unless you pass `--sbom` to diff two SBOM files directly.
- Plugin detectors participate in the same planning flow when they declare package-manager evidence.

## Detector Chains

A **detector chain** is the ordered list Bomly tries for a package manager. The first entry is preferred. Later entries are fallbacks Bomly uses when the preferred detector is not ready, is not applicable, or cannot produce graph data.

For example, the `npm` chain is `npm-detector` → `syft-detector`:

1. `npm-detector` parses `package-lock.json` directly and resolves the full transitive graph.
2. `syft-detector` runs only if the native detector cannot produce graph data (for example, no lockfile present), and emits a flat package list.

Per-ecosystem chains are listed in [`detectors/ecosystems/`](detectors/ecosystems/). The full live list lives in the CLI:

```bash
bomly plugins list --detectors
bomly plugins list --detectors --json
```

## Native vs. Syft

| | Native detectors | Syft-backed |
| --- | --- | --- |
| Graph shape | Full transitive graph with edges | Flat package list |
| Source | Lockfile or build-tool output | Cataloger heuristics |
| Best for | Local source trees, monorepos, CI | Container images, ecosystems without a native detector |
| Performance | Faster on supported ecosystems | Required for many container layers |

Bomly prefers native detectors because they preserve edges (needed by `bomly explain`, reachability, and scope filtering). It falls back to Syft transparently when no native detector applies.

## Selecting detectors

Use `--detectors` to restrict or extend the default set with the standard `+/-` selector grammar:

```bash
# Use only the native Go detector
bomly scan --detectors go-detector

# Disable Syft fallback for this run
bomly scan --detectors -syft-detector

# Add an external plugin detector
bomly scan --detectors +bomly.examples.detector.bun-lock
```

Pass the bare detector name to filter to only that detector, `+name` to add it on top of defaults, or `-name` to remove it.

## Network behavior

Detectors differ in whether they run subprocesses, and those that do may invoke build tools that download packages from registries. The marketing claim "Bomly is offline-safe by default" is precise: **matchers** make zero outbound calls without `--enrich`. **Detectors** may invoke build tools that download packages on your behalf during normal graph resolution.

| Detector class | Examples | Network during normal scan |
| --- | --- | --- |
| Lockfile parser | `npm-detector`, `pnpm-detector`, `bundler-detector`, `composer-detector`, `nuget-detector`, `github-actions-detector`, SBOM ingest | None — pure file parse |
| Lockfile-first hybrid | `cargo-detector`, `poetry-detector`, `uv-detector` | None when the lockfile is present; the build-tool fallback uses `--locked` / `--no-sync` to stay offline |
| `pip inspect` | `pip-detector`, `pipenv-detector` | None — reads the local Python environment |
| Build-tool primary | `go-detector`, `maven-detector`, `gradle-detector`, `sbt-native-detector` | **May download** uncached artifacts during normal resolution |

The build-tool-primary detectors invoke commands you would already run locally (`go list`, `mvn dependency:tree`, `gradle dependencies`, `sbt dependencyTree`). Whether they hit the network is a property of those tools and your local cache state, not a Bomly choice. To keep these scans fully offline, pre-warm the local cache (`go mod download`, `mvn dependency:go-offline`, etc.) or commit a lockfile when the ecosystem supports one.

Per-PM pages under [`detectors/ecosystems/`](detectors/ecosystems/) document the exact command each detector runs and whether it touches the network.

## `--install-first` {#install-first}

Pass `--install-first` to let supporting detectors run their normal dependency-install (or cache-warming) command **before** resolving the graph. The exact command depends on the package manager:

| Package manager | Install-first command |
| --- | --- |
| `gomod` | `go mod download` |
| `npm` | `npm install` |
| `pnpm` | `pnpm install` |
| `yarn` | `yarn install` |
| `pip` | `python -m pip install -r <requirements>` (plus `requirements-dev.txt` if present) |
| `pipenv` | `pipenv install` |
| `poetry` | `poetry install --no-root` |
| `uv` | `uv sync` |
| `bundler` | `bundle install` |
| `composer` | `composer install` |
| `maven` | `mvn dependency:resolve` (uses `./mvnw` if present) |
| `gradle` | `gradle dependencies --console=plain` (uses `./gradlew` if present) |
| `cargo` | `cargo fetch --locked` |

⚠️ **`--install-first` downloads packages from each ecosystem's registry** and modifies the filesystem (writes to `node_modules/`, the active virtualenv, `vendor/`, `~/.m2/repository/`, etc.). It is opt-in for that reason. Use it when:

- You're scanning in CI on a clean checkout where dependencies have not been installed locally.
- The lockfile is missing or stale and you want a fresh graph.
- A build-tool primary detector (Go, Maven, Gradle) would otherwise fetch artifacts during the resolution step itself — `--install-first` is the cleaner place to bear that cost.

Detectors without an `Install` implementation (e.g. NuGet, GitHub Actions, SBOM ingest, Syft) silently skip the step when `--install-first` is set. Bomly does **not** install package managers themselves — only their dependencies.

Each package-manager page under [`detectors/ecosystems/`](detectors/ecosystems/) lists whether `--install-first` is supported and the exact command that runs.

### Customizing the install command with `--install-arg`

The default install-first command for each detector is fine for most projects, but real builds often need extra flags (skip dev dependencies, use a legacy resolver, point at a private index, run a clean install). Pass `--install-arg` — repeatable — to append arguments to whatever the detector's `Install()` method runs.

⚠️ **`--install-arg` requires exactly one selected detector.** Bomly cannot safely apply an arbitrary flag to a chain of mixed package managers, so it rejects the run with exit 4 if zero or more than one detector is in scope. Combine with `--detectors <name>` to scope to a single detector.

Args are **appended** to the default command, not replacing it. For example, the `npm` detector defaults to `npm install`; with `--install-arg --legacy-peer-deps --install-arg --no-audit` it runs `npm install --legacy-peer-deps --no-audit`.

Recipes:

```bash
# npm: tolerate peer-dependency conflicts on a legacy project
bomly scan --install-first --detectors npm-detector \
  --install-arg --legacy-peer-deps

# pip: install from a private index in CI
bomly scan --install-first --detectors pip-detector \
  --install-arg --index-url --install-arg https://pypi.example.com/simple

# composer: skip dev dependencies for a production-shaped graph
bomly scan --install-first --detectors composer-detector \
  --install-arg --no-dev

# bundle: deployment mode (frozen lockfile, no version updates)
bomly scan --install-first --detectors bundler-detector \
  --install-arg --deployment

# go: verbose download output for CI debugging
bomly scan --install-first --detectors go-detector \
  --install-arg -x

# mvn: pass a specific Maven profile for the dependency:resolve step
bomly scan --install-first --detectors maven-detector \
  --install-arg -Pproduction

# uv: install only the locked dependencies, no editable updates
bomly scan --install-first --detectors uv-detector \
  --install-arg --frozen
```

`--install-arg` is consumed whenever Bomly runs a detector install step. Most detectors only install when `--install-first` is set; `pip-detector` may also install automatically into its isolated temp virtualenv when no readable `requirements.lock` is present.

## Discovery and monorepos

For local source trees, Bomly discovers subprojects before running detectors. Every directory containing recognized evidence becomes a subproject; Bomly runs the matching detector chain in each one and consolidates the results into a single graph.

There is no project-root requirement. Pointing `bomly scan` at a monorepo will scan every workspace in one pass.

## SBOM ingest

Bomly treats SPDX 2.3 and CycloneDX SBOMs as first-class input. Use `--sbom` to ingest an SBOM file directly without re-running ecosystem detectors:

```bash
bomly scan --sbom --path ./existing.spdx.json
```

This is fast and offline. See [SBOM formats](SBOM.md) for the format comparison.

## Container images

Bomly resolves container references via the host's registry credentials. Native detectors that work on lockfile contents inside layers still run; everything else falls through to Syft:

```bash
bomly scan --image ghcr.io/example/app:latest
```

## See also

- [Ecosystem guides](detectors/ecosystems/) — generated per-ecosystem detector chains, evidence patterns, and `PATH` requirements
- [Support matrix](SUPPORT_MATRIX.md) — generated overview of every supported ecosystem
- [Plugins](PLUGINS.md) — author and install external detectors
