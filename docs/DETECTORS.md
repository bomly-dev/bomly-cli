# Detectors

Detectors turn a project, container image, or SBOM into a dependency graph. Every scan starts with a detector.

A detector knows one or more package managers. It looks for evidence on disk: a lockfile, a manifest, a workflow file, or an SBOM document. From that evidence it produces packages, versions, and the links between them. Bomly ships native detectors for the most common ecosystems. For everything else it falls back to Syft, a bundled tool that lists packages by recognizing files on disk.

## When detectors run

- `bomly scan` runs detectors to build the graph.
- `bomly explain` reuses the same detector planning before walking dependency paths.
- `bomly diff` runs detectors for each side of the comparison, unless you pass `--sbom` to diff two SBOM files directly.
- Plugin detectors take part in the same planning when they declare package-manager evidence.

## Detector chains

A **detector chain** is the ordered list Bomly tries for a package manager. The first entry is preferred. Later entries are fallbacks. Bomly uses a fallback when the preferred detector is not ready, does not apply, or cannot produce graph data.

For example, the `npm` chain is `npm` → `syft-detector`:

1. `npm` tries its internal strategies in order. It parses `package-lock.json` first and falls back to `npm ls`. Either way it resolves the full transitive graph.
2. `syft-detector` runs only if the npm detector cannot produce graph data, for example when there is no lockfile and no npm command. It emits a flat package list.

Per-detector chains are listed in the [detector reference](detectors/). The CLI prints the live list:

```bash
bomly plugins list --detectors
bomly plugins list --detectors --json
```

## Native vs. Syft

| | Native detectors | Syft-backed |
| --- | --- | --- |
| Graph shape | Full transitive graph with edges | Flat package list |
| Source | Lockfile or build-tool output | Files Syft recognizes |
| Best for | Local source trees, monorepos, CI | Container images, ecosystems without a native detector |
| Performance | Faster on supported ecosystems | Required for many container layers |

Bomly prefers native detectors because they keep the edges. `bomly explain`, reachability, and scope filtering all need those edges. When no native detector applies, Bomly falls back to Syft without any extra flag.

## Selecting detectors

Use `--detectors` to restrict or extend the default set with the standard [selector grammar](COMMANDS.md#selector-grammar). Pass the bare name to use only that detector, `+name` to add one to the defaults, or `-name` to remove one:

```bash
# Use only the native Go detector
bomly scan --detectors go-detector

# Disable Syft fallback for this run
bomly scan --detectors -syft-detector

# Add an external plugin detector
bomly scan --detectors +bomly.examples.detector.bun-lock
```

## Remediation hints

After vulnerability enrichment, a detector may describe how its package manager can fix a dependency it found. Each detector declares that capability for itself and owns the advice for its package manager. Bomly's remediation component checks those read-only hints and chooses the final suggestion. Detectors never choose a fix version and never change manifests or lockfiles.

Each package-manager page lists the strategies its built-in detectors understand. External detector plugins can advertise the same optional capability. Older protocol-v1 plugins keep working without it.

## Resolution warnings

A detector can resolve a good graph from a project whose package-manager setup will still break an install somewhere else. Examples are a lockfile format the pinned package manager will not keep, or an install policy that rejects freshly published versions. Detectors record those as resolution warnings on the manifest they resolved. The graph is still produced and the problem is still reported. See [CI-readiness warnings](CI_READINESS.md) for the checks and where the warnings appear.

## Network behavior

Matchers only call out when you pass `--enrich`, but a detector that runs a build tool may download dependencies while it resolves the graph. [Network and privacy](NETWORK.md) is the full rule. The table below says which detectors can download during a plain scan.

| Detector class | Examples | Network during a plain scan |
| --- | --- | --- |
| Lockfile parser | `npm`, `pnpm`, `yarn` (lockfile strategy), `bundler-detector`, `composer-detector`, `nuget-detector`, `github-actions-detector`, SBOM ingest | None. The detector only reads files. |
| Lockfile-first hybrid | `cargo-detector`, `poetry-detector`, `uv-detector` | None when the lockfile is present. The build-tool fallback passes `--locked` or `--no-sync` to stay offline. |
| `pip inspect` | `pip-detector`, `pipenv-detector` | None when a lockfile is present. Otherwise the detector **may download** packages while it fills the isolated environment it inspects. |
| Build-tool primary | `go-detector`, `maven-detector`, `gradle-detector`, `sbt-native-detector` | **May download** artifacts that are not in the local cache. |

The build-tool detectors run commands you would already run locally: `go list`, `mvn dependency:tree`, `gradle dependencies`, and `sbt dependencyTree`. Whether those commands use the network depends on the tool and on your local cache, not on Bomly. To keep these scans offline, warm the local cache first (for example with `go mod download` or `mvn dependency:go-offline`) or commit a lockfile when the ecosystem supports one.

Each page under [`detectors/`](detectors/) documents the exact command that detector runs and whether it uses the network.

## `--install-first` {#install-first}

Pass `--install-first` to let supporting detectors run their normal install or cache-warming command **before** resolving the graph. The command depends on the package manager:

| Package manager | Install-first command |
| --- | --- |
| `gomod` | `go mod download` |
| `npm` | `npm i` (the short form of `npm install`) |
| `pnpm` | `pnpm i` (the short form of `pnpm install`) |
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

⚠️ **`--install-first` downloads packages from each ecosystem's registry** and writes to the filesystem. Depending on the package manager, that means `node_modules/`, the active virtual environment, `vendor/`, or `~/.m2/repository/`. It is opt-in for that reason. Use it when:

- You scan in CI on a clean checkout where dependencies have not been installed.
- The lockfile is missing or stale and you want a fresh graph.
- A build-tool detector (Go, Maven, Gradle) would otherwise fetch artifacts during resolution. `--install-first` is the cleaner place to pay that cost.

Detectors with no install step (for example NuGet, GitHub Actions, SBOM ingest, and Syft) skip the step silently when `--install-first` is set. Bomly does **not** install package managers themselves, only their dependencies.

Each page under [`detectors/`](detectors/) says whether `--install-first` is supported and which command runs.

### Customizing the install command with `--install-arg`

The default install command suits most projects. Real builds often need extra flags: skip dev dependencies, use a legacy resolver, point at a private index, or run a clean install. Pass `--install-arg` once per argument to append arguments to the detector's install command.

⚠️ **`--install-arg` requires exactly one selected detector.** Bomly cannot safely apply one flag to a chain of mixed package managers. It rejects the run with exit code 4 when zero or more than one detector is in scope. Combine it with `--detectors <name>` to select a single detector.

Arguments are **appended** to the default command, never replacing it. For example, the `npm` detector runs `npm i` by default. With `--install-arg --legacy-peer-deps --install-arg --no-audit` it runs `npm i --legacy-peer-deps --no-audit`.

The recipes below cover the most common adjustments:

```bash
# npm: tolerate peer-dependency conflicts on a legacy project
bomly scan --install-first --detectors npm \
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

Bomly applies `--install-arg` whenever it runs a detector install step. Most detectors only install when `--install-first` is set. `pip-detector` may also install into its isolated temporary virtual environment when no readable `requirements.lock` is present.

## Discovery and monorepos

For local source trees, Bomly discovers subprojects before running detectors. Every package manager with recognized evidence in the target directory becomes a subproject. Workspace-aware package managers (npm, pnpm, Yarn, Maven, Gradle, Cargo) expand their own nested modules from the root manifest. Bomly runs the matching detector chain in each subproject and merges the results into a single graph.

To also discover independent projects in nested directories, pass `--recursive`. See [Monorepos](MONOREPOS.md) for depth and exclusion options.

## SBOM ingest

Bomly treats SPDX 2.3 and CycloneDX SBOMs as first-class input. Use `--sbom` to ingest an SBOM file directly without running ecosystem detectors:

```bash
bomly scan --sbom --path ./existing.spdx.json
```

This is fast and offline. See [SBOM formats](SBOM.md) for the format comparison.

## Container images

Bomly pulls container images with the host's registry credentials. Native detectors that read lockfile contents inside layers still run. Everything else falls through to Syft:

```bash
bomly scan --image ghcr.io/example/app:latest
```

## See also

- [Detector reference](detectors/): one generated page per native detector, plus [Syft fallback](detectors/syft.md) for everything else
- [Support matrix](SUPPORT_MATRIX.md): generated overview of every supported ecosystem
- [CI-readiness warnings](CI_READINESS.md): the package-manager mismatches detectors report alongside the graph
- [Plugins](PLUGINS.md): author and install external detectors
