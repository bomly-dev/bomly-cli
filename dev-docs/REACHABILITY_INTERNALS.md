# Reachability internals

Contributor notes on how each built-in analyzer works. The user-facing page is
[`docs/REACHABILITY.md`](../docs/REACHABILITY.md); keep caveats that users need
there, and implementation detail here. The analyzers live in their own
repositories (`bomly-plugin-{govulncheck,jsreach,pyreach,jvmreach}-analyzer`)
and are consumed as pinned Go modules.

## Pipeline position

`--analyze` adds the `analyze` stage after `match` and before `audit`.
Analyzers dispatch on `(Language, Ecosystem, PackageManager)` and write a
`model.Reachability` onto the matching `model.Vulnerability` records inside
the PURL-keyed `model.PackageRegistry`. The output layer resolves them at
projection time through `(Finding.PackageRef, Finding.VulnerabilityID)`, so
reachability reaches JSON, SARIF, text, and the TUI without a separate field
on `Finding`.

Analyzer failures degrade to `Status: unknown` with a stable `Reason`; they
never abort the pipeline.

## `jsreach`

Backed by `github.com/evanw/esbuild/pkg/api`, run in-process. esbuild walks
the application source from the `package.json` entry points (`main`,
`module`, `browser`, `exports`, `bin`, plus implicit `index.*`, `app.js`,
`server.js`, `main.js` fallbacks) with `PackagesExternal` set, so it stops at
every bare specifier without opening `node_modules`. That yields the
directly-imported set. The analyzer then expands it transitively through the
npm detector's graph (`Graph.Dependencies`). The closure is keyed by graph
node ID, not package name, so a top-level `lodash@4` and a nested `lodash@3`
are attributed separately.

Workspace traversal is manifest-driven: npm and Yarn `workspaces` arrays,
Yarn-style `workspaces.packages` objects, and `pnpm-workspace.yaml` patterns.
Imports between workspace packages are followed by package name without
relying on installed symlinks.

## `pyreach`

An in-process, line-oriented import scanner. It walks every `.py` file under
the project root (located by `pyproject.toml`, `setup.py`,
`requirements*.txt`, `Pipfile`, `poetry.lock`, `pdm.lock`, or `uv.lock`),
records each top-level module from `import` and `from … import` statements,
and maps module names to PyPI distribution names in three layers:

1. A static override table for the well-known mismatches (`yaml → pyyaml`,
   `cv2 → opencv-python`, `sklearn → scikit-learn`, `bs4 → beautifulsoup4`,
   `PIL → pillow`, `jwt → pyjwt`, …).
2. PEP 503 normalization (lowercase, `_` and `.` to `-`) for everything else.
3. Standard-library modules are dropped from the import set.

The set is then expanded through the Python detector's graph. A missing
override entry produces a false negative for a direct import; the breadth-
first expansion usually recovers it through a transitive edge from a
correctly mapped neighbor. Adding an override is a one-line change in the
analyzer repository.

## `jvmreach`

An in-process, line-oriented import scanner for `.java`, `.kt`, `.kts`,
`.scala`, and `.groovy` files. It parses top-of-file `import` statements
(Java `static`, Kotlin aliases, Scala selectors and wildcards) and maps the
fully qualified name prefix to a Maven coordinate (`groupId:artifactId`)
through a curated longest-prefix map, then expands through the Maven, Gradle,
or SBT graph.

The Java mapping has no naming convention to fall back on: `org.apache.commons`
covers many artifacts and `com.google.common` is one. The prefix map is small
and biased toward popular libraries, so a missing prefix is a false negative
for direct imports with no normalization fallback.

Multi-module traversal follows Maven parent `<modules>` recursively and
Gradle `include(...)` declarations with `projectDir` overrides. Gradle
composite builds (`includeBuild`) and computed settings are not followed.

## `govulncheck`

Backed by `golang.org/x/vuln/scan`, run in-process, so users never need a
`govulncheck` binary. It requires a buildable module; build failures map to
the reason codes listed on the user page (`missing-toolchain`,
`no-go-packages`, `module-resolution-failed`, `invalid-go-mod`,
`build-failed`, `cancelled`, `runner-error`).

## Confidence and dynamic imports

Package-tier analyzers populate `hops` (graph distance from a directly
imported package), `confidence` (`high` for a direct import with no dynamic
imports, `medium` for one to three hops, `low` for four or more hops or when
dynamic imports were seen), and `dynamic_imports_detected`. When the scanner
sees `require(variable)`, `importlib.import_module(name)`, or
`Class.forName(string)`, reachable results are forced to `low` confidence.

## Build layout

Analyzers have no builtin/external build-tag split. All four ship one
in-process implementation; `govulncheck` and `jsreach` vendor a library and
`pyreach` and `jvmreach` are self-contained. Lite builds include them as-is.
