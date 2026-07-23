# Parser fuzzing inventory

The native fuzz suite covers in-process parsers that consume repository,
configuration, plugin-path, SDK, baseline, SBOM, analyzer, or matcher data.
Every target bounds its input before parsing and treats a panic as a failure.
Graph-producing targets also verify non-nil nodes, identifiers, and edge
endpoints after every successful parse.

## Native targets

| Input family | Targets |
|---|---|
| Configuration and policy documents | strict YAML configuration, finding baseline |
| Shared JSON contracts | dependency graph, package registry |
| Package identifiers and plugin paths | package URL canonicalization, plugin path sanitizers |
| SBOM | automatic SPDX, CycloneDX, and Syft JSON decoding |
| Analyzer output | govulncheck JSON stream, esbuild metafile |
| Node lockfiles | npm, pnpm, Yarn, Bun |
| Python lockfiles | Poetry, uv, Pipenv |
| Other lockfiles and manifests | Cargo, CocoaPods, Composer, Conan, Go list, Mix, NuGet lock and packages.config, Pub, Bundler, SwiftPM |
| Workflow manifests | GitHub Actions workflow references |
| Matcher evidence | vulnerability consolidation and advisory aliases |

Seeds include valid minimal documents and malformed/truncated structures.
The fuzz engine supplies invalid encodings, deep nesting, duplicate values,
oversized structures within the bound, and arbitrary path/reference text.

## Exclusions

- Command-backed detectors are exercised through fake-binary unit tests and
  smoke tests. Their parsers are fuzzed only when the command output has an
  isolated, deterministic in-process parser.
- Maven, Gradle, and SBT XML/tree output is coupled to command execution and
  does not currently expose a pure parser boundary.
- Archive extraction uses Go standard-library readers plus explicit path
  containment checks; hostile archive path behavior remains covered by
  security tests coordinated with the threat-model work.
- YAML, JSON, XML, TOML, URL, and CSV primitives provided directly by Go or
  existing dependencies are not fuzzed independently. Bomly-owned conversion
  and validation code around them is the target.
- Filesystem discovery and package-manager subprocess orchestration are not
  parsers and remain covered by unit, integration, and smoke tests.

Add every new pure parser target to `scripts/run-fuzz.sh`; the scheduled fuzz
workflow invokes that manifest through `make fuzz`.
