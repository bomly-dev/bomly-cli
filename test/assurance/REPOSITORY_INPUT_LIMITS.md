# Repository input limits

Bomly parses project files in its own process. A very large file must not make
that process allocate memory without a limit.

## Shared limit

One repository-controlled file may contain at most 64 MiB. This limit applies
before a parser receives the bytes and while a streaming reader consumes them,
so a file that grows after it is opened cannot bypass the check.

The shared limit covers:

| Input | Readers |
| --- | --- |
| Dependency manifests and lockfiles | Cargo, CocoaPods, Composer, Conan, Go modules, Gradle, Maven modules, Mix, npm, pnpm, Yarn, Bun, NuGet, Pub, Python, Bundler, SBT, SwiftPM, and GitHub Actions |
| Workspace and module metadata | Cargo workspaces, Gradle modules, Maven modules, npm workspaces, pnpm workspaces, and registry discovery |
| Analyzer project files | Go module fingerprints, JavaScript package and workspace files, JVM build files, Python project files, and source files scanned by the in-process reachability analyzers |
| Best-effort source positions | Manifest and lockfile line scans used to attach source locations |
| Hidden benchmark parser inputs | Selected target manifests use 64 MiB; generated and downloaded SBOM documents use 256 MiB; Git scalar output uses 1 MiB |

An input at the limit is read in full. An input one byte larger returns
`system.ErrInputTooLarge`; parsers do not use a partial document or partial
graph.

## Other existing limits

Some inputs already have a narrower or purpose-specific limit:

| Input | Limit |
| --- | --- |
| Selected configuration | 4 MiB |
| Finding baseline | 16 MiB and 10,000 entries |
| Explicit SBOM | 256 MiB |
| Plugin manifest or runtime snapshot | 1 MiB |
| Installed plugin database | 16 MiB |
| Matcher responses | 4–64 MiB, depending on the service and operation |
| Plugin package | 256 MiB download, 4,096 entries, 256 MiB per expanded file, and 512 MiB expanded total |

Local matcher and analyzer JSON cache entries have a 64 MiB read limit.
Corrupt or oversized cache entries are treated as misses, so they do not fail
the scan.

## Intentional exclusions

- A selected package manager or other host tool owns its command output.
  Bomly does not truncate that output because doing so could produce a
  believable but incomplete dependency graph. Command timeouts, fake-binary
  tests, and smoke tests cover those integrations.
- Yarn format detection reads only a fixed-size head of `yarn.lock`; it never
  reads the complete file a second time.
- Directory discovery, source-tree walking, and subprocess orchestration are
  not document parsers. Remote checkouts have separate entry, size, depth,
  time, and symlink controls. Local target size remains under the user's
  filesystem authority.
- Benchmark executable hashing, generated-artifact hashing, and the committed
  report prompt are maintenance operations rather than untrusted document
  parsing. Their reads are intentionally not classified as repository parser
  inputs.
- JSON, YAML, XML, TOML, and CSV libraries are not tested in isolation.
  Bomly-owned parsing and graph conversion around them is covered by the fuzz
  targets listed in `PARSER_FUZZING.md`.

## Regression evidence

- `bomly-sdk/system` (pinned dependency): the authoritative exact-limit,
  one-byte-over-limit, streamed-growth, and size-scaled read tests and
  benchmarks live upstream in `bomly-dev/bomly-sdk` (`system/read_test.go`);
  `test/assurance/sdk_contract_test.go` re-asserts the bounding contract
  (including growth rejection and the 64 MiB repository limit) against the
  pinned version in `make test`.
- `bomly-sdk/filecache` (pinned dependency): corrupt and oversized cache
  entries degrade to a miss — contract-checked locally in
  `test/assurance/sdk_contract_test.go`, authoritative suite upstream in
  `filecache/cache_test.go`.
- Detector and analyzer package suites: valid fixtures still produce their
  complete expected graphs and analysis results through the bounded readers.
- `scripts/run-fuzz.sh`: every registered pure repository parser receives
  bounded malformed input and must not panic.
