# Security and Trust Boundaries

Bomly reads repository files, can start package-manager commands, and can make
network requests when you ask it to. This page explains where those permissions
come from and which parts of a run you must trust.

## Safe Defaults

- Bomly automatically loads only the user configuration at
  `~/.bomly/config.yaml`. A repository configuration loads only when you
  select it with `--config` or `BOMLY_CONFIG`.
- Network-backed matchers run only with `--enrich`. `--audit` and `--analyze`
  do not turn on enrichment.
- `--url` is an explicit request to clone a remote Git repository.
- Package installation runs only with `--install-first`.
- External plugins are disabled after installation until you enable them.
- MCP requests do not turn on enrichment or analysis unless their matching
  request fields do so explicitly.

These defaults limit authority. They do not make every scan offline. A selected
build-tool detector may run tools such as Go, Maven, Gradle, or npm, and those
tools may contact their configured registries while resolving dependencies.

## Network Trust

Bomly's built-in HTTP clients honor the configured proxy, no-proxy rules, and
additional CA certificates. Redirects use Go's standard redirect rules,
including its redirect limit and removal of credentials on a cross-host
redirect. Errors and logs do not include configured endpoint or proxy
credentials.

Trusted configuration may select a custom endpoint on a public or private
network, including plain HTTP. Standard redirects may also move an HTTPS
request to HTTP. Bomly does not block private addresses, pin DNS answers,
prevent DNS rebinding, or block that downgrade. Selecting the endpoint grants
Bomly permission to follow those standard redirect rules.

Host package managers, Git, container tools, and registries keep ownership of
their own credentials and network behavior. At debug verbosity, Bomly logs the
executable, working directory, and arguments after removing recognized
credential-shaped values and URL user information. This is a deliberately
bounded redactor, not a promise that arbitrary argument text is secret-free.
Arbitrary subprocess stderr is counted, not printed, because it may contain
credentials. This rule also covers Java readiness checks and local Git
revision and diff commands. When one fails, Bomly reports the exit status and
diagnostic byte count, but not the tool's exact message. This loses some
troubleshooting detail in exchange for one consistent subprocess-output
boundary.

## Files and Resource Limits

Bomly treats repository files, SBOMs, baselines, plugin packages, and remote
responses as untrusted input.

- Recursive discovery does not follow directory symlinks.
- Automatically discovered baseline symlinks are ignored with a warning. A
  user-selected baseline may be a symlink because selecting its path is an
  explicit trust decision.
- Archive extraction rejects paths, links, and special files that could escape
  the plugin directory. Plugin downloads, archive entries, expanded files, and
  plugin metadata have fixed size limits.
- Configuration, baselines, SBOM input, and deps.dev responses have fixed
  limits. Oversized input fails with an error instead of being partially used.
- Output is written only to the path selected by the user. Cache keys are
  hashed before they become paths.

Some resources intentionally have no general hard size limit:

- `--url` uses the installed Git client and has no Bomly byte or disk quota.
  Cancel the command or apply operating-system limits when scanning an
  untrusted, very large repository.
- Ordinary manifests and lockfiles do not share one global byte limit. Their
  parsers reject malformed input and are fuzz-tested, but a very large project
  can still consume substantial memory and time.
- Files in Bomly's local cache directories are treated as user-controlled
  state. Their contents are not given repository or plugin authority, but
  cache files do not have a separate read-size limit.

## Plugin Trust

Installing a plugin verifies its package and records it, but does not enable
it. Enabling a native plugin is the trust decision.

An enabled plugin is a native process with the same user privileges as Bomly.
It can read and write files, use the network, inspect its environment, and
start other programs. The plugin protocol validates data returned to Bomly; it
is not an operating-system sandbox.

Bomly passes managed plugins a small, explicit environment rather than copying
the complete host environment. Repository files cannot install or enable a
plugin automatically.

## MCP

MCP tools use the same command options and pipeline gates as the CLI. Policy
fields do not implicitly enable enrichment or analysis. Compact MCP responses
have size caps and truncation counts. Tool failures return stable error
categories. Local MCP error logs contain the category and unwrapped Go cause
type, not the raw cause text. Components may also emit their own safe stage
logs independently.

The MCP server is a local process. Your MCP host controls who can start it,
which directories it can reach, and whether additional operating-system
sandboxing is applied.

## Reporting a Vulnerability

Please follow the private reporting instructions in the repository's
[Security policy](https://github.com/bomly-dev/bomly-cli/security/policy).
Do not include credentials or private project data in a public issue.
