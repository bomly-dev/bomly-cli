# Security and trust boundaries

Bomly reads repository files, can start package-manager commands, and can make network requests when you ask it to. This page explains where each of those permissions comes from, which limits Bomly enforces on untrusted input, and which risks remain. Read it when you assess Bomly for your organization. [Network and privacy](NETWORK.md) has the complete list of network triggers.

## Safe defaults

- Bomly loads only the user configuration at `~/.bomly/config.yaml` on its own. A configuration file inside a repository loads only when you select it with `--config` or `BOMLY_CONFIG`, because a complete configuration can enable network access, package-manager commands, plugins, and file output.
- Enrichment runs only with `--enrich`. `--audit` and `--analyze` do not turn it on.
- `--url` is an explicit request to clone a remote Git repository.
- Package installation runs only with `--install-first`.
- External plugins stay disabled after installation until you enable them.
- MCP requests turn on enrichment or analysis only when their request fields ask for it.

These defaults limit what Bomly may do. They do not make every scan offline: a build-tool detector may run Go, Maven, Gradle, or npm, and those tools may contact their registries while they resolve dependencies.

## Network trust

Bomly's built-in HTTP clients honor the configured proxy, no-proxy rules, and extra CA certificates. Redirects follow Go's standard rules, including its redirect limit and the removal of credentials on a cross-host redirect. Errors and logs never include endpoint or proxy credentials.

A trusted configuration may point a matcher at a custom endpoint on a public or private network, including plain HTTP, and a standard redirect may move an HTTPS request to HTTP. Bomly does not block private addresses, pin DNS answers, prevent DNS rebinding, or block that downgrade. In practice this means that whoever controls your configuration, or a server it names, controls where enrichment requests go. Keep configuration files under the same review as code.

Package managers, Git, container tools, and registries keep their own credentials and network behavior. At debug verbosity (`-vv`) Bomly logs each command it runs with its working directory and arguments, after removing values that look like credentials and the user part of URLs. This catches common secrets, not every possible one. Debug logs also include the raw stderr of invoked tools, which Bomly cannot scrub, so treat debug logs as sensitive. Lower verbosity levels do not include either.

## Files and resource limits

Bomly treats repository files, SBOMs, baselines, plugin packages, and remote responses as untrusted input, and refuses oversized input instead of using part of it.

| Input | Limit |
| --- | --- |
| A manifest, lockfile, workspace file, or source file parsed in process | 64 MiB per file |
| A local JSON cache entry | 64 MiB; an oversized or corrupt entry is a cache miss |
| A remote Git operation | 10 minutes |
| A completed Git checkout | 1,000,000 paths, 10 GiB of regular files, 256 path levels; a symlink may not point outside the checkout |
| A baseline file | 16 MiB and 10,000 entries |
| An SBOM's open member names during duplicate detection | 100,000 names or 16 MB; see the [SBOM field reference](SBOM_REFERENCE.md#strict-ingest-limits) |
| Plugin downloads, archive entries, expanded files, and metadata | See [Plugins](PLUGINS.md#install-sources) |
| Configuration files and deps.dev responses | Fixed limits; oversized input fails with an error |

Other rules for untrusted files:

- Recursive discovery does not follow directory symlinks.
- An automatically discovered baseline that is a symlink is ignored with a warning. A baseline you select explicitly may be a symlink, because selecting its path is a trust decision.
- Plugin archive extraction rejects paths, links, and special files that could escape the plugin directory.
- An imported SBOM must have one unambiguous reading, and every value it asserts is re-checked before Bomly republishes it. [SBOM formats](SBOM.md#what-bomly-refuses-to-read) explains what is refused and why. The plugin protocol keeps its own decoding, because an enabled plugin is a process you chose to run.
- Output is written only to the path you selected. Cache keys are hashed before they become file names.

Some resources have no hard limit on purpose:

- `--url` uses the installed Git client. Git may download objects and use disk space before Bomly can check the finished checkout, and the `.git` directory is not counted in the 10 GiB limit. Use operating-system limits when that earlier use must be capped.
- Output from a package manager or other host tool is not truncated, because a truncated result could look like a complete dependency graph.
- A local target may contain any number of files, each limited individually. Bomly does not limit the total size of a local project.

## Plugin trust

Installing a plugin verifies its package and records it, but does not enable it. Enabling a plugin is the trust decision. An enabled plugin is a process with the same privileges as Bomly: it can read and write files, use the network, read its environment, and start other programs. The plugin protocol validates the data a plugin returns; it is not a sandbox. Bomly passes plugins a small, explicit environment rather than the complete host environment, and repository files cannot install or enable a plugin. [Plugins](PLUGINS.md#trust-and-security) lists what Bomly checks before it runs one.

## MCP

The MCP tools use the same options and rules as the CLI, and policy fields never turn on enrichment or analysis by themselves. Responses have size caps with truncation counters. Tool failures return a short, stable category rather than the raw error, so local paths, command output, and credentials stay out of the protocol and the logs. The MCP server is a local process; your MCP client decides who can start it, which directories it can reach, and whether to sandbox it further.

## Reporting a vulnerability

Follow the private reporting instructions in the repository's [security policy](https://github.com/bomly-dev/bomly-cli/security/policy). Do not include credentials or private project data in a public issue.
