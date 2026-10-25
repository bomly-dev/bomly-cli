# Plugins

Plugins add detectors, matchers, auditors, and analyzers to Bomly without changing the Bomly binary. This page is for people who install and run plugins: how to install one, decide to trust it, select it in a scan, and configure it. If you want to write a plugin, start with [Plugin authoring](plugins/authoring.md).

A plugin can add one of four component kinds:

| Kind | What it does | Runs during |
| --- | --- | --- |
| Detector | Turns project files into a dependency graph | Every scan |
| Matcher | Adds vulnerability, license, lifecycle, or other data to packages | `--enrich` |
| Auditor | Turns graph and package data into findings | `--audit` |
| Analyzer | Marks vulnerabilities as reachable or not from your code | `--analyze` |

Official plugin repositories:

- [ClearlyDefined license matcher](https://github.com/bomly-dev/bomly-plugin-clearlydefined-matcher): license data from clearlydefined.io
- [EOL lifecycle matcher](https://github.com/bomly-dev/bomly-plugin-eol-matcher): end-of-life status from endoflife.date
- [Bun lockfile detector](https://github.com/bomly-dev/bomly-plugin-bun-lock-detector): a reference detector for plugin authors
- [Meme auditor](https://github.com/bomly-dev/bomly-plugin-meme-auditor): a deliberately small auditor that shows the minimal contract

The [Bomly marketplace](https://bomly.dev/marketplace) lists every component that can take part in a scan, built in or external, filterable by kind and ecosystem. Each entry says who wrote the code: **Core** components ship in the binary, **Bundled** components are third-party tools compiled in (Syft, Grype), and **External plugins** are installed at runtime from their own repositories. To list a plugin there, open a submission from the marketplace page; entries are reviewed and added by hand.

## Quick start

Install a plugin from a GitHub release, check it, enable it, and use it:

```bash
bomly plugins install github:bomly-dev/bomly-plugin-clearlydefined-matcher@v0.3.0
bomly plugins verify clearlydefined-license-matcher
bomly plugins enable clearlydefined-license-matcher
bomly scan --enrich --matchers +clearlydefined-license-matcher
```

Installed plugins are disabled until you enable them. Enabling a plugin is the trust decision: see [Trust and security](#trust-and-security) before you do it.

## How plugins run

A plugin is a Go binary built on Bomly's public SDK. Bomly starts each enabled plugin as a separate process and talks to it over a versioned protocol. During one command, Bomly keeps one process per enabled plugin, starts it on first use, and stops it when the command ends. If the process dies, Bomly restarts it once; a second death disables the plugin for the rest of the command with a warning. Plugin processes never outlive the Bomly command.

Bomly owns installing plugin packages, validating their manifest, checking recorded checksums, storing plugins under `~/.bomly/plugins`, enabling and disabling them, and loading enabled plugins at the start of a command. Plugins have no install hooks or post-install scripts, and Bomly never runs a plugin it finds in a repository checkout.

## Install sources

| Source | Command | Integrity check |
| --- | --- | --- |
| GitHub release | `bomly plugins install github:<owner>/<repo>@<tag>` | Verified against the release's `SHA256SUMS` when present. Preferred |
| Local archive | `bomly plugins install ./dist/plugin.tar.gz --checksum sha256:...` | The checksum ties the installed binary to the archive |
| Direct URL | `bomly plugins install https://example.com/plugin.tar.gz --checksum sha256:...` | The checksum ties the download to the declared identity. Always pass `--checksum` |
| Direct URL, unchecked | `... --insecure-skip-checksum` | None. The binary may differ from the declared source |
| Local binary | `bomly plugins install ./bin/plugin --dev` | None. Only for binaries you built yourself |

For a GitHub release, Bomly reads the release metadata, picks the asset for your operating system and architecture, and verifies it against `SHA256SUMS` when the release publishes one. For a private release, set a token first:

```bash
export BOMLY_GITHUB_TOKEN=<token-with-release-access>   # also accepted: GITHUB_TOKEN, GH_TOKEN, GITHUB_AUTH_TOKEN
bomly plugins install github:bomly-dev/bomly-plugin-bun-lock-detector@v0.1.0
```

Bomly attaches the token only to `github:` metadata, checksum, and asset downloads. Direct URL installs never receive it.

Plugin archives have fixed size limits so a bad download cannot fill local storage:

| Limit | Value |
| --- | --- |
| Remote download | 256 MiB |
| GitHub release metadata | 4 MiB |
| Archive entries | 4,096 |
| One expanded file | 256 MiB |
| All expanded files | 512 MiB |
| Plugin manifest | 1 MiB |
| Descriptor snapshot | 1 MiB |
| Installed plugin database | 16 MiB |

Local archives skip the download limit but keep the extraction limits. Zip archives are checked before any file is extracted; tar archives are checked entry by entry. The JSON limits apply at install time and every time Bomly loads an installed plugin.

Installed plugins live under `~/.bomly/plugins/`, with `installed.json` and one `store/<plugin-id>/<version>/` directory per installed version.

## Manage plugins

| Task | Command |
| --- | --- |
| List built-in and external components | `bomly plugins list` (filter with `--external`, `--detectors`, `--matchers`, `--auditors`, `--analyzers`, `--json`) |
| Show one plugin, including its config keys | `bomly plugins info <plugin-id>` |
| Check manifest, checksum, binary, and descriptor | `bomly plugins verify <plugin-id>` |
| Check that it starts and reports ready | `bomly plugins test <plugin-id>` |
| Both checks | `bomly plugins doctor <plugin-id>` |
| Turn on or off | `bomly plugins enable <plugin-id>`, `bomly plugins disable <plugin-id>` |
| Remove | `bomly plugins uninstall <plugin-id>` |

## Select plugins in a scan

Plugin components use the same selectors as built-in ones (see [Selector grammar](COMMANDS.md#selector-grammar)): a bare name replaces the default set, `+name` adds to it, `-name` removes from it.

```bash
bomly scan --detectors bomly.examples.detector.bun-lock          # only this detector
bomly scan --enrich --matchers +clearlydefined-license-matcher   # add a matcher
bomly scan --audit --auditors bomly.examples.auditor.meme-deps   # only this auditor
bomly scan --enrich --analyze --analyzers +my-reach-analyzer     # add an analyzer
```

A detector plugin takes part in project discovery like a built-in detector. It declares which package managers and files it handles, which directories to skip, and whether it expands workspace modules itself; see [Monorepos](MONOREPOS.md).

## Component prerequisites

A component can declare the inputs it needs before it can do useful work. Bomly checks these declarations before it calls the component. When the declarations pass, Bomly still runs the component's own readiness and applicability checks. A component without declarations goes straight to those checks.

| Requirement | Met when |
| --- | --- |
| `source-tree-v1` | The target is a directory (`--path`) or a Git repository (`--url`), not an SBOM document or a container image |
| `dependency-graph-v1` | Detection found at least one dependency. A detector cannot require it |
| `vulnerability-records-v1` | At least one package carries a vulnerability record when analyzers and auditors run. This usually needs `--enrich` with a vulnerability [matcher](GLOSSARY.md) |

What Bomly does with an unmet requirement depends on why the component is in the run:

| Situation | Result |
| --- | --- |
| You selected the component by name, and the target can never meet the requirement | The command stops with exit code 4 before any stage runs |
| The component runs by default | Bomly skips it and shows a warning under that stage |
| The requirement depends on what the scan found, such as no dependencies or no vulnerability records | Bomly skips it and shows a warning, however it was selected |

"By name" means a plain selector list such as `--analyzers my-reach-analyzer`, or `+name` for a component that is off by default. A requirement that this version of Bomly does not know is never treated as met.

The error names the component, the requirement, and what would meet it. This run selects an analyzer that needs a source tree while it reads an SBOM file:

```text
bomly scan --sbom --path ./bom.cdx.json --enrich --analyze --analyzers my-reach-analyzer

Error: selected components cannot run: analyzer my-reach-analyzer requires source-tree-v1: the target is an SBOM document, not a source tree; scan a directory with --path or a Git repository with --url
```

`bomly plugins info <plugin-id>` lists the requirements a component declares. Requirements name kinds of data, never other plugins, and Bomly never changes the order of the stages to meet one.

## Configure a plugin

Plugin configuration is grouped by component kind under `plugins.<kind>.<name>`:

```yaml
plugins:
  matchers:
    clearlydefined-license-matcher:
      api_base: https://api.clearlydefined.io
  analyzers:
    my-reach-analyzer:
      max_depth: 10
```

`bomly plugins info <plugin-id>` prints the keys, descriptions, and defaults a plugin declares. The older flat form `plugins.<plugin-id>:` still works but is deprecated and prints a warning; the kind-scoped block wins when both exist.

Bomly passes its proxy settings to every plugin, so a plugin that makes HTTP calls follows the same `network.proxy` and `network.ca_cert_file` configuration as Bomly itself. See [Network and privacy](NETWORK.md#proxies-custom-endpoints-and-cas) and the [Config reference](CONFIG_REFERENCE.md).

## Trust and security

An enabled plugin runs as a normal process with your user's privileges. It can read and write files, open network connections, start child processes, and read environment variables. Bomly does not sandbox it. The plugin protocol limits what Bomly accepts as a result, but it cannot limit what the process does on the host.

Before it runs a plugin, Bomly checks:

- the manifest has the required fields (ID, version, kind, runtime, API version);
- the plugin's API version is compatible with the running Bomly;
- the entrypoint binary exists at the recorded path;
- the SHA-256 checksum matches the installed record, when one was recorded;
- the descriptor the binary returns matches the manifest identity, kind, API version, and the snapshot taken at install time.

Bomly cannot restrict a plugin's file or network access, stop it reading credentials from the environment, stop it starting child processes, or guarantee that an unchecked binary matches its declared source.

### Declared access

A plugin's manifest can include an `access` block: the publisher's own statement of the files, network destinations, environment variables, and commands the plugin uses. Bomly shows it when you install the plugin, when you enable it (before the plugin is enabled), and in `bomly plugins info`, `verify`, and `doctor`. The `--json` forms of `list`, `info`, `verify`, and `doctor` carry it as `access`, with `accessDisclosure` set to `declared` or `unknown`.

This is how `bomly plugins enable` shows a declared block:

```text
Declared access (the publisher's claim; Bomly does not verify or enforce it):
  Filesystem read  : cache, project
  Filesystem write : cache
  Network          : api.osv.dev
  Environment      : none declared
  Subprocesses     : none declared
enabled acme.matcher.example@1.0.0
```

Read the block as a description, not a limit:

- Bomly does not check that the plugin behaves as declared, and it does not stop the plugin from doing more. A checksum proves the file is the one published, not that its behavior is safe.
- A manifest without an `access` block shows `Declared access: unknown`. Treat that plugin as able to use everything your user account can.
- An `access` block with every list empty is the publisher's claim that the plugin needs none of that access.
- Bomly shows environment variable names only, never their values.
- Bomly refuses to install a manifest whose `access` block is malformed or has an unknown key. The install error names the problem.

Recommended practice:

- Prefer `github:owner/repo@tag` installs from releases that publish `SHA256SUMS`.
- Always pass `--checksum` for direct URL installs.
- Run `bomly plugins verify <id>` before you enable a plugin from an external source, and compare its declared access with what the plugin says it does.
- Do not enable plugins you did not build or obtain from a source you control.

[Security and trust boundaries](SECURITY.md) describes the wider trust model.

## Compatibility

Plugin compatibility has two independent parts:

- **The Go API** a plugin compiles against follows the SDK module's semantic version. Upgrading the SDK pin may need code changes when you rebuild the plugin.
- **The wire protocol** between a built plugin and a Bomly binary is versioned separately (`bomly.plugin.v1`). A plugin built against an older SDK keeps working with newer Bomly binaries as long as both speak the same protocol major version.

Within protocol v1 every change is additive: new fields and calls are optional, nothing is removed or renamed, and features that need both sides are negotiated through advertised capabilities. A change that cannot be made additively would ship as a new protocol version negotiated alongside v1, and existing v1 plugins would keep running. Details for authors are in [Plugin authoring](plugins/authoring.md#protocol-evolution).

## See also

- [Plugin authoring](plugins/authoring.md) — write, test, package, and release a plugin
- Implementation guides: [detector](plugins/how-to-implement-detector.md), [matcher](plugins/how-to-implement-matcher.md), [auditor](plugins/how-to-implement-auditor.md), [analyzer](plugins/how-to-implement-analyzer.md)
- [Security and trust boundaries](SECURITY.md) — what a plugin can and cannot reach
