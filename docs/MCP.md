# MCP Server

Bomly can run as a local Model Context Protocol (MCP) server. This lets an MCP-aware agent call Bomly's dependency graph tools directly instead of asking you to paste scan output into chat.

The server is local and stdio-based:

- the MCP client starts `bomly mcp serve` as a child process
- Bomly reads the same project files the CLI can read
- tool results are returned as structured JSON
- Bomly does not host a remote MCP endpoint

## Prerequisites

Install Bomly first and make sure the `bomly` executable is on `PATH`:

```bash
bomly version
```

If that command fails, install Bomly from [Installation](INSTALLATION.md) or use the absolute path to the binary in your MCP client config.

Start the server by hand when you want to check that the command works:

```bash
bomly mcp serve
```

The command writes its startup banner to stderr and then waits for an MCP client on stdio. It is not meant to be used as an interactive shell command after startup.

## Claude Code

Add Bomly as a local stdio server:

```bash
claude mcp add --transport stdio bomly -- bomly mcp serve
```

For a project-scoped config you can also commit a `.mcp.json` file:

```json
{
  "mcpServers": {
    "bomly": {
      "type": "stdio",
      "command": "bomly",
      "args": ["mcp", "serve"],
      "env": {}
    }
  }
}
```

Claude Code prompts before using project-scoped servers from `.mcp.json`. Use `/mcp` inside Claude Code to inspect the connection and available tools.

## Cursor

Create or update `.cursor/mcp.json` in a project, or `~/.cursor/mcp.json` for your user:

```json
{
  "mcpServers": {
    "bomly": {
      "type": "stdio",
      "command": "bomly",
      "args": ["mcp", "serve"],
      "env": {}
    }
  }
}
```

Then open Cursor's MCP settings and confirm that the Bomly server is enabled. If Cursor cannot start the server, run `bomly mcp serve` in a terminal from the same environment Cursor uses.

## VS Code

Create or update `.vscode/mcp.json` in a workspace, or your user MCP config:

```json
{
  "servers": {
    "bomly": {
      "type": "stdio",
      "command": "bomly",
      "args": ["mcp", "serve"]
    }
  }
}
```

Use the command palette action `MCP: List Servers` or `MCP: Open Workspace Folder MCP Configuration` to inspect the server. VS Code also supports sandbox settings for local stdio servers if you want to restrict filesystem or network access.

## Tools

Bomly registers five MCP tools.

| Tool | Use it for | Required arguments | Optional arguments | Enrichment behavior |
| --- | --- | --- | --- | --- |
| `bomly_scan` | Scan a path, Git URL, container image, or SBOM and return packages, manifests, and optional findings. | None | `path`, `image`, `container` (deprecated alias), `url`, `ref`, `enrich`, `audit`, `analyze`, `fail_on`, `ecosystems`, `scope` | Calls external matchers only when `enrich` is true. `audit` evaluates data already present on packages and usually pairs with `enrich`. |
| `bomly_explain` | Explain why a package is present by returning dependency paths to it. | `package` | `path`, `enrich`, `audit`, `analyze` | Calls external matchers only when `enrich` is true. |
| `bomly_diff` | Compare dependency state across two Git refs or container tags/digests. | `base`, `head` | `path`, `image`, `container` (deprecated alias), `enrich`, `audit`, `analyze`, `fail_on`, `allow_vulnerability_ids`, `allow_licenses`, `deny_licenses`, `license_exempt_packages`, `deny_packages`, `deny_groups`, `protected_packages`, `typosquat_threshold`, `typosquat_mode`, `warn_only` | Calls external matchers only when `enrich` is true. |
| `bomly_vuln_fix_context` | Return fix context for vulnerabilities on one package, including affected manifests and dependency paths. | `package` | `vuln_id`, `path` | Always enriches, because vulnerability data is required to compute fix context. |
| `bomly_plugins` | List built-in and installed external plugins with their enabled state. | None | None | Does not enrich package data. |

Tool responses are JSON text results. `bomly_scan`, `bomly_explain`, and `bomly_diff` use the same response shapes documented in [JSON Schemas](SCHEMAS.md). `bomly_vuln_fix_context` returns a smaller remediation-focused payload with the package, matched vulnerabilities, dependency paths, affected manifests, and recommendation text.

## Example Prompts

After the server is connected, ask your agent for focused dependency tasks:

```text
Use Bomly to scan this project and summarize high-severity findings.
```

```text
Use Bomly to explain why lodash is present before changing package.json.
```

```text
Use Bomly to diff this branch against main and tell me whether the PR introduces new vulnerable dependencies.
```

For repeatable team behavior, put a short instruction in your repository's agent guidance:

```text
Before committing dependency or lockfile changes, use Bomly's MCP tools to run a dependency diff against the base branch and explain any new vulnerable package.
```

This is a workflow hint, not a security guarantee. Review the tool output and the proposed code changes.

## Security And Network Behavior

Bomly's MCP server runs as your user on your machine. Treat it like running the Bomly CLI from the same repository:

- it can read project files that the Bomly process can access
- it can invoke package-manager tools used by detectors if those tools are on `PATH`
- it inherits the environment passed by your MCP client
- it does not need a Bomly account, API key, or token

Network enrichment is opt-in via `enrich` for `bomly_scan`, `bomly_explain`, and `bomly_diff`. Without enrichment, matchers do not call vulnerability, license, lifecycle, or scorecard services. Some detectors may still invoke package-manager commands, and those tools can contact package registries as part of normal dependency resolution. See [Detectors](DETECTORS.md#network-behavior) for the detector-level breakdown.

`bomly_vuln_fix_context` always enables enrichment because it needs vulnerability records and fixed-version data. Use it only when you want that network-backed fix context.

## Troubleshooting

### `spawn bomly ENOENT`

Your MCP client cannot find `bomly` on `PATH`. Run:

```bash
which bomly
```

Then either fix the client environment or use the absolute path:

```json
{
  "command": "/usr/local/bin/bomly",
  "args": ["mcp", "serve"]
}
```

### The Server Starts But No Tools Appear

Check the MCP client's server status panel first. Then run:

```bash
bomly mcp serve
```

If the command exits immediately, fix the printed error. If you recently changed the config, restart the MCP server or reset the client's cached tool list.

### A Scan Takes A Long Time

The MCP tools run the real Bomly pipeline. Large repositories, container images, Git clones, enrichment, and build-tool-backed detectors can take longer than small lockfile-only scans.

Use narrower arguments when possible:

```json
{
  "path": "./services/api",
  "scope": "runtime"
}
```

For clients with per-tool timeouts, increase the timeout for the Bomly server rather than retrying the same scan in a loop.

### A Detector Says A Package Manager Is Missing

Bomly does not install package managers for you. Install the package manager the project uses, or scan from an environment where that tool is already available. Lockfile-parser detectors and SBOM ingest do not need package-manager binaries.

### The JSON Output Is Large

Dependency graphs can be large. Ask the agent to summarize specific fields, use `bomly_explain` for one package, or use `bomly_diff` to compare two refs instead of scanning the whole graph when your question is about a change.
