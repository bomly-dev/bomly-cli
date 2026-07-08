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

Bomly registers four MCP tools.

| Tool | Use it for | Required arguments | Optional arguments | Enrichment behavior |
| --- | --- | --- | --- | --- |
| `bomly_scan` | Scan a path, Git URL, container image, or SBOM and get a compact, remediation-grouped summary of what needs fixing. | None | `path`, `image`, `url`, `ref`, `enrich`, `audit`, `analyze`, `fail_on`, `ecosystems`, `scope` | Calls external matchers only when `enrich` is true. Pass `enrich` and `audit` together for a security review. |
| `bomly_explain` | Drill into one package: dependency paths, full advisory detail, and concrete fix context. | `package` | `path`, `enrich`, `audit`, `analyze` | Calls external matchers only when `enrich` is true. |
| `bomly_diff` | Branch-aware security delta between two Git refs, container tags/digests, or SBOM files: what head fixes, introduces, and leaves open after merge. | `base`, `head` | `path`, `image`, `sbom`, `enrich`, `audit`, `analyze`, `fail_on`, `allow_vulnerability_ids`, `allow_licenses`, `deny_licenses`, `license_exempt_packages`, `deny_packages`, `deny_groups`, `protected_packages`, `typosquat_threshold`, `typosquat_mode`, `warn_only` | Calls external matchers only when `enrich` is true. |
| `bomly_plugins` | List built-in and installed external plugins with their enabled state. | None | None | Does not enrich package data. |

MCP coverage matches Bomly CLI coverage: `bomly_scan`, `bomly_explain`, and `bomly_diff` use the same detector, matcher, auditor, and analyzer registry as the CLI. See [Support Matrix](SUPPORT_MATRIX.md) for the current ecosystem and package-manager list.

## Compact Responses And Drill-Down

MCP tool results land in an agent's context window, so they use a compact response shape (`schema_version: "mcp/1"`), sized for tool-result limits and versioned independently of the CLI JSON documents in [JSON Schemas](SCHEMAS.md). A realistic enriched scan that serializes to megabytes as a full document comes back as a few KB of actionable data.

`bomly_scan` returns:

- **`summary`** — manifest/package counts, vulnerable vs clean packages, findings by severity, and whether enrich/audit ran. Clean packages are counted, never listed.
- **`remediations`** — ranked groups, each one concrete change and every finding it closes: the direct dependency to change (`target_package`, full identity with org/scope and PURL), the manifest to edit, the version to move to, and an `action` (`direct-bump`, `transitive-override`, `lockfile-refresh`, `no-fix-upstream`, `policy-review`). Transitive cases carry package-manager-specific `override_advice` (npm `overrides`, pnpm `pnpm.overrides` / `pnpm-workspace.yaml`, yarn `resolutions`, Maven `dependencyManagement`, Gradle constraints, `go get` + `go mod tidy`, and so on). Groups are ranked by known-exploited (KEV) first, then severity, EPSS, and fixability.
- **`informational`** — warn-disposition and policy-only findings, separated from actionable work.
- **`diagnostics`** — pipeline warnings (detector fallbacks, matcher failures) so partial results explain themselves.
- **`truncation`** — explicit counters whenever a cap cut anything; nothing is dropped silently.

Each finding carries advisory identifiers (`vuln_id`, aliases), severity, classification (`fix_available`, `no_fix_upstream`, `wont_fix`, `policy_only`), the shortest dependency path, and KEV/EPSS/reachability signals — but no descriptions, reference URLs, or CVSS vectors.

For the omitted detail:

- **One package**: call `bomly_explain` with `enrich` (and `audit` for remediation context). Its response carries the package's full advisory records — descriptions, references, CVSS, affected ranges — bounded to that package.
- **The complete document**: run the CLI (`bomly scan --format json -o <file>`). The MCP server intentionally never returns the full scan document; it does not fit tool-result limits on real projects.

`bomly_diff` returns the same finding shape bucketed into a `security_delta` — `introduced` (new on head), `resolved` (closed when head merges), `persisted` (still open after merge) — keyed by advisory id independent of version bumps, plus remediation groups for everything still open. By default `base` and `head` are Git refs; set `image` to diff two container tags/digests, or `sbom: true` to diff two SBOM file paths (SPDX or CycloneDX), mirroring the CLI's `--image` and `--sbom` diff modes.

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

### I Need The Full Scan Document

MCP responses are intentionally compact. When an agent (or you) needs the complete three-collection JSON document, run the CLI instead: `bomly scan --format json -o scan.json`. For advisory detail on a single package, `bomly_explain` returns it without the size cost.

### A Scan Says "No Subprojects Discovered"

The error now includes a discovery probe listing the manifest files that do exist under the target and which package manager they belong to (for example `found package.json at web (npm)`), plus any active filters. Check that the `path` argument points at the project root and that no `ecosystems` filter excludes what is actually there.
