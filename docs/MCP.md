# MCP server

Bomly can run as a local server for the Model Context Protocol (MCP), the standard AI coding agents use to call tools. An agent such as Claude Code, Cursor, or VS Code can then run `scan`, `explain`, and `diff` itself instead of asking you to paste output into the chat. This page shows how to connect each client, what the tools return, and how to fix common problems.

The server is local and talks over standard input and output:

- the MCP client starts `bomly mcp serve` as a child process;
- Bomly reads the same project files the CLI can read;
- results come back as structured JSON;
- there is no hosted Bomly endpoint, account, or API key.

## Prerequisites

Install Bomly and make sure `bomly` is on `PATH`:

```bash
bomly version
```

If that fails, install from [Installation](INSTALLATION.md), or use the binary's absolute path in your client config. To check that the server itself starts, run it by hand; it prints a banner to stderr and then waits for a client:

```bash
bomly mcp serve
```

### Without installing the CLI

The [`bomly-mcp`](https://www.npmjs.com/package/bomly-mcp) npm package starts the same server and downloads the CLI for you:

```bash
npx -y bomly-mcp
```

Its install step downloads the release archive for your platform from GitHub Releases and checks it against the release's `SHA256SUMS` file. If the checksum does not match, nothing is unpacked. Set `BOMLY_MCP_VERSION` to pin a CLI version. Anywhere below that a config uses `"command": "bomly"` with `"args": ["mcp", "serve"]`, you can use `"command": "npx"` with `"args": ["-y", "bomly-mcp"]` instead. If `bomly` is already on `PATH`, prefer it: it starts faster and your package manager updates it.

## Connect a client

### Claude Code

Add Bomly as a local server:

```bash
claude mcp add --transport stdio bomly -- bomly mcp serve
```

Or commit a project-scoped `.mcp.json`:

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

Claude Code asks before it uses a project-scoped server. Run `/mcp` inside Claude Code to inspect the connection and the tools.

### Cursor

Create or update `.cursor/mcp.json` in the project, or `~/.cursor/mcp.json` for your user:

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

Then confirm in Cursor's MCP settings that the server is enabled. If Cursor cannot start it, run `bomly mcp serve` in a terminal from the same environment Cursor uses.

### VS Code

Create or update `.vscode/mcp.json` in the workspace, or your user MCP config:

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

Use the command palette actions `MCP: List Servers` or `MCP: Open Workspace Folder MCP Configuration` to inspect it. VS Code can also sandbox local servers if you want to restrict file or network access.

## Tools

Bomly registers four tools. The three graph tools use the same detectors, matchers, auditors, and analyzers as the CLI, so coverage matches the [Support matrix](SUPPORT_MATRIX.md).

| Tool | Use it for | Required | Optional |
| --- | --- | --- | --- |
| `bomly_scan` | Scan a path, Git URL, container image, or SBOM | None | `path`, `image`, `url`, `ref`, `enrich`, `audit`, `analyze`, policy arguments, `ecosystems`, `scope`, `recursive`, `max_depth`, `exclude` |
| `bomly_explain` | Show why one package is present, with full advisory detail when enriched | `package` | `path`, `enrich`, `audit`, `analyze`, policy arguments, `recursive`, `max_depth`, `exclude` |
| `bomly_diff` | Compare dependencies between Git refs, image tags, or SBOM files | `base`, `head` | `path`, `image`, `sbom`, `enrich`, `audit`, `analyze`, policy arguments, `recursive`, `max_depth`, `exclude` |
| `bomly_plugins` | List built-in and installed external components with their enabled state | None | None |

The arguments mirror the CLI flags. `enrich` adds vulnerabilities and fix suggestions, and `audit` and `analyze` both require it. The policy arguments are `fail_on`, `allow_vulnerability_ids`, `allow_licenses`, `deny_licenses`, `license_exempt_packages`, `deny_packages`, `deny_groups`, `protected_packages`, `typosquat_threshold`, `typosquat_mode`, `warn_only`, and `baseline`. Per-call values layer over the server's resolved configuration and are validated with the same rules as the flags. For `bomly_diff`, `base` and `head` are Git refs by default; set `image` to compare two image tags or digests, or `sbom: true` to compare two SBOM files.

## What the tools return

Tool results land in the agent's context window, so they use a compact shape (`schema_version: "mcp/1"`) that is versioned separately from the CLI JSON documents. A scan that is megabytes as a full document comes back as a few kilobytes.

`bomly_scan` returns:

| Field | Content |
| --- | --- |
| `summary` | Manifest and package counts, `subprojects` and `modules` counts when the scan spans nested projects, vulnerable and clean package counts, findings by severity, and whether enrich and audit ran. A clean scan without audit also includes a capped package list |
| `remediations` | Suggested changes for vulnerable packages, most urgent first. Each group names the package and, when known, the manifest to edit. `recommended_version` appears only when the data supports one complete recommendation |
| `informational` | Findings that need no change now: warning-only findings, and vulnerabilities allowed by policy or below the failure threshold |
| `diagnostics` | Pipeline warnings (detector fallbacks, matcher failures) and the [CI-readiness warnings](CI_READINESS.md), so partial results explain themselves |
| `truncation` | Counters for anything a size cap cut, so the agent knows what it did not see |

Each remediation group carries one of these actions:

| Action | Meaning |
| --- | --- |
| `direct-bump` | Update a package declared directly in the project |
| `transitive-override` | Pin an indirect package with the package manager's override feature |
| `lockfile-refresh` | Ask the package manager to resolve a newer indirect version |
| `no-fix-upstream` | The advisory source says no fixed version exists |
| `manual-review` | The data does not support a specific change |

Each finding carries the advisory identifiers, severity, classification (`fix_available`, `no_fix_upstream`, `wont_fix`, `policy_only`), the shortest dependency path, and the KEV, EPSS, and reachability signals, but no descriptions, reference URLs, or CVSS vectors. For that detail, call `bomly_explain` with `enrich` on one package; its response carries the full advisory records for that package only. The server never returns the complete scan document, because it does not fit tool-result limits on real projects. When you need it, run the CLI: `bomly scan --format json -o scan.json`.

`bomly_diff` with `enrich` returns fix suggestions for vulnerable packages on the head side. With `audit` it also returns the findings grouped as `introduced`, `resolved`, and `persisted` under `security_delta`.

## Example prompts

Once the server is connected, ask for focused dependency tasks:

```text
Use Bomly to scan this project and summarize the high-severity findings.
```

```text
Use Bomly to explain why lodash is present before you change package.json.
```

```text
Use Bomly to diff this branch against main and tell me whether the PR introduces new vulnerable dependencies.
```

For repeatable team behavior, add a line to your repository's agent instructions (`CLAUDE.md`, `AGENTS.md`, or `copilot-instructions.md`):

```text
Before committing dependency or lockfile changes, use Bomly's MCP tools to run a dependency diff against the base branch and explain any new vulnerable package.
```

This is a workflow hint, not a security guarantee. Review the tool output and the proposed changes.

## Security and network behavior

The server runs as your user on your machine. Treat it like running the CLI from the same repository: it can read the project files your user can read, it can run the package-manager tools detectors use when they are on `PATH`, and it inherits the environment your client passes. Enrichment is opt-in through the `enrich` argument; without it Bomly contacts no vulnerability or license service. [Network and privacy](NETWORK.md) lists everything that can reach the network.

## Troubleshooting

### A tool reports only a short failure category

Tool errors are short, such as `scan pipeline failed` or `diff target resolution failed`. Bomly does not send raw internal errors to the client, because they can contain local paths, command output, URLs, or credentials. Request validation works the same way: it names the category, not the rejected value, so an agent may need to check the tool schema or retry with fewer options to find an invalid combination.

To see the detail, run the server with `bomly -vv mcp serve` and repeat the request. The components log their own stage details; the MCP error log records only the category.

### `spawn bomly ENOENT`

The client cannot find `bomly` on `PATH`. Run `which bomly`, then fix the client's environment or use the absolute path:

```json
{
  "command": "/usr/local/bin/bomly",
  "args": ["mcp", "serve"]
}
```

### The server starts but no tools appear

Check the client's server status panel first. Then run `bomly mcp serve` in a terminal. If it exits at once, fix the printed error. If you changed the config recently, restart the server or reset the client's cached tool list.

### A scan takes a long time

The tools run the real pipeline. Large repositories, container images, Git clones, enrichment, and build-tool-backed detectors take longer than a lockfile-only scan. Narrow the request where you can, for example `{"path": "./services/api", "scope": "runtime"}`. If your client has per-tool timeouts, raise the timeout for the Bomly server rather than retrying the same scan.

### A detector says a package manager is missing

Bomly does not install package managers. Install the one the project uses, or run from an environment that has it. Lockfile-parser detectors and SBOM ingest need no package-manager binaries.

### A scan says "no subprojects discovered"

The error lists the target, the search scope, the active filters, and every manifest candidate under the target with the reason it was skipped. Check these in order:

- `path` points at the project root;
- no `ecosystems` filter excludes what is there;
- if the candidates are in subdirectories, pass `recursive: true`, because discovery looks only at the target root by default; `max_depth` and `exclude` bound the walk.

[Troubleshooting](TROUBLESHOOTING.md#nothing-to-evaluate-exit-5) lists every skip reason and its fix.
