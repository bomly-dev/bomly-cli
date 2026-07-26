<!-- mcp-name: io.github.bomly-dev/bomly-cli -->

# bomly-mcp

Give your coding agent the dependency graph it is about to change.

`bomly-mcp` starts the [Bomly](https://github.com/bomly-dev/bomly-cli) MCP server over stdio, so an MCP-aware agent can generate, diff, explain, and audit dependencies itself instead of asking you to paste scan output into chat.

Free and open source, no account, no login.

## Use it

```bash
npx -y bomly-mcp
```

Claude Code:

```bash
claude mcp add --transport stdio bomly -- npx -y bomly-mcp
```

Cursor or VS Code, in `.cursor/mcp.json` or `.vscode/mcp.json`:

```json
{
  "mcpServers": {
    "bomly": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "bomly-mcp"]
    }
  }
}
```

If you already have the `bomly` CLI on `PATH`, you do not need this package — point your client at `bomly mcp serve` instead.

## Tools

| Tool | Use it for |
| --- | --- |
| `bomly_scan` | Scan a path, Git URL, container image, or SBOM and return a compact dependency summary. |
| `bomly_explain` | Show why one package is present, with full advisory details when enriched. |
| `bomly_diff` | Compare dependencies between Git refs, container images, or SBOM files. |
| `bomly_plugins` | List built-in and installed plugins with their enabled state. |

Full setup, arguments, and troubleshooting: [docs/MCP.md](https://github.com/bomly-dev/bomly-cli/blob/main/docs/MCP.md).

## How it installs

The postinstall step downloads the Bomly release archive for your platform from GitHub Releases, checks it against that release's `SHA256SUMS`, and unpacks the binary into the package. A checksum mismatch fails the install; there is no unverified fallback.

Environment overrides:

- `BOMLY_MCP_VERSION` — download a different CLI version.
- `BOMLY_MCP_SKIP_DOWNLOAD=1` — skip the download (for lint or CI installs that never run the server).

Supported: macOS, Linux, and Windows on x64 and arm64.

## Network behavior

The server runs as you, on your machine, and reads the project files the Bomly process can read. Vulnerability, license, lifecycle, and scorecard lookups are opt-in per call via `enrich`. Some detectors invoke package-manager commands, and those tools can contact package registries as part of normal dependency resolution. See [Detectors](https://github.com/bomly-dev/bomly-cli/blob/main/docs/DETECTORS.md#network-behavior).

Apache-2.0.
