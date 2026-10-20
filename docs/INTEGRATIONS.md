# Integrations

This page lists the tools and services Bomly connects to, with one line and a link each. Use it to find the right guide for your CI system, editor, or package manager. Entries marked **Official** are built and maintained by the Bomly project. **Community** entries are maintained by their own authors, who also answer support questions. To add one, open a pull request with an entry in the same format.

## CI / CD

### Bomly Guard (Official)

The GitHub Action for pull requests. It runs `bomly diff` against the merge base, fails the check on policy violations, posts or updates one PR comment, and can upload SARIF to code scanning.
→ [bomly-dev/bomly-guard](https://github.com/bomly-dev/bomly-guard) · [Guard guide](BOMLY_GUARD.md)

### Direct CLI recipes (Official)

Copy-and-paste recipes for GitHub Actions, GitLab CI, Jenkins, Azure DevOps, and CircleCI, plus a pre-commit hook.
→ [CI Integration](CI_INTEGRATION.md)

## AI agents and editors

### MCP server (Official)

`bomly mcp serve` is built into the binary and works with any MCP client that supports stdio transport. The guide shows setup for Claude Code, Cursor, and VS Code.
→ [MCP Server](MCP.md)

### Agent guidance snippet (Official)

A ready-made instruction for `CLAUDE.md`, `AGENTS.md`, or `copilot-instructions.md` that makes a coding agent run a dependency diff before it commits lockfile changes.
→ [MCP Server → Example prompts](MCP.md#example-prompts)

## GitHub code scanning

Bomly writes SARIF 2.1.0, which the GitHub Security tab and other SARIF-aware tools read. Upload it through Guard's `upload-sarif` input or from the CLI.
→ [Output formats → SARIF](OUTPUT_FORMATS.md#sarif)

## Package managers and distribution

Official install channels:

- Homebrew tap (`bomly-dev/tap`)
- WinGet (`Bomly.BomlyCLI`) and Scoop
- Install scripts (`bomly.dev/install.sh`, `bomly.dev/install.ps1`)
- Linux packages (`.deb`, `.rpm`, `.apk`, Arch)
- `go install`
- Release archives with checksums, a signed checksum file, and build provenance

→ [Installation](INSTALLATION.md)

## Plugins

External detectors, matchers, auditors, and analyzers install as plugins: versioned, checksum-verified, and disabled until you enable them. Official plugin repositories:

- **ClearlyDefined license matcher (Official)** — license enrichment from clearlydefined.io. → [bomly-plugin-clearlydefined-matcher](https://github.com/bomly-dev/bomly-plugin-clearlydefined-matcher)
- **EOL lifecycle matcher (Official)** — end-of-life status from endoflife.date. → [bomly-plugin-eol-matcher](https://github.com/bomly-dev/bomly-plugin-eol-matcher)
- **Bun lockfile detector (Official, example)** — reference implementation for plugin authors. → [bomly-plugin-bun-lock-detector](https://github.com/bomly-dev/bomly-plugin-bun-lock-detector)
- **Meme auditor (Official, example)** — a deliberately silly auditor showing the minimal auditor contract. → [bomly-plugin-meme-auditor](https://github.com/bomly-dev/bomly-plugin-meme-auditor)

→ [Plugins](PLUGINS.md) to install and trust one · [Plugin authoring](plugins/authoring.md) to write one · the [marketplace](https://bomly.dev/marketplace) to browse every built-in and external component

## Community

No community integrations are listed yet. If you have built one (a CI orb, an IDE extension, a dashboard that reads Bomly JSON), open a pull request that adds it here with one line and a link.
