# Integrations

Tools and surfaces that Bomly plugs into. Entries are tagged **Official** (built and maintained by the Bomly project) or **Community** (maintained by their own authors — direct support questions to them). To suggest an addition, open a pull request that adds an entry in the same format.

## CI / CD

### Bomly Guard (Official)

The turnkey GitHub Action: runs `bomly diff` against a pull request's merge base and reports dependency changes, findings, and an updatable PR comment, with optional SARIF upload to code scanning.
→ [bomly-dev/bomly-guard](https://github.com/bomly-dev/bomly-guard) · [Guard guide](BOMLY_GUARD.md)

### Direct CLI recipes (Official)

Drop-in pipeline snippets for GitHub Actions, GitLab CI, Jenkins, Azure DevOps, and CircleCI, plus a pre-commit hook for local enforcement.
→ [CI Integration](CI_INTEGRATION.md)

## AI agents and editors

### MCP server (Official)

`bomly mcp serve` is built into the binary and works with any MCP client that supports stdio transport. Documented host setups: Claude Code, Cursor, VS Code, GitHub Copilot, and Codex.
→ [MCP Server](MCP.md)

### Agent guidance snippet (Official)

A ready-made instruction block for `CLAUDE.md` / `AGENTS.md` / `copilot-instructions.md` that has coding agents run a dependency diff before committing lockfile changes.
→ [MCP Server → Agent workflows](MCP.md)

## GitHub code scanning

SARIF 2.1.0 output uploads to the GitHub Security tab (and any other SARIF-aware tool) either via Guard's `upload-sarif` input or directly from the CLI.
→ [Output Formats → SARIF](OUTPUT_FORMATS.md#sarif--ci-security-tools)

## Package managers and distribution

Official install channels: Homebrew tap (`bomly-dev/tap`), WinGet (`Bomly.BomlyCLI`), Scoop, install scripts (`bomly.dev/install.sh`), Linux packages, `go install`, and prebuilt release archives with checksums and SLSA provenance.
→ [Installation](INSTALLATION.md)

## Plugins

External detectors, matchers, and auditors install as managed plugins (versioned, verified, disabled until enabled). Official plugin repositories:

- **ClearlyDefined license matcher (Official)** — license enrichment from clearlydefined.io. → [bomly-plugin-clearlydefined-matcher](https://github.com/bomly-dev/bomly-plugin-clearlydefined-matcher)
- **EOL lifecycle matcher (Official)** — end-of-life status from endoflife.date. → [bomly-plugin-eol-matcher](https://github.com/bomly-dev/bomly-plugin-eol-matcher)
- **Bun lockfile detector (Official, example)** — reference implementation for plugin authors. → [bomly-plugin-bun-lock-detector](https://github.com/bomly-dev/bomly-plugin-bun-lock-detector)
- **Meme auditor (Official, example)** — a deliberately silly auditor showing the minimal auditor contract. → [bomly-plugin-meme-auditor](https://github.com/bomly-dev/bomly-plugin-meme-auditor)

Write your own: [Plugins](PLUGINS.md) and the per-role implementation guides.

## Community

No community integrations are listed yet — if you've built one (a CI orb, an IDE extension, a dashboard that reads Bomly JSON), open a pull request adding it here with a one-line description and a link.
