# Interactive terminal UI

`bomly scan --interactive` opens a terminal UI for browsing scan results. Use it when the text report is too dense, or when you want to search and filter the results live. This page lists the tabs and keys.

```bash
bomly scan --enrich --audit --interactive
```

Requirements:

- a real terminal on both stdin and stderr. Bomly refuses to start the TUI when either is piped;
- a terminal with TrueColor support, for the best rendering.

`--interactive` forces `--format text`. It cannot be combined with `--json`, `--format json`, `--format sarif`, or an SBOM written to stdout (`-o spdx` without `=<path>`). SBOMs written to files still work alongside the TUI.

## Tabs

Switch with the number keys or `Tab` (`Shift+Tab` goes backwards in terminals that support it):

| Key | View | What it shows |
| --- | --- | --- |
| `1` | Overview | Scan summary, totals by ecosystem and severity |
| `2` | Components | The project tree: manifests and their dependency trees |
| `3` | Vulnerabilities | Findings grouped by package |
| `4` | Licenses | License inventory and conflicts |
| `5` | Findings | Audit policy hits with reasons |
| `6` | Source | The detected manifests and lockfiles |

The Components tree follows the project layout:

- manifests at the scan root sit directly under the project node;
- a **subproject** node holds the manifests of a nested directory found by `--recursive`;
- a **module** node holds a workspace or reactor member (an npm or pnpm workspace package, a Cargo workspace member, a Maven reactor module) that resolves under one root manifest.

A single-root scan keeps a plain project-to-manifests tree. Group nodes expand and collapse like any other row, and their details pane shows the directory, ecosystems, and manifest counts. [Monorepos](MONOREPOS.md) explains the terms.

## Navigation

| Key | Action |
| --- | --- |
| `↑` / `k` | Move up one row |
| `↓` / `j` | Move down one row |
| `Home` (or `g` on tabs without grouping) | Jump to top |
| `End` / `G` | Jump to bottom |
| `PgUp` / `Ctrl+u` | Half page up |
| `PgDn` / `Ctrl+d` | Half page down |
| `←` / `h` / `Backspace` | Collapse, or go back |
| `→` / `l` | Expand |
| `[` | Collapse all |
| `]` | Expand all |
| `Enter` | Open or toggle the selected row |

## Search

| Key | Action |
| --- | --- |
| `/` | Start a search |
| (typing) | Narrow the results as you type |
| `Enter` | Keep the filter |
| `Esc` | Cancel the search |
| `Backspace` | Edit the query |

Search matches the package name, version, ecosystem, vulnerability ID, and license expression.

## Filters

Press a filter key, then pick a value from the popup. Press the same key again to clear that filter.

| Key | Filter |
| --- | --- |
| `r` | Relationship (direct, transitive, root) |
| `s` | Scope (runtime, development, unknown) |
| `v` | Severity (critical, high, medium, low, unknown) |
| `e` | Ecosystem |
| `g` | Group (on tabs that support grouping) |

You can combine filters with each other and with a search. The header shows the active set.

## Quit

| Key | Action |
| --- | --- |
| `q` | Quit, after a confirmation prompt |
| `Esc` | Quit, when no search or popup is open |
| `Ctrl+C` | Quit, after a confirmation prompt |

The prompt prevents accidental exits. Press `y` to confirm, or any other key to stay.

## Fix suggestions

When enrichment found fix information, select a package in the Components view. Its details pane shows a **Remediation suggestion** section below **Vulnerabilities**, with one of four fix states: **Complete fix available**, **Partial fix available**, **No fix available**, or **Fix availability unknown**. The section may also show a recommended version, suggested actions, and package-manager advice. A suggestion changes nothing on disk. Check compatibility and run your tests before you apply an upgrade.

## Tips

- Run with `--enrich` to see vulnerability details, and add `--audit` to see policy findings.
- Search (`/`) narrows a large monorepo quickly: `/api` shows only packages with `api` in the name.
- Combine the severity filter (`v`) with the Findings tab to triage the most severe items first.

## Limitations

- The TUI does not produce JSON or SARIF. Re-run without `--interactive` for machine-readable output.
- A plugin matcher that prints progress to stderr can corrupt the display. Debug plugins in a non-interactive run.
- SSH sessions work, and so do `tmux` and `screen`, including detaching and reattaching.
