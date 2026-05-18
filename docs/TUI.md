# Interactive Terminal UI

`bomly scan --interactive` opens a Bubbletea TUI for browsing scan results. Use it when text output is too dense or you want to filter results live.

```bash
bomly scan --enrich --audit --interactive
```

Requirements:

- A real terminal on stdin **and** stderr. Piping into a non-tty rejects with `ErrNotATerminal`.
- A TrueColor-capable terminal for the best rendering.

`--interactive` forces `--format text` and is incompatible with `--format json`, `--format sarif`, and stdout SBOM writes (`-o spdx-json` without `=<path>`). Filed SBOM writes still work alongside the TUI.

## Tabs

Switch with the number keys or `Tab`:

| Key | View | What's shown |
| --- | --- | --- |
| `1` | Overview | Scan summary, totals by ecosystem and severity |
| `2` | Packages | Full dependency list with tree expansion |
| `3` | Vulnerabilities | Findings grouped by package |
| `4` | Licenses | License inventory and conflicts |
| `5` | Findings | Audit policy hits with reasons |
| `6` | Source | Detected manifest and lockfile inventory |

`Tab` cycles forward through views; `Shift+Tab` is the reverse cycle in supporting terminals.

## Navigation

| Key | Action |
| --- | --- |
| `↑` / `k` | Move up one row |
| `↓` / `j` | Move down one row |
| `Home` / `g` | Jump to top |
| `End` / `G` | Jump to bottom |
| `PgUp` / `Ctrl+u` | Half-page up |
| `PgDn` / `Ctrl+d` | Half-page down |
| `←` / `h` / `Backspace` | Collapse / go back |
| `→` / `l` | Expand |
| `[` | Collapse all |
| `]` | Expand all |
| `Enter` | Open / toggle the selected row |

## Search

| Key | Action |
| --- | --- |
| `/` | Start a search |
| (typing) | Refine the query incrementally |
| `Enter` | Commit the filter |
| `Esc` | Cancel the search |
| `Backspace` | Edit the current query |

Search matches package name, version, ecosystem, vulnerability ID, and license expression.

## Filters

Press the filter key, then pick from the popup. Press the same key again to clear that filter.

| Key | Filter |
| --- | --- |
| `r` | Relationship (direct, transitive, root) |
| `s` | Scope (runtime, development, unknown) |
| `v` | Severity (critical, high, medium, low, unknown) |
| `e` | Ecosystem |
| `g` | Group (custom grouping) |

Filters compose. Search and filters compose. The current filter set is shown in the header.

## Quit

| Key | Action |
| --- | --- |
| `q` | Quit (with confirmation prompt) |
| `Esc` | Quit when no search/popup is active |
| `Ctrl+C` | Quit (with confirmation prompt) |

The confirmation prompt prevents accidental exits mid-scroll. Press `y` to confirm or any other key to stay.

## Tips

- Run with `--enrich --audit` to see vulnerability and finding views populated. Without `--enrich`, the Vulnerabilities and Findings tabs will be empty.
- Use `Search` (`/`) to narrow a large monorepo quickly: `/api` shows only packages with `api` in the name.
- Combine the Severity filter (`v`) with the Findings tab to triage the highest-impact items first.

## Limitations

- TUI output is not captured into JSON or SARIF. Re-run without `--interactive` to produce machine-readable artifacts.
- Plugin matchers that print progress to stderr will draw under the TUI; use a non-interactive run for plugin debugging.
- SSH and `tmux` sessions are supported; multiplexer detach/reattach is supported.
