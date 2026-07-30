# Commands

Everything Bomly does runs through one of these commands. The three graph commands have dedicated reference pages; the others are documented on their feature pages.

| Command | Purpose | Reference |
| --- | --- | --- |
| `bomly scan` | Resolve dependencies, render reports, and write SBOMs | [scan](commands/scan.md) |
| `bomly explain` | Show every path that pulls a package into the graph | [explain](commands/explain.md) |
| `bomly diff` | Compare dependency state across Git refs, SBOM files, or image tags | [diff](commands/diff.md) |
| `bomly baseline` | Create and inspect finding baselines | [Finding Baselines](BASELINES.md) |
| `bomly plugins` | List, install, enable, verify, and test external plugins | [Plugins](PLUGINS.md) |
| `bomly mcp` | Serve Bomly's tools to MCP-aware AI agents | [MCP Server](MCP.md) |
| `bomly version` | Print version information | — |

## Shared option surface

The three graph commands share one option surface: the same target flags (`--path`, `--recursive`, `--url`/`--ref`, `--image`, `--sbom`), the same pipeline gates (`--enrich`, `--audit`, `--analyze`), the same component selectors (`--detectors`, `--matchers`, `--auditors`, `--analyzers`), and the same output flags (`--format`, `-o`, `--json`). Learn them once on the [scan](commands/scan.md) page; the [explain](commands/explain.md) and [diff](commands/diff.md) pages cover only what differs.

## Selector grammar

`--detectors`, `--matchers`, `--auditors`, `--analyzers`, and `--ecosystems` all accept the same selector list:

- A bare list **replaces** the default set: `--matchers osv` runs only OSV.
- `+name` **appends** to the defaults: `--matchers +clearlydefined-license-matcher` adds an installed plugin matcher.
- `-name` **removes** from the defaults: `--matchers -depsdev-license-matcher` keeps everything else.
- Entries are comma-separated and may mix forms: `--ecosystems +go,-npm`.

A name must belong to a registered component — a typo or a plugin that isn't installed fails with exit `4` and a message naming the unknown selector. Discover valid names with `bomly plugins list`.

Output targets use a separate spec: `-o <format>` or `-o <format>=<path>`, repeatable for multiple artifacts in one run — see [Output Formats](OUTPUT_FORMATS.md#additional-output--o).

For every flag with its config key, environment variable, and default, see the generated [Config Reference](CONFIG_REFERENCE.md) — or run `bomly <command> --help`.
