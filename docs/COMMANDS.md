# Commands

Everything Bomly does runs through one of these commands. The three commands that build a dependency graph (`scan`, `explain`, `diff`) have their own reference pages. The others are documented on their feature pages.

| Command | Purpose | Reference |
| --- | --- | --- |
| `bomly scan` | Resolve dependencies, render reports, and write SBOMs | [scan](commands/scan.md) |
| `bomly explain` | Show every path that pulls a package into the graph | [explain](commands/explain.md) |
| `bomly diff` | Compare dependencies across Git refs, SBOM files, or image tags | [diff](commands/diff.md) |
| `bomly baseline` | Create and inspect finding baselines | [Finding baselines](BASELINES.md) |
| `bomly plugins` | List, install, enable, verify, and test external plugins | [Plugins](PLUGINS.md) |
| `bomly mcp` | Serve Bomly's tools to AI agents over MCP | [MCP server](MCP.md) |
| `bomly version` | Print version information | — |

## Shared options

`scan`, `explain`, and `diff` share the same options. Learn them once on the [scan](commands/scan.md) page; the [explain](commands/explain.md) and [diff](commands/diff.md) pages cover only what differs.

| Group | Flags |
| --- | --- |
| Target | `--path`, `--recursive`, `--url` and `--ref`, `--image`, `--sbom` |
| Pipeline steps | `--enrich`, `--audit`, `--analyze` |
| Component selection | `--detectors`, `--matchers`, `--auditors`, `--analyzers`, `--ecosystems` |
| Output | `--format`, `-o`, `--json` |

## Selector grammar

`--detectors`, `--matchers`, `--auditors`, `--analyzers`, and `--ecosystems` all accept the same kind of list:

| Form | Effect | Example |
| --- | --- | --- |
| Plain names | Replace the default set | `--matchers osv` runs only OSV |
| `+name` | Add to the defaults | `--matchers +clearlydefined-license-matcher` adds an installed plugin |
| `-name` | Remove from the defaults | `--matchers -depsdev-license-matcher` keeps everything else |

Entries are comma-separated and the forms can be mixed: `--ecosystems +go,-npm`. An unknown name, including a plugin that is not installed, fails with exit 4 and a message naming it. `bomly plugins list` shows the valid names.

Output targets use a different form, `-o <format>` or `-o <format>=<path>`, repeatable for several outputs in one run. See [Output formats](OUTPUT_FORMATS.md#write-more-than-one-output--o).

Every flag's config key, environment variable, and default is in the generated [Config reference](CONFIG_REFERENCE.md), or run `bomly <command> --help`.
