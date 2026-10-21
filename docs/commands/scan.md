# bomly scan

`bomly scan` resolves a target's dependencies into one graph and prints a report. With extra flags it also looks up vulnerability and license data (enrich), checks whether your code can reach each vulnerability (analyze), and evaluates your policy (audit). It is the command every other graph command builds on, so the flags you learn here work the same way on [explain](explain.md) and [diff](diff.md).

## Minimal invocation

Scan the current directory:

```bash
bomly scan
```

On a small npm project:

```text
✓ 68 packages in 1 manifest   (1 direct, 67 transitive · runtime 68, dev 0)

Top-level dependencies
  NAME      VERSION   LICENSE   SCOPE     VULNS
  express   4.19.2    MIT       runtime   -
```

No vulnerability or license service is contacted. The enrichment columns stay empty until you ask for them. A detector may still run your build tool when it cannot read a lockfile; [Network and privacy](../NETWORK.md) lists every case.

## Choose a target

One target per run:

```bash
bomly scan --path ./services/api                                 # a directory
bomly scan --recursive                                           # nested projects too (see --max-depth, --exclude)
bomly scan --url https://github.com/owner/repo --ref v1.2.3      # a Git ref, cloned for you
bomly scan --image ghcr.io/example/app:latest                    # a container image
bomly scan --sbom --path ./sbom.cdx.json                         # an existing SBOM
```

[Scan targets](../SCAN_TARGETS.md) covers each target's rules and limits, and [Monorepos](../MONOREPOS.md) covers `--recursive`.

## Enrich, analyze, audit

Each step is optional, and they build on each other: `--audit` and `--analyze` both require `--enrich`.

```bash
bomly scan --enrich                                                       # add vulnerability, license, and lifecycle data
bomly scan --enrich --audit --fail-on high                                # evaluate policy; exit 2 when a finding matches
bomly scan --enrich --audit --analyze --fail-on low --fail-on reachable   # gate only on reachable findings
```

| Flag | What it does | Read more |
| --- | --- | --- |
| `--enrich` | Looks packages up in vulnerability and license sources. The only flag that turns on enrichment network calls | [Matchers](../MATCHERS.md), [Network and privacy](../NETWORK.md) |
| `--audit` | Evaluates the data already on the packages against your policy. If you repeat `--fail-on`, a vulnerability finding must match every value (`any`, `low`, `medium`, `high`, `critical`, `reachable`, `exploitable`). Policy flags such as `--deny-license`, `--deny-package`, `--allow-vulnerability-id`, and `--baseline` are documented with the auditors | [Auditors](../AUDITORS.md), [Finding baselines](../BASELINES.md) |
| `--analyze` | Experimental. Marks each vulnerability as reachable or not from your code | [Reachability](../REACHABILITY.md) |
| `--warn-only` | Keeps findings visible but the exit code stays `0` | [Auditors](../AUDITORS.md) |

## Render output

```bash
bomly scan --json                                               # structured output, same as --format json
bomly scan --enrich --audit --fail-on high --format sarif       # SARIF for code-scanning tools
bomly scan -o spdx=sbom.spdx.json -o cyclonedx=sbom.cdx.json    # write two SBOM files
bomly scan --interactive                                        # open the terminal UI instead of printing
```

`--format` accepts `text`, `json`, `markdown`, `sarif`, `spdx`, and `cyclonedx`. When every `-o` names a file and you set no `--format`, the run writes the files and prints nothing. See [Output formats](../OUTPUT_FORMATS.md), [SBOM formats](../SBOM.md), and the [interactive TUI](../TUI.md).

## Narrow the run

```bash
bomly scan --scope runtime               # drop development dependencies
bomly scan --ecosystems npm,go           # only these ecosystems
bomly scan --detectors npm               # pin the detector (recommended in CI)
bomly scan --install-first               # let detectors install dependencies first (network, opt-in)
```

Pinning `--detectors` makes CI fail loudly when the chosen detector cannot run, instead of quietly falling back to a less precise one. See [Detectors](../DETECTORS.md) and [CI-readiness warnings](../CI_READINESS.md). The selector forms (`name`, `+name`, `-name`) are on the [Commands](../COMMANDS.md#selector-grammar) page.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No finding matched the policy |
| `1` | Execution error |
| `2` | A finding matched `--fail-on` |
| `3` | A required detector could not produce a graph |
| `4` | Invalid flag, value, or target |
| `5` | Nothing to evaluate |

[Exit codes](../EXIT_CODES.md) has the detail and CI recipes.

## See also

- [Getting started](../GETTING_STARTED.md) — the five-minute walkthrough
- [Use cases](../USE_CASES.md) — recipes built on `scan`
- [Config reference](../CONFIG_REFERENCE.md) — every flag's config key, environment variable, and default
