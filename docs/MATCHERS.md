# Matchers

Matchers enrich packages after Bomly has built a dependency graph.

Bomly is offline-safe by default. Network-backed matchers only run when package enrichment is explicitly enabled, for example with `bomly scan --enrich`. Matchers attach data such as vulnerabilities, license metadata, and end-of-life signals to packages. Auditors can then evaluate the enriched graph when `--audit` is enabled.

## What Matchers Add

- Vulnerability matchers add vulnerability IDs, severity, aliases, CVSS, fixed versions, references, and KEV signals where available.
- License matchers add license evidence from external package metadata services.
- Lifecycle matchers add ecosystem/runtime end-of-life metadata.

## Generated Matcher Guides

The pages in `docs/matchers/` are generated from Bomly's matcher descriptors and known runtime behavior. They list when each matcher runs, whether it uses the network, cache expectations, and the output fields users should expect.
