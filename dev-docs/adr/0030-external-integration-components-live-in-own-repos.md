# ADR-0030: External-integration components live in their own repositories, consumed as ordinary Go modules

- **Date:** 2026-08-13
- **Status:** Accepted

The component-extraction program's final shape: components whose job is integrating an external tool or service — the reachability analyzers (govulncheck, jsreach, pyreach, jvmreach), the external enrichment matchers (osv, deps.dev license, scorecard, grype), and the Syft catch-all detector — each live in a public `bomly-plugin-*` repository and are consumed by the CLI as ordinary pinned Go modules. Auditors and native detectors stay CLI-internal.

Each component repository exposes a `plugin` package with two consumption surfaces:

```go
// Embedded: the CLI composition constructs the component directly.
analyzer := plugin.Analyzer{Logger: logger}

// Managed: the same code packaged for subprocess plugin execution.
module := plugin.Module()
```

The embedded surface preserves the exact constructor shapes the CLI used in-tree (`Config`/`DefaultConfig`/`New` for the configurable matchers, plain struct literals for grype and the analyzers, host-injected catalog fields for the Syft detector), so swapping the import path was the whole migration. Descriptor names are unchanged, which keeps goldens, detector aliases, and generated component docs stable. The grype and syft repositories carry both build-tag variants of their code; the root build's `bomly_external_syft` / `bomly_external_grype` tags select files inside those modules, so full and lite builds work exactly as before.

Two nested-module designs were evaluated and abandoned before this: a committed `go.work` workspace with `components/<kind>/<name>/` modules plus a lockstep release train, and a variant consuming the same nested modules through root `replace` directives. Both kept the code in-repo but added machinery the ordinary-module model does not need — workspace/pinned-build split in CI, a replace-directive allowlist, a bespoke tagging script — and the replace-based variant broke remote `go install`. With external repositories, `go install github.com/bomly-dev/bomly-cli/cmd/bomly@latest` keeps working, Dependabot handles version bumps, and each component repository owns its tests, fuzz targets, and releases.
