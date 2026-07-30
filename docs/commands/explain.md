# bomly explain

Answer "why is this package here?" — trace every dependency path that pulls a package into the graph. `explain` runs the same detect and match stages as [scan](scan.md), then walks the graph from the project roots to the package you named.

## Minimal invocation

```bash
bomly explain send
```

On a project that depends on `express`:

```text
ecosystem  npm
manager    npm
package    send@0.18.0
scope      runtime
direct     no
licenses
  MIT [declared]
introduced by:
  demo@1.0.0
  └─ express@4.19.2
     ├─ send@0.18.0 [analyzed] (transitive)
     └─ serve-static@1.15.0
        └─ send@0.18.0 [analyzed] (transitive)
```

Every path is shown, not just the shortest one — here `send` enters both directly through `express` and again through `serve-static`, which matters when you're deciding what to bump.

## Naming the package

Pass a package name or a full PURL. A PURL disambiguates when the same name exists in more than one ecosystem:

```bash
bomly explain lodash
bomly explain pkg:npm/react
bomly explain github.com/spf13/cobra --path ./backend
```

## Targets and gates

`explain` accepts the same target flags as scan (`--path`, `--recursive`, `--url`/`--ref`, `--image`, `--sbom`) and the same pipeline gates. Add `--enrich` to include the package's vulnerabilities in the explanation, and `--audit`/`--analyze` when you want policy findings or reachability on it:

```bash
bomly explain send --enrich            # include known vulnerabilities
bomly explain send --enrich --analyze  # and whether they're reachable
bomly explain send --json              # structured paths for tooling
```

The JSON shape is documented in the [explain schema](../schemas/explain.md).

## Exit codes

Same table as every command — see [Exit Codes](../EXIT_CODES.md). Notably `5` when the target has no supported manifests, and `4` for a malformed PURL.

## See also

- [scan](scan.md) — the shared target, gate, and output flags
- [diff](diff.md) — when the question is "what changed" rather than "why is it here"
- [Interactive TUI](../TUI.md) — explore the same paths interactively with `bomly scan --interactive`
