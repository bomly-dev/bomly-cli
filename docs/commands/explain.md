# bomly explain

`bomly explain` answers "why is this package here?" It runs the same detect and enrich steps as [scan](scan.md), then prints every dependency path from a project root to the package you name.

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

Every path is shown, not only the shortest. Here `send` comes in through `express` and again through `serve-static`, which matters when you decide what to upgrade. `[analyzed]` marks a package that reachability analysis looked at.

## Naming the package

Pass a package name or a full package URL (PURL). The PURL form settles which package you mean when the same name exists in more than one ecosystem:

```bash
bomly explain lodash
bomly explain pkg:npm/react
bomly explain github.com/spf13/cobra --path ./backend
```

## Targets and steps

`explain` accepts the same target flags as scan (`--path`, `--recursive`, `--url` and `--ref`, `--image`, `--sbom`) and the same pipeline steps. Add `--enrich` to include the package's vulnerabilities. Add `--audit` for policy findings on it, or `--analyze` for reachability:

```bash
bomly explain send --enrich            # include known vulnerabilities
bomly explain send --enrich --analyze  # and whether your code can reach them
bomly explain send --json              # structured paths for tooling
```

The JSON shape is documented in the [explain schema](../schemas/explain.md).

## Exit codes

The same table as every command ([Exit codes](../EXIT_CODES.md)). Two cases are common here: `5` when the target has no supported manifests, and `4` for a malformed PURL.

## See also

- [scan](scan.md) — the shared target, step, and output flags
- [diff](diff.md) — when the question is "what changed" rather than "why is it here"
- [Interactive TUI](../TUI.md) — explore the same paths with `bomly scan --interactive`
