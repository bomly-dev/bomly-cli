# Hand-written prose for generated docs

The files in this tree are embedded into the auto-generated detector and
matcher pages by `internal/support/component_docs.go`. The structured
fact tables on each page are regenerated from the registry on every
`make generate`; the prose here is the human-written explanation that
goes beneath those tables.

## Layout

```
prose/
  detectors/
    <ecosystem>.md   # e.g. go.md, npm.md, maven.md
  matchers/
    <name>.md        # e.g. osv.md, grype.md
```

`<ecosystem>` matches `sdk.Ecosystem` values (`go`, `npm`, `maven`,
`python`, …). `<name>` matches `sdk.MatcherDescriptor.Name`
(`osv`, `grype`, `depsdev-license-matcher`, …).

## Template

Each page is structured like a Veracode "Find vulnerabilities in X" page:
brief intro, prerequisites, examples, limitations. Default H2 spine:

```markdown
## Scan your project

[Prerequisites: toolchain version floor, env vars, lockfile/manifest
the detector needs.]

[The exact `bomly scan` command for the most common case.]

[One or two flag variants worth highlighting.]

## Prerequisites

[Bullet list: version floors, required tools on PATH, env vars,
manifest filenames that must exist.]

## Examples

[Real `bomly scan` invocations users can paste.]

## Limitations

[Blunt statements of what the detector or matcher cannot do.
One sentence per limitation, naming the consequence.]
```

Skip any section that's truly not applicable. Don't pad.

## Voice

- Imperative H2s ("Scan your project", not "Scanning").
- Short sentences. Active voice. No marketing.
- Inline-code every flag, filename, env var, command.
- Limitations: declarative, no hedging. "X is not supported." beats
  "X may not work in all cases."

## Workflow

1. Edit or add a file under `prose/detectors/` or `prose/matchers/`.
2. Run `make generate`.
3. The new content appears at the bottom of the corresponding
   `docs/detectors/ecosystems/<name>.md` or `docs/matchers/<name>.md`.
4. Commit both the prose file and the regenerated docs.

The embed is done via `//go:embed all:prose` in
`internal/support/component_docs.go`, so adding a new file requires no
generator changes.
