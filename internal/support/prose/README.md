# Handwritten prose for generated docs

The files in this tree are embedded into the generated detector, matcher,
and auditor pages by `internal/support/component_docs.go`. Each generated
page starts with a fact table that `make generate` rebuilds from the
registry. The prose file is appended below that table, unchanged.

## Layout

```
prose/
  README.md
  detectors/
    <package-manager>.md   # npm.md, pnpm.md, gomod.md, pip.md, syft.md
  matchers/
    <matcher-name>.md      # osv.md, grype.md, depsdev-license-matcher.md
  auditors/
    <auditor-name>.md      # vulnerability.md, license.md, package.md
```

A detector file is named after the package manager, not the ecosystem,
because every package manager gets its own page: `npm/npm.md`,
`npm/pnpm.md`, and `npm/yarn.md` all sit under the `npm` ecosystem. The
name must match the package manager's name in the support registry.
`syft.md` is the one exception: it is the shared page for every package
manager that only Syft covers. A matcher or auditor file is named after
the component's descriptor name.

A page with no prose file still gets its fact table. A prose file for a
name the registry does not know is silently ignored, so check the
generated output after adding one.

## Section order

Every detector page uses the same H2 order so readers can compare pages:

| Section | Content |
| --- | --- |
| How `<name>` resolves | The strategies the chain tries, as a table of strategy, command, and working directory. One line on whether the command can use the network. |
| Prerequisites | Tools on `PATH`, required files, version floors, environment variables. |
| Examples | Real `bomly` commands, plus how to fix a direct and a transitive finding. |
| Ecosystem extras | Only when they apply, in this order: workspaces, vendored mode, `--install-first`, source details, reachability. |
| Limitations | One sentence per limitation, naming the consequence. |
| Configuration | The detector's config block, when it has one. |

Matcher pages use: What `<name>` does, When it runs, Network, Output
fields, Examples, Limitations. Auditor pages use: What the `<name>`
auditor does, Options, Examples, Limitations.

Skip a section that does not apply. Do not pad.

## Voice

- Plain English. Sentences under about 25 words. No idioms.
- Sentence-case headings. US spelling.
- Put every flag, filename, environment variable, and command in inline
  code.
- Limitations are plain statements. "X is not supported." beats "X may
  not work in all cases."
- State a shared rule once and link to its home. The network rule lives in
  `docs/NETWORK.md`. The reachability caveat lives in
  `docs/REACHABILITY.md`. A detector page says each in one sentence with a
  link, never in a repeated block.
- No Go identifiers, package paths, or issue numbers. The reader is a
  Bomly user, not a contributor.

## Workflow

1. Edit or add a file under `prose/detectors/`, `prose/matchers/`, or
   `prose/auditors/`.
2. Run `make generate`.
3. Check the matching page under `docs/detectors/<ecosystem>/`,
   `docs/matchers/`, or `docs/auditors/`.
4. Commit the prose file and the regenerated docs together.

The whole tree is embedded with `//go:embed all:prose`, so adding a file
needs no generator change.
