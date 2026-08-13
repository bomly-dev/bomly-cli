# Release Checklist

Use this checklist when publishing a tagged Bomly CLI release.

## Before tagging

- Confirm `main` is green for required checks.
- Run the smoke workflow (or confirm its latest scheduled smoke result is healthy).
- Confirm `cmd/bomly/main.go` contains the intended version after the `Auto Version` workflow.
- Confirm release publishing credentials are configured in GitHub Actions.

## Release workflow

- Run `Auto Version` from `main`, choosing `patch`, `minor`, or `major`.
- `Auto Version` performs the whole lockstep release train in one dispatch,
  as a two-commit flow:
  1. Version-bump commit **A** on `main`: `cmd/bomly/main.go` plus the npm
     wrapper and MCP Registry versions. No root tag yet.
  2. Every component module tag (`components/<kind>/<name>/vX.Y.Z`) at
     commit A. From here, `go get <module>@vX.Y.Z` resolves.
  3. Pin commit **B** on `main` (`[skip ci]`): the root `go.mod`/`go.sum`
     pinned to the just-tagged component versions (`GOWORK=off go get` +
     `go mod tidy`).
  4. The root tag `vX.Y.Z` at commit B, then a `Release` dispatch.
- Why two commits: the root `go.mod` carries **no `replace` directives**, so
  every root tag has resolvable pins and remote
  `go install github.com/bomly-dev/bomly-cli/cmd/bomly@latest` keeps
  working. The component tags must exist before the pins can resolve — the
  Go equivalent of Maven parent-version inheritance: one authoritative
  version, propagated by automation.
- Lockstep invariant (asserted by the workflow and by `verify`): the
  `components/` tree is identical between commits A and B — commit B touches
  only the root `go.mod`/`go.sum`, and component module zips contain only
  their own subtree, so the component tags describe exactly the code that
  ships in the CLI release.
- Every phase is idempotent: rerunning a partially failed `Auto Version`
  completes the missing pieces (component tags already on origin at commit A
  are skipped; a tag on origin at any other commit aborts the run and must
  be resolved on origin first; an already-present pin skips commit B). For
  manual recovery, use
  `./scripts/release-components.sh tag --version vX.Y.Z --commit <A>`,
  `./scripts/release-components.sh pin --version vX.Y.Z` (then commit), and
  check the invariant with
  `./scripts/release-components.sh verify --version vX.Y.Z`. If the run
  failed after the root tag was pushed, dispatch `Release` manually:
  `gh workflow run release.yml --ref vX.Y.Z`.
- Wait for `Release` to finish.
- Run `./scripts/release-components.sh verify --version vX.Y.Z` if you want an
  explicit post-release lockstep check (the workflow already ran it).
- Review the published GitHub release:
  - `bomly` archives exist for Linux, macOS, and Windows on `amd64` and `arm64`.
  - `bomly-lite` archives exist for the same platforms.
  - `SHA256SUMS` exists.
  - `.deb`, `.rpm`, `.apk`, and Arch Linux package artifacts exist.
  - Homebrew, Scoop, and WinGet manifest PRs were opened or updated.
  - The landing-page sync PR updates `/install.sh` and `/install.ps1` from this tag when those scripts changed.

## Verification

Run the checks against the published release tag. Replace `VERSION` in the examples below with the actual release tag, such as `v0.2.0`.

```bash
gh release download VERSION --pattern SHA256SUMS --pattern 'bomly_VERSION_linux_amd64.tar.gz'
sha256sum --check SHA256SUMS --ignore-missing
tar -xzf bomly_VERSION_linux_amd64.tar.gz bomly
./bomly version
```

If practical, verify package-manager installs in clean runners or VMs. The `bomly-dev/tap` Homebrew reference is managed by GoReleaser through `bomly-dev/homebrew-tap`; no manual tap registration is required during release.

```bash
brew install bomly-dev/tap/bomly
dpkg -i bomly_VERSION_linux_amd64.deb
rpm -i bomly_VERSION_linux_amd64.rpm
apk add --allow-untrusted bomly_VERSION_linux_amd64.apk
```

On Windows, validate:

```powershell
winget install Bomly.BomlyCLI
scoop bucket add bomly https://github.com/bomly-dev/scoop-bucket
scoop install bomly
```

## Publish and rollback

- Merge package-manager PRs after their generated manifests pass review.
- Confirm the landing-page docs sync PR opened.
- If a release must be pulled, delete or unpublish the GitHub Release to trigger the automatic yanking workflow.
- Close Homebrew and Scoop package-manager PRs that reference the bad tag, then tag a replacement patch release when appropriate.
- For WinGet, confirm the release lifecycle workflow either skipped cleanup because no version manifest existed or opened a removal PR against `microsoft/winget-pkgs`.
