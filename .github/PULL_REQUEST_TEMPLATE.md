<!--
Thanks for contributing to Bomly! Please complete the sections below.
Commit messages follow Conventional Commits (feat:, fix:, docs:, refactor:, ...),
since they drive the automated release version bump.
-->

## Summary

<!-- What does this change do, and why? Link any related issue (e.g. Closes #123). -->

## Changes

<!-- Bullet the notable changes. -->

-

## Checklist

- [ ] `make test` passes.
- [ ] `make lint` passes.
- [ ] `make generate` run and committed if I changed `internal/config/config.go`, `internal/output/*`, `sdk/catalog.go`, `sdk/support_matrix.go`, or `internal/registry/support.go`.
- [ ] Smoke goldens regenerated (`make smoke ARGS="-update"`) and committed if behavior changed.
- [ ] Docs updated (feature page, `docs/ARCHITECTURE.md`, `CLAUDE.md`/`AGENTS.md`) where relevant.

### For a new user-visible feature (new flag / component / pipeline stage)

<!-- Delete this section if not applicable. See the Feature Checklist in CLAUDE.md. -->

- [ ] CLI flag, config field, and validation wired up.
- [ ] Reachable from the matching MCP tool.
- [ ] Surfaced in `bomly plugin` listing (for a new component kind).
- [ ] Smoke test added against a pinned public repo.
