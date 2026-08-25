# ADR-0029: Shared helper code lives in bomly-sdk subpackages, not CLI-internal packages

- **Date:** 2026-08-12
- **Status:** Accepted

The former `internal/system`, `internal/matchers/cache`, and `internal/testutil` helpers (plus subprocess logging and detector/matcher helper functions) moved to `bomly-sdk` subpackages: `system`, `filecache`, `logkit`, `detectorkit`, `matcherkit`, and `testkit`. Two forces drove this:

- **One helper surface for both sides of the plugin boundary.** The component-extraction program moved external-integration built-ins into their own `bomly-plugin-*` module repositories, and external plugin authors implement the same SDK contracts. Both need the same bounded filesystem/subprocess ops, file cache, and logging discipline; keeping the helpers CLI-internal would have forced extracted components and plugins to copy them.
- **The SDK stays lightweight.** The helper subpackages depend on the standard library plus zap only, so importing them does not drag CLI dependencies into plugin builds.

Do not reintroduce CLI-internal copies of these helpers; new shared helper code goes into the appropriate SDK subpackage.
