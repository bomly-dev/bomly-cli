# ADR-0005: Reachability analyzers derive local hierarchy closures

- **Date:** 2026-06-01
- **Status:** Accepted

Tier-3 source analyzers discover local workspace and module hierarchies from declarative project files while the consolidated detector graph remains the source of truth for external package edges. `jsreach` follows package-name imports across npm, Yarn, and pnpm workspace members. `jvmreach` follows source namespace imports across Maven `<modules>` and standard Gradle `include` declarations. This keeps hierarchy traversal automatic, avoids package-manager installation or network activity during reachability analysis, and prevents unused sibling projects from widening the reachable set.
