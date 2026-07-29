# Public evidence catalog

This directory maps Bomly claims to repeatable tests and checked-in evidence.
It is not a second test suite. The catalog points to the smoke tests, focused
unit tests, fixtures, and manually started assurance workflows that already
own each behavior.

Run the catalog check from the repository root:

```sh
make evidence
```

Show one case and its exact reproduction command:

```sh
make evidence CASE=graph-npm
```

The checker verifies that:

- every remote Git input has a full commit revision;
- every fixture, workflow, and result file has the recorded SHA-256 checksum;
- every case says what it proves and what it does not prove;
- case IDs are unique and stable.

## Evidence levels

- `deterministic` uses checked-in inputs or local services and should produce
  the same normalized result.
- `pinned-input` uses a public repository revision. Package-manager tools or
  registries can still affect build-tool-backed resolution.
- `live-service` combines a pinned project with current advisory data. It is a
  dated observation because advisory services change.
- `manual-assurance` starts a GitHub Actions workflow and stores the detailed
  run report as a workflow artifact.

The catalog schema belongs only to repository assurance metadata. It does not
change Bomly's CLI, MCP, SDK, or plugin schemas.
