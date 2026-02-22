# Plugin Development Guide

This guide covers how to build plugins for Bomly.

---

## Naming Convention

Plugin executables must be named `bomly-<name>`:

```
bomly-npm
bomly-pip
bomly-custom-auditor
```

---

## Discovery

Bomly discovers plugins from two locations in priority order:

1. `~/.bomly/plugins/bomly-*` — user-installed plugins (highest priority)
2. `PATH` — system-wide or project-local plugins

User-installed plugins take precedence so an explicit local install wins over ambient system state.

---

## Handshake

Every plugin must support the `--bomly-plugin-info` flag, which prints JSON metadata to stdout:

```json
{
  "name": "example",
  "version": "0.1.0",
  "protocol": "v1",
  "commands": [
    {
      "name": "deps",
      "summary": "Resolve dependency graph",
      "stage": "detect"
    }
  ]
}
```

### Fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Plugin name (matches the `bomly-<name>` executable suffix) |
| `version` | Yes | Plugin version (semver) |
| `protocol` | Yes | Must be `"v1"` |
| `commands` | Yes | Array of command descriptors |
| `commands[].name` | Yes | Subcommand name |
| `commands[].summary` | Yes | One-line description |
| `commands[].stage` | No | Pipeline stage: `pre-resolve`, `detect`, `audit`, or `post-resolve`. Defaults to `detect` |

---

## JSON Envelope Protocol

All stages use a typed JSON envelope over stdio:

### Request (stdin)

```json
{
  "protocol": "bomly-plugin-v1",
  "stage": "detect",
  "payload": { ... }
}
```

### Response (stdout)

```json
{
  "protocol": "bomly-plugin-v1",
  "stage": "detect",
  "payload": { ... }
}
```

---

## Stages

### Pre-Resolve

Runs before dependency detection. Use cases: install dependencies, prepare the build environment.

**Input payload:**

```json
{
  "execution_target": { "kind": "filesystem", "location": "/path/to/project" },
  "subprojects": [...],
  "config": { ... }
}
```

**Output payload:**

```json
{
  "success": true,
  "message": "Dependencies installed"
}
```

### Detect

Resolves dependency graphs. This is the primary plugin stage.

**Input payload:**

```json
{
  "subproject": { "path": "/path/to/project", "ecosystem": "npm" },
  "execution_target": { "kind": "filesystem", "location": "/path/to/project" },
  "config": { ... }
}
```

**Output payload:**

```json
{
  "graph": {
    "packages": [
      { "name": "lodash", "version": "4.17.21", "ecosystem": "npm", "purl": "pkg:npm/lodash@4.17.21" }
    ],
    "edges": [
      { "from": 0, "to": 1 }
    ]
  }
}
```

### Audit

Analyzes a resolved dependency graph for vulnerabilities or risks.

**Input payload:**

```json
{
  "graph": { ... },
  "packages": [
    { "name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21" }
  ]
}
```

**Output payload:**

```json
{
  "findings": [
    {
      "id": "GHSA-xxxx-yyyy-zzzz",
      "title": "Prototype Pollution in lodash",
      "severity": "high",
      "package": { "name": "lodash", "version": "4.17.21" }
    }
  ]
}
```

### Post-Resolve

Runs after all detection, auditing, and enrichment. Use cases: upload results, generate reports, enforce policies.

**Input payload:**

```json
{
  "container": { ... }
}
```

**Output payload:**

```json
{
  "success": true,
  "message": "Results uploaded",
  "artifacts": ["report.pdf"]
}
```

---

## Environment Variables

Bomly sets these environment variables for every plugin invocation:

| Variable | Value |
|----------|-------|
| `BOMLY_PROTOCOL` | `v1` |
| `BOMLY_CORE_VERSION` | Core CLI version (semver) |
| `BOMLY_CWD` | Absolute path to the working directory |
| `BOMLY_CONFIG` | Path to the active config file |

---

## Error Handling

- Non-zero exit codes are treated as plugin errors
- Stderr output is captured and logged by the core
- Plugin errors are non-fatal for the scan — the engine skips the plugin and continues

---

## Testing Your Plugin

1. Verify the handshake:

```bash
./bomly-myplugin --bomly-plugin-info | jq .
```

2. Test with Bomly:

```bash
bomly scan              # should discover your plugin
bomly plugin list       # should show your plugin
```

3. Test the envelope protocol manually:

```bash
echo '{"protocol":"bomly-plugin-v1","stage":"detect","payload":{...}}' | ./bomly-myplugin deps
```

---

## Example: Minimal Detect Plugin (Bash)

```bash
#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "--bomly-plugin-info" ]]; then
  cat <<'EOF'
{"name":"hello","version":"0.1.0","protocol":"v1","commands":[{"name":"deps","summary":"Hello world detector","stage":"detect"}]}
EOF
  exit 0
fi

# Read envelope from stdin, emit a graph
cat <<'EOF'
{"protocol":"bomly-plugin-v1","stage":"detect","payload":{"graph":{"packages":[],"edges":[]}}}
EOF
```
