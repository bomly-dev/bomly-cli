# Bomly Explain JSON Schema Reference

Complete reference for the `bomly explain` JSON output.

## Document

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | `string` | |
| `command` | `string` | |
| `project` | [`ProjectDescriptor`](#projectdescriptor) | |
| `query` | [`ExplainQuery`](#explainquery) | |
| `dependency` | [`PackageRef`](#packageref) | |
| `paths` | Array<[`Path`](#path)> | |
| `findings` | Array<[`AuditFinding`](#auditfinding)> | |
| `audit_summary` | [`AuditSummary`](#auditsummary) | |
| `targets` | Array<[`ExplainTargetResponse`](#explaintargetresponse)> | |
| `metadata` | [`Metadata`](#metadata) | |

## Types

### `AuditFinding`

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | |
| `kind` | `string` | |
| `severity` | `string` | |
| `package` | [`PackageRef`](#packageref) | |
| `title` | `string` | |
| `reasons` | Array<`string`> | |
| `source` | `string` | |

### `AuditSummary`

| Field | Type | Description |
|-------|------|-------------|
| `critical` | `integer` | |
| `high` | `integer` | |
| `medium` | `integer` | |
| `low` | `integer` | |
| `unknown` | `integer` | |
| `total` | `integer` | |

### `ExplainQuery`

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | |

### `ExplainTargetResponse`

| Field | Type | Description |
|-------|------|-------------|
| `project` | [`ProjectDescriptor`](#projectdescriptor) | |
| `detector` | `string` | |
| `dependency` | [`PackageRef`](#packageref) | |
| `paths` | Array<[`Path`](#path)> | |
| `findings` | Array<[`AuditFinding`](#auditfinding)> | |
| `audit_summary` | [`AuditSummary`](#auditsummary) | |

### `LicenseRef`

| Field | Type | Description |
|-------|------|-------------|
| `value` | `string` | |
| `spdxExpression` | `string` | |
| `type` | `string` | |

### `Metadata`

| Field | Type | Description |
|-------|------|-------------|
| `duration_ms` | `integer` | |

### `PackageRef`

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | |
| `version` | `string` | |
| `scope` | `string` | |
| `purl` | `string` | |
| `id` | `string` | |
| `metadata` | `object` | |
| `licenses` | Array<[`LicenseRef`](#licenseref)> | |

### `Path`

| Field | Type | Description |
|-------|------|-------------|
| `Relationship` | `string` | |
| `Packages` | Array<[`PackageRef`](#packageref)> | |
| `IntroducedVia` | `string` | |
| `cyclic` | `boolean` | |
| `cycle_to` | `string` | |

### `ProjectDescriptor`

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | |
| `path` | `string` | |
| `ecosystem` | `string` | |
| `package_manager` | `string` | |

