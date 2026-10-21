## How `composer` resolves

`composer-detector` is a **lockfile parser**. It reads `composer.lock` (preferred) or `vendor/composer/installed.json` directly and produces a full transitive graph with Packagist coordinates. No command runs.

| Step | Strategy | Command |
| --- | --- | --- |
| Resolve graph | Lockfile parser | None |

The detector reads one file and runs nothing, so it never uses the network. See [Network and privacy](../../NETWORK.md) for the shared rule.

## Prerequisites

- A committed `composer.lock` for full transitive resolution. The detector handles Composer 2.x lockfiles.
- If only `vendor/composer/installed.json` is present, the detector reads that file instead. Both produce the same graph data.
- No PHP or Composer installation is required to scan.
- For `--install-first`: `composer` on `PATH`.

## Examples

### Fix a direct vulnerability

Raise the range in `composer.json`:

```json
{
  "require": {
    "symfony/http-foundation": "^7.1.4"
  }
}
```

Re-lock with `composer update symfony/http-foundation` and re-scan.

### Pin a transitive vulnerability

Add the transitive package at the top level:

```json
{
  "require": {
    "guzzlehttp/guzzle": ">=7.9.0"
  }
}
```

Re-lock with `composer update guzzlehttp/guzzle` and re-scan.

## `--install-first`

With `--install-first`, Bomly runs `composer install` in the project directory before resolving the graph. That downloads packages from Packagist, or from the repositories your `composer.json` declares, and writes to `vendor/`. Use it on a clean checkout when the lockfile is missing or stale:

```bash
bomly scan --install-first
```

To append flags to that command, repeat `--install-arg`. This requires `--detectors composer-detector`:

```bash
# Production-shaped graph: skip dev dependencies, optimize the autoloader
bomly scan --install-first --detectors composer-detector \
  --install-arg --no-dev --install-arg --optimize-autoloader
```

## Reachability

Bomly has no PHP reachability analyzer. `--analyze` reports `not_applicable` for Composer packages.

## Limitations

- **PEAR-installed packages** are detected by Syft, not by `composer-detector`. PEAR is in maintenance, so expect coverage to follow Syft's.
- **Platform requirements** (`php`, `ext-*`) are recorded as metadata, not as graph edges.
- **Path repositories** (`type: path`) are recorded with their resolved version. The local package's own dependencies come from the local checkout.
- **VCS repositories** with branch refs are tracked by the resolved reference. Advisory matching uses the version Composer records.
