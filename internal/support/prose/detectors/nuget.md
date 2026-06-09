## How `nuget` resolves

`nuget-detector` is a **lockfile parser** — it reads NuGet lockfiles directly. Bomly accepts several lockfile formats, preferring the most precise:

1. `packages.lock.json` — central package lockfile (preferred).
2. `*.deps.json` — runtime asset graph for published apps.
3. `project.assets.json` — restore output for SDK-style projects.
4. `packages.config` — legacy direct-only manifest (no transitives).
5. `*.csproj` / `*.fsproj` / `*.vbproj` / `*.vcxproj` — project XML (direct refs only).

| Step | Strategy | Command |
| --- | --- | --- |
| Resolve graph | Lockfile parser | None |

## Network behavior

✅ **Fully offline-safe.** Bomly does not invoke `dotnet`, `nuget`, or any other tool to resolve the graph.

## Prerequisites

- One of the lockfile/project formats listed above, committed to the repository.
- For full transitive coverage: a committed `packages.lock.json`. Enable with `<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>` in your project, then run `dotnet restore --use-lock-file` once.
- No .NET SDK installation is required to scan.

## `--install-first`

`nuget` does **not** support `--install-first` today. Pre-populate `packages.lock.json` (or commit `project.assets.json`) before scanning.

## Examples

### Fix a direct vulnerability

```xml
<PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
```

`dotnet restore --force-evaluate`. Re-scan.

### Pin a transitive vulnerability

Promote the transitive to a top-level `PackageReference` at the fixed version, or use central package management:

```xml
<!-- Directory.Packages.props -->
<ItemGroup>
  <PackageVersion Include="System.Text.Json" Version="8.0.4" />
</ItemGroup>
```

`dotnet restore`. Re-scan.

## Reachability

> **Not yet supported.** Bomly has no .NET reachability analyzer today. `--analyze` produces `not_applicable` for NuGet packages.

## Limitations

- **`packages.config` (old-style)** produces only a flat list (direct deps only). Migrate to `PackageReference` for a full graph.
- **Target frameworks** are recorded as metadata; per-TFM reachability is not computed.
- **Native runtime packages** (`runtime.<rid>.native.*`) are tracked as regular packages; advisory matching uses the NuGet ID.
- **Private feeds** require `NuGet.Config` configured locally; Bomly does not authenticate to NuGet feeds.
