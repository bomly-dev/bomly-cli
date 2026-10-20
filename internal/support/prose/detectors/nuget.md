## How `nuget` resolves

`nuget-detector` is a **lockfile parser**. It reads NuGet lockfiles and project files directly. When several are present it prefers the most precise one:

| Priority | File | What it gives |
| --- | --- | --- |
| 1 | `packages.lock.json` | Central package lockfile with the full transitive graph |
| 2 | `*.deps.json` | Runtime asset graph for published apps |
| 3 | `project.assets.json` | Restore output for SDK-style projects |
| 4 | `packages.config` | Legacy manifest, direct dependencies only |
| 5 | `*.csproj`, `*.fsproj`, `*.vbproj`, `*.vcxproj` | Project XML, direct references only |

The detector reads files and runs nothing, so it never uses the network. See [Network and privacy](../../NETWORK.md) for the shared rule.

## Prerequisites

- One of the files above, committed to the repository.
- For full transitive coverage: a committed `packages.lock.json`. Enable it with `<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>` in your project, then run `dotnet restore --use-lock-file` once.
- No .NET SDK installation is required to scan.

## Examples

### Fix a direct vulnerability

Raise the version in the project file:

```xml
<PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
```

Re-lock with `dotnet restore --force-evaluate` and re-scan.

### Pin a transitive vulnerability

Promote the transitive package to a top-level `PackageReference` at the fixed version, or use central package management in `Directory.Packages.props`:

```xml
<ItemGroup>
  <PackageVersion Include="System.Text.Json" Version="8.0.4" />
</ItemGroup>
```

Re-lock with `dotnet restore` and re-scan.

## `--install-first`

Not supported. Commit `packages.lock.json` or `project.assets.json` before scanning.

## Reachability

Bomly has no .NET reachability analyzer. `--analyze` reports `not_applicable` for NuGet packages.

## Limitations

- **`packages.config` projects** produce a flat list of direct dependencies only. Migrate to `PackageReference` for a full graph.
- **Target frameworks** are recorded as metadata. Per-framework reachability is not computed.
- **Native runtime packages** (`runtime.<rid>.native.*`) are tracked as regular packages. Advisory matching uses the NuGet ID.
- **Private feeds** need a local `NuGet.Config`. Bomly does not authenticate to NuGet feeds.
