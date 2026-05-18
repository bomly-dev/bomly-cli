## Scan your Maven or Gradle project

Bomly has native detectors for Maven (`maven-detector`) and Gradle (`gradle-detector`). Both produce a full transitive dependency graph with `groupId:artifactId:version` coordinates and Maven scopes (`compile`, `runtime`, `test`, `provided`).

```bash
bomly scan --path .
```

The Maven detector parses `pom.xml` directly. The Gradle detector parses `gradle.lockfile`. If your Gradle project does not commit a lock file, generate one with `./gradlew dependencies --write-locks` first.

## Prerequisites

### Maven

- A valid `pom.xml` at every module root. Multi-module reactors are supported; each `pom.xml` is its own subproject.
- `mvn` on `PATH` if you pass `--install-first` (Bomly will run `mvn dependency:list -DincludeScope=runtime` to refresh the resolved graph).
- Parent POMs and BOM-imported managed dependencies are resolved transitively from your local repository (`~/.m2/repository`). If a parent POM is not cached, set up your settings so `mvn install` works first.
- Private repositories: configure `~/.m2/settings.xml` as usual. Bomly does not authenticate to repositories itself.

### Gradle

- A committed `gradle.lockfile` (Gradle 6+ lockfile format) for full transitive coverage.
- `build.gradle` or `build.gradle.kts`. Bomly treats every Gradle module under `settings.gradle` as a subproject.
- Without a lockfile, Bomly falls back to Syft, which parses `build.gradle` but cannot resolve transitive versions.

## Reachability — what `jvmreach` tells you

The JVM analyzer is **Tier-3 (package)**. It walks `.java`, `.kt`, `.kts`, `.scala`, `.groovy` source files under the project root, parses top-of-file `import` statements, and maps fully-qualified-name prefixes to Maven coordinates via a curated longest-prefix map (in `internal/analyzers/jvmreach/prefixmap.go`).

Importantly, "unreachable" is not "safe" — reflection, `ServiceLoader`, Spring component scanning, OSGi, JPMS dynamic layers, and annotation processors are invisible. See [REACHABILITY.md](../../REACHABILITY.md#unreachable-is-not-safe).

```bash
bomly scan --enrich --audit --reachability --fail-on high --fail-on reachable
```

If a missing prefix produces a false-negative for a direct import, add the mapping to `prefixmap.go` (one-line PR).

## Examples

### Fix a direct vulnerability

Bump the version in your `pom.xml`:

```xml
<dependency>
  <groupId>com.fasterxml.jackson.core</groupId>
  <artifactId>jackson-databind</artifactId>
  <version>2.17.1</version>
</dependency>
```

Or in Gradle:

```kotlin
implementation("com.fasterxml.jackson.core:jackson-databind:2.17.1")
```

Re-lock (Gradle) and re-scan.

### Pin a transitive vulnerability (Maven)

Use `<dependencyManagement>` to override the version a transitive dep resolves to:

```xml
<dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.17.1</version>
    </dependency>
  </dependencies>
</dependencyManagement>
```

### Pin a transitive vulnerability (Gradle)

Use a resolution strategy in your root `build.gradle.kts`:

```kotlin
configurations.all {
  resolutionStrategy.eachDependency {
    if (requested.group == "com.fasterxml.jackson.core" &&
        requested.name  == "jackson-databind") {
      useVersion("2.17.1")
    }
  }
}
```

Re-run `./gradlew dependencies --write-locks` and re-scan.

## Limitations

- **System-scoped Maven dependencies** (`<scope>system</scope>`) are recorded but not classified by ecosystem — Bomly cannot follow `<systemPath>` to a Maven coordinate.
- **Classifier-only differences** are collapsed to a single graph node; if two artifacts differ only by classifier (e.g. `linux-x86_64` vs. `macos-aarch64`), reachability annotates them identically.
- **Dynamic versions** (`+`, `latest.release`, version ranges) are resolved at lock-time, not by Bomly. A stale `gradle.lockfile` will not pick up new advisories until you re-lock.
- **Gradle composite builds** (`includeBuild`) are scanned per-included-build; cross-build dependency edges are best-effort.
- **JVM bytecode analysis** is not performed. `jvmreach` is source-based; pre-built JAR artifacts in a project are skipped.
