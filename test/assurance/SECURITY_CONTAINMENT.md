# Filesystem containment assurance

This assurance slice checks where Bomly reads and writes files when it handles
repository content and generated artifacts. The tests focus on boundaries that
must remain stable.

## Behaviors under test

| Boundary | Expected behavior | Main coverage |
|---|---|---|
| Git materialization | A requested commit is copied to a temporary checkout without changing the source repository | `TestCloneTempMaterializesRequestedCommitWithoutChangingSource` |
| Repository symlinks | Materialization preserves links, while recursive discovery does not follow linked directories | `TestMaterializeLocalRefKeepsRepositorySymlinksAsSymlinks`, `TestPlanSubprojectsRecursiveDoesNotFollowSymlinkedDirs` |
| Plugin ZIP extraction | Absolute paths, parent traversal, and symbolic links cannot write outside the extraction directory | `TestExtractZipArchiveRejectsEscapingAndSymlinkEntries` |
| Plugin tar extraction | Absolute paths, parent traversal, links, and special files cannot write outside the extraction directory | `TestExtractTarGzArchiveRejectsEscapingLinksAndSpecialFiles` |
| Automatic baseline | The conventional project baseline is resolved for filesystem and materialized Git targets, and invalid documents fail closed | `TestResolversForTargetHandlesOptionalRequiredAndURLPolicies`, `TestLoadRejectsMalformedAndUnsupportedDocuments` |
| Baseline replacement | A rejected replacement leaves the existing baseline intact | `TestWriteAtomicValidationFailurePreservesExistingDocument` |
| Cache filename | Untrusted package identity text is hashed before it becomes a cache filename | `TestSDKContractFileCachePermissionsAndContainment` (local contract in `test/assurance/sdk_contract_test.go`; authoritative suite upstream in `bomly-dev/bomly-sdk` `filecache/cache_test.go`) |
| Generated output | Output is written only to the destination the user selected | `TestWriteOutputDocumentWritesOnlyToExplicitDestination` |

Explicit paths are authority boundaries, not project sandboxes. A user may
choose an output, cache, config, or baseline path outside the scanned project.
Repository config files are not loaded automatically, so repository content
cannot choose those paths without the user explicitly selecting that config.

The tests live beside the owning packages so they can exercise the real
implementation without exporting security helpers. Parser fuzzing remains
listed in [PARSER_FUZZING.md](PARSER_FUZZING.md).
