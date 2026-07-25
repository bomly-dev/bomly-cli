# Filesystem containment assurance

This assurance slice checks where Bomly reads and writes files when it handles
repository content and generated artifacts. The tests focus on boundaries that
must remain stable:

- a requested Git ref is materialized in a temporary checkout without changing
  the source repository;
- repository symlinks remain symlinks during materialization, and recursive
  project discovery does not follow symlinked directories;
- plugin ZIP and tar archives cannot use absolute paths, parent traversal,
  links, or special files to write outside their temporary extraction
  directory;
- automatic baseline selection uses the conventional path inside the
  materialized target, malformed baseline documents fail closed, and baseline
  replacement does not expose partial data;
- untrusted package identity text is hashed before it becomes a cache filename;
- generated output is written only to the path the user explicitly selected.

Explicit paths are authority boundaries, not project sandboxes. A user may
choose an output, cache, config, or baseline path outside the scanned project.
Repository config files are not loaded automatically, so repository content
cannot choose those paths without the user explicitly selecting that config.

The tests live beside the owning packages so they can exercise the real
implementation without exporting security helpers. Parser fuzzing remains
listed in [PARSER_FUZZING.md](PARSER_FUZZING.md).
