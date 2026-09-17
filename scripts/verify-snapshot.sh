#!/usr/bin/env sh
#
# Print a digest of the repository content that `make verify` verifies.
#
# The stamp records this digest; .githooks/pre-push recomputes it and refuses
# a push when the two differ. It replaced a list of file globs compared by
# modification time, which was wrong in three ways: the list named 541 of the
# repository's 816 tracked files, so editing a shell script, a workflow, an
# npm wrapper source or a nested testdata fixture left the stamp looking
# fresh; a deleted file simply vanished from the list, lowering nothing; and a
# restored mtime is indistinguishable from an unchanged file. Each reported a
# passing verification for work that was never tested.
#
# The digest is the git tree of everything in the worktree that .gitignore
# does not exclude, built in a throwaway index so neither the real index nor
# HEAD is touched or consulted.
#
# Reading content rather than git's bookkeeping is the whole point. Two
# earlier attempts folded in HEAD, and then the index, and both invalidated a
# verification that was still perfectly valid: `git add` and `git commit` move
# content across those boundaries without changing a byte of it. A gate that
# fails on staging or committing is one that teaches people to pass
# --no-verify, which is worse than no gate at all. What survives here changes
# when a file's bytes change, when a file appears, and when one is deleted --
# and at no other time.
#
# Untracked files count, unless ignored: a new source file is part of what a
# push delivers, whether or not it has been added yet. Build outputs and the
# stamp itself are ignored, so neither perturbs the digest.
set -eu

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

index=$(mktemp -u "${TMPDIR:-/tmp}/bomly-verify-index.XXXXXX")
trap 'rm -f "$index"' EXIT INT TERM

GIT_INDEX_FILE="$index" git add -A
GIT_INDEX_FILE="$index" git write-tree
