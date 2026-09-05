#!/usr/bin/env sh
#
# Print a digest of the repository state that `make verify` verifies.
#
# The stamp records this digest; .githooks/pre-push recomputes it and refuses
# a push when the two differ. It replaces a list of file globs compared by
# modification time, which was wrong in three ways: the list named 541 of the
# repository's 816 tracked files, so editing a shell script, a workflow, an
# npm wrapper source or a nested testdata fixture left the stamp looking
# fresh; a deleted file simply vanished from the list, lowering nothing; and a
# restored mtime is indistinguishable from an unchanged file.
#
# Git decides what the repository contains, rather than a hand-written walk
# that has to be kept in step with the tree. HEAD plus the full diff against
# it covers every tracked file, staged and unstaged alike, including deletions
# and newly added files. Untracked files are deliberately excluded: they are
# not part of a push, which is the same rule the previous check documented.
set -eu

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

digest() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256
	else
		openssl dgst -sha256
	fi
}

{
	git rev-parse HEAD 2>/dev/null || echo "no-head"
	git diff HEAD --binary 2>/dev/null || git diff --binary
} | digest | tr -d ' -' | tr -d '\n'
echo
