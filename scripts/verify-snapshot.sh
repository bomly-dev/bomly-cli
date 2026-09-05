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
# that has to be kept in step with the tree.
#
# The digest covers the index (blob hashes for every tracked path) plus the
# worktree's diff against it, which together pin the exact content of every
# tracked file, including deletions and newly staged files. Untracked files
# are deliberately excluded: they are not part of a push, which is the same
# rule the previous check documented.
#
# It deliberately does NOT include HEAD. Committing moves content across the
# HEAD boundary without changing a byte of it, so folding HEAD in invalidated
# a verification that was still perfectly valid -- and a gate that fails on
# `git commit` is one that teaches people to pass --no-verify, which is worse
# than no gate at all. Neither `git ls-files -s` nor `git diff` is affected by
# a commit, so this holds across one and still changes on any real edit.
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
	git ls-files -s
	git diff --binary
} | digest | tr -d ' -' | tr -d '\n'
echo
