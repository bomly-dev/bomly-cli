#!/usr/bin/env bash
# Points this checkout's build at a local bomly-sdk checkout, or back at the
# released version go.mod pins, through an ignored go.work.
#
#   scripts/sdk-workspace.sh on [<sdk-dir>]   # default ../bomly-sdk; a worktree path works
#   scripts/sdk-workspace.sh off              # back to the go.mod pin
#   scripts/sdk-workspace.sh status           # which SDK the build resolves
#
# go.work is never committed (.gitignore; CI fails if it is tracked), so the
# released pin in go.mod stays the only thing a pull request ships.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

status() {
	local dir version
	IFS='|' read -r version dir < <(go list -m -f '{{.Version}}|{{.Dir}}' github.com/bomly-dev/bomly-sdk)
	if [ -f go.work ] && [ -z "$version" ]; then
		echo "bomly-sdk: local checkout $dir (go.work)"
	else
		echo "bomly-sdk: $version (go.mod pin)"
	fi
}

case "${1:-status}" in
on)
	sdk="${2:-$root/../bomly-sdk}"
	if [ ! -f "$sdk/go.mod" ] || ! grep -q '^module github.com/bomly-dev/bomly-sdk$' "$sdk/go.mod"; then
		echo "no bomly-sdk checkout at $sdk; pass its path" >&2
		exit 2
	fi
	sdk="$(cd "$sdk" && pwd)"
	rm -f go.work go.work.sum
	go work init . "$sdk"
	status
	;;
off)
	rm -f go.work go.work.sum
	status
	;;
status)
	status
	;;
*)
	echo "usage: $0 on [<sdk-dir>] | off | status" >&2
	exit 2
	;;
esac
