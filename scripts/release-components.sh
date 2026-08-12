#!/usr/bin/env bash
# release-components.sh — release-train helper for in-repo component modules.
#
# Component modules live under components/<kind>/<name>/ with their own go.mod
# and are versioned with per-module tags of the form:
#
#   components/<kind>/<name>/vX.Y.Z
#
# Usage:
#   ./scripts/release-components.sh            # dry run: print the tag commands
#   ./scripts/release-components.sh --apply    # create + push annotated tags
#
# Dry run (default): for every component module that has commits touching its
# directory since its latest tag (or that has never been tagged), compute the
# next patch version and print the `git tag` / `git push` commands without
# running them.
#
# --apply: create and push those annotated tags, then print the root-module
# `go get` commands that bump the CLI's pins to the freshly tagged versions.
#
# Notes:
# - Only patch bumps are computed. Minor/major component releases are rare and
#   deliberate; tag those by hand.
# - No component modules exist yet; until the first wave PR lands, a dry run
#   prints nothing and exits 0.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

apply=false
if [[ "${1:-}" == "--apply" ]]; then
    apply=true
elif [[ -n "${1:-}" ]]; then
    echo "usage: $0 [--apply]" >&2
    exit 2
fi

# Collect component module directories: components/<kind>/<name>/go.mod.
modules=()
for gomod in components/*/*/go.mod; do
    [[ -f "${gomod}" ]] || continue
    modules+=("$(dirname "${gomod}")")
done

if [[ ${#modules[@]} -eq 0 ]]; then
    echo "no component modules found under components/*/*/ — nothing to release" >&2
    exit 0
fi

bump_cmds=()
for module in "${modules[@]}"; do
    # Latest existing tag for this module, sorted by semantic version.
    last_tag="$(git tag --list "${module}/v*" --sort=-v:refname | head -n 1)"

    if [[ -n "${last_tag}" ]]; then
        # Skip modules without changes since their last tag.
        if git diff --quiet "${last_tag}" HEAD -- "${module}"; then
            echo "# ${module}: no changes since ${last_tag}, skipping"
            continue
        fi
        version="${last_tag##*/v}"
        major="${version%%.*}"
        rest="${version#*.}"
        minor="${rest%%.*}"
        patch="${rest#*.}"
        next="v${major}.${minor}.$((patch + 1))"
    else
        next="v0.1.0"
    fi

    tag="${module}/${next}"
    if ${apply}; then
        git tag -a "${tag}" -m "Release ${tag}"
        git push origin "${tag}"
        echo "tagged and pushed ${tag}"
    else
        echo "git tag -a ${tag} -m 'Release ${tag}'"
        echo "git push origin ${tag}"
    fi
    # Derive the module path from the component's go.mod rather than the
    # filesystem path, so /v2+ major-version modules pin correctly.
    module_path="$(awk '$1 == "module" { print $2; exit }' "${module}/go.mod")"
    if [[ -z "${module_path}" ]]; then
        echo "error: ${module}/go.mod has no module directive" >&2
        exit 1
    fi
    bump_cmds+=("go get ${module_path}@${next}")
done

if [[ ${#bump_cmds[@]} -gt 0 ]]; then
    echo ""
    echo "# root-module pin bumps (run from the repository root, then 'go mod tidy'):"
    for cmd in "${bump_cmds[@]}"; do
        echo "${cmd}"
    done
fi
