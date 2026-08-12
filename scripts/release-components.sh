#!/usr/bin/env bash
# release-components.sh — release-train helper for in-repo component modules.
#
# Component modules live under components/<kind>/<name>/ with their own go.mod
# and are versioned in LOCKSTEP with the CLI: every component module is tagged
# at the CLI's release version, whether or not it changed. One version number
# describes the whole repository; empty component releases are deliberate and
# accepted in exchange for that simplicity.
#
#   components/<kind>/<name>/vX.Y.Z   (X.Y.Z = the CLI release version)
#
# Usage:
#   ./scripts/release-components.sh                     # dry run at the latest CLI tag
#   ./scripts/release-components.sh --version v1.2.3    # dry run at an explicit version
#   ./scripts/release-components.sh --apply             # create + push the tags
#
# Dry run (default): resolve the release version (latest root v* tag unless
# --version is given), then print the `git tag` / `git push` commands for every
# component module missing that tag, plus the root-module `go get` pin bumps.
#
# --apply: create and push those annotated tags. Modules whose tag already
# exists ON ORIGIN are skipped (the remote is the source of truth, so a rerun
# after a partial failure pushes any local-only tag instead of skipping it),
# making the script idempotent. The root pin bumps are printed, not executed —
# they land through a normal PR.
#
# Intended flow: run after the CLI release tag exists (auto-version.yml), then
# open the pin-bump PR.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

apply=false
version=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --apply)
            apply=true
            shift
            ;;
        --version)
            version="${2:-}"
            if [[ -z "${version}" ]]; then
                echo "error: --version requires a value (vX.Y.Z)" >&2
                exit 2
            fi
            shift 2
            ;;
        *)
            echo "usage: $0 [--apply] [--version vX.Y.Z]" >&2
            exit 2
            ;;
    esac
done

if [[ -z "${version}" ]]; then
    # Latest CLI release tag. Root tags are plain vX.Y.Z; component tags carry
    # a path prefix, so this glob cannot match them.
    version="$(git tag --list 'v[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname | head -n 1)"
    if [[ -z "${version}" ]]; then
        echo "error: no CLI release tag found; pass --version vX.Y.Z" >&2
        exit 1
    fi
fi

if [[ ! "${version}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "error: version ${version} is not of the form vX.Y.Z" >&2
    exit 1
fi

# Component tags must point at the CLI release commit, not HEAD: the local
# branch may have advanced past the release tag (or --version may select an
# older release), and lockstep means the component tag captures exactly the
# code that shipped in that CLI release.
release_commit="$(git rev-parse -q --verify "refs/tags/${version}^{commit}")" || {
    echo "error: release tag ${version} not found locally; fetch tags first (git fetch --tags)" >&2
    exit 1
}

# Collect component module directories from the RELEASE COMMIT, not the
# working tree: with --version selecting an older release, HEAD's set of
# components/<kind>/<name>/go.mod files may differ from what shipped.
modules=()
while IFS= read -r gomod; do
    modules+=("$(dirname "${gomod}")")
done < <(git ls-tree -r --name-only "${release_commit}" -- components/ |
    grep -E '^components/[^/]+/[^/]+/go\.mod$' || true)

if [[ ${#modules[@]} -eq 0 ]]; then
    echo "no component modules found under components/*/*/ — nothing to release" >&2
    exit 0
fi

echo "# release version: ${version} (commit ${release_commit})"
bump_cmds=()
for module in "${modules[@]}"; do
    tag="${module}/${version}"
    # Derive the module path from the go.mod AS OF THE RELEASE COMMIT (not the
    # checkout), so /v2+ major-version modules pin correctly and the pin
    # commands describe released code by construction.
    module_path="$(git show "${release_commit}:${module}/go.mod" |
        awk '$1 == "module" { print $2; exit }')"
    if [[ -z "${module_path}" ]]; then
        echo "error: ${module}/go.mod at ${version} has no module directive" >&2
        exit 1
    fi
    bump_cmds+=("go get ${module_path}@${version}")

    # Idempotent reruns must survive a partial failure between local tag
    # creation and push: the REMOTE is the source of truth for "already
    # released". A local-only tag is verified against the release commit
    # (a stale local tag is an error, never silently pushed) and pushed.
    if [[ -n "$(git ls-remote --tags origin "refs/tags/${tag}")" ]]; then
        echo "# ${module}: ${tag} already on origin, skipping"
        continue
    fi
    local_tag_commit="$(git rev-parse -q --verify "refs/tags/${tag}^{commit}" || true)"
    if [[ -n "${local_tag_commit}" && "${local_tag_commit}" != "${release_commit}" ]]; then
        echo "error: local tag ${tag} points at ${local_tag_commit}, not release commit ${release_commit}; delete it (git tag -d ${tag}) and rerun" >&2
        exit 1
    fi
    if ${apply}; then
        if [[ -z "${local_tag_commit}" ]]; then
            git tag -a "${tag}" -m "Release ${tag}" "${release_commit}"
        else
            echo "# ${module}: local tag ${tag} exists but was never pushed, pushing"
        fi
        git push origin "${tag}"
        echo "tagged and pushed ${tag} at ${release_commit}"
    else
        if [[ -z "${local_tag_commit}" ]]; then
            echo "git tag -a ${tag} -m 'Release ${tag}' ${release_commit}"
        else
            echo "# ${module}: local tag ${tag} exists but is not on origin"
        fi
        echo "git push origin ${tag}"
    fi
done

if [[ ${#bump_cmds[@]} -gt 0 ]]; then
    echo ""
    echo "# root-module pin bumps (run from the repository root, then 'go mod tidy'):"
    for cmd in "${bump_cmds[@]}"; do
        echo "${cmd}"
    done
fi
