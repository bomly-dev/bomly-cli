#!/usr/bin/env bash
# release-components.sh — lockstep release-train tool for in-repo component modules.
#
# Component modules live under components/<kind>/<name>/ with their own go.mod
# and are versioned in LOCKSTEP with the CLI: every component module is tagged
# at the CLI's release version, whether or not it changed. One version number
# describes the whole repository — the Go equivalent of Maven parent-version
# inheritance: the version is authoritative in one place and automation
# propagates it. Empty component releases are deliberate and accepted in
# exchange for that simplicity.
#
#   components/<kind>/<name>/vX.Y.Z   (X.Y.Z = the CLI release version)
#
# The root go.mod pins released component versions and carries NO replace
# directives, so remote `go install .../cmd/bomly@latest` keeps working at
# every root tag. That constraint forces a two-commit release train, fully
# automated in .github/workflows/auto-version.yml:
#
#   commit A  version bump on main (cmd/bomly/main.go etc.); NOT root-tagged
#   tags      components/<kind>/<name>/vX.Y.Z for every module, at commit A
#             (now `go get <module>@vX.Y.Z` resolves)            → `tag`
#   commit B  root go.mod/go.sum pinned to the new tags, [skip ci] → `pin`
#   root tag  vX.Y.Z at commit B, then release.yml dispatch
#
# Component module zips contain only their own subtree, so commit B (root
# go.mod/go.sum only) never changes what the component tags describe. The
# lockstep invariant is therefore TREE IDENTITY, not commit identity: the
# components/ tree must be identical between the component tags (at A) and
# the root tag (at B). `verify` checks exactly that.
#
# Subcommands (used by auto-version.yml; run manually only for recovery after
# a partial failure):
#
#   tag --version vX.Y.Z --commit <sha>
#       Create and push an annotated components/<kind>/<name>/vX.Y.Z tag for
#       every component module found in <sha>'s tree. Idempotent, remote-first:
#       a tag already on origin at <sha> is skipped; a tag on origin at any
#       other commit aborts the train (resolve it on origin first); a stale
#       local-only tag at the wrong commit aborts with a delete hint; a
#       local-only tag at the right commit (partial earlier run) is pushed.
#
#   pin --version vX.Y.Z
#       With the workspace off, `go get` every component module in HEAD's tree
#       at vX.Y.Z and run `go mod tidy`, so the root go.mod/go.sum pin the
#       just-tagged releases. No commit — the caller commits (commit B).
#       Already-pinned modules make this a no-op, so reruns are safe.
#
#   verify --version vX.Y.Z
#       Check the lockstep invariant for a released version: every component
#       tag exists on origin and peels to a commit whose components/ tree is
#       identical to the root tag's components/ tree.
#
# Usage:
#   ./scripts/release-components.sh                     # dry run at the latest CLI tag
#   ./scripts/release-components.sh --version v1.2.3    # dry run at an explicit version
#   ./scripts/release-components.sh tag --version v1.2.3 --commit <sha>
#   ./scripts/release-components.sh pin --version v1.2.3
#   ./scripts/release-components.sh verify --version v1.2.3
#
# The dry run prints, without changing anything, what the `tag` and `pin`
# phases would do at the given (default: latest) root release tag.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

die() {
    echo "error: $*" >&2
    exit 1
}

usage() {
    echo "usage: $0 [tag|pin|verify] [--version vX.Y.Z] [--commit <sha>]" >&2
    echo "       $0 [--version vX.Y.Z]        # dry run" >&2
    exit 2
}

subcommand="dry-run"
case "${1:-}" in
    tag | pin | verify)
        subcommand="$1"
        shift
        ;;
esac

version=""
commit=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)
            version="${2:-}"
            [[ -n "${version}" ]] || die "--version requires a value (vX.Y.Z)"
            shift 2
            ;;
        --commit)
            commit="${2:-}"
            [[ -n "${commit}" ]] || die "--commit requires a value (sha)"
            shift 2
            ;;
        --apply)
            die "--apply was replaced by subcommands: $0 tag --version vX.Y.Z --commit <sha>, then $0 pin --version vX.Y.Z"
            ;;
        *)
            usage
            ;;
    esac
done

require_version() {
    [[ -n "${version}" ]] || die "${subcommand} requires --version vX.Y.Z"
    [[ "${version}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
        die "version ${version} is not of the form vX.Y.Z"
}

# resolve_default_version fills in the latest CLI release tag when the dry run
# is invoked without --version. Root tags are plain vX.Y.Z; component tags
# carry a path prefix, so this glob cannot match them.
resolve_default_version() {
    if [[ -z "${version}" ]]; then
        version="$(git tag --list 'v[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname | head -n 1)"
        [[ -n "${version}" ]] || die "no CLI release tag found; pass --version vX.Y.Z"
    fi
}

# list_modules prints the component module directories found in a commit's
# tree (never the working tree: the checkout may have drifted from the commit
# being tagged or verified).
list_modules() { # $1 = commit
    git ls-tree -r --name-only "$1" -- components/ |
        { grep -E '^components/[^/]+/[^/]+/go\.mod$' || true; } |
        sed 's#/go\.mod$##'
}

# module_path_at reads the `module` directive of a component go.mod as of a
# commit, validating that the module is well-formed before it gets a tag or a
# pin.
module_path_at() { # $1 = commit, $2 = module dir
    git show "$1:$2/go.mod" | awk '$1 == "module" { print $2; exit }'
}

# remote_tag_commit prints the commit a tag on origin points at, preferring
# the peeled ^{} entry (annotated tags) and falling back to the unpeeled ref
# (lightweight tags). Prints nothing when the tag is not on origin.
remote_tag_commit() { # $1 = tag
    local peeled
    peeled="$(git ls-remote --tags origin "refs/tags/$1^{}" | awk '{print $1; exit}')"
    if [[ -z "${peeled}" ]]; then
        peeled="$(git ls-remote --tags origin "refs/tags/$1" | awk '{print $1; exit}')"
    fi
    printf '%s' "${peeled}"
}

# components_tree_matches succeeds when two commits have byte-identical
# components/ trees — the lockstep invariant between the component tags
# (commit A) and the root tag (commit B).
components_tree_matches() { # $1 = commit, $2 = commit
    git diff --quiet "$1" "$2" -- components/
}

# tag_module creates+pushes (mode=apply) or prints (mode=print) one component
# tag at ${release_commit}. Idempotent reruns must survive a partial failure
# between local tag creation and push: the REMOTE is the source of truth for
# "already released". A local-only tag is verified against the release commit
# (a stale local tag is an error, never silently pushed) and pushed. A
# pre-existing remote tag is verified too; a remote tag at the wrong commit
# aborts the train — it must never silently ride into a release.
tag_module() { # $1 = module dir, $2 = mode (apply|print)
    local module="$1" mode="$2" tag module_path remote_commit local_commit
    tag="${module}/${version}"

    module_path="$(module_path_at "${release_commit}" "${module}")"
    [[ -n "${module_path}" ]] ||
        die "${module}/go.mod at ${release_commit} has no module directive"

    remote_commit="$(remote_tag_commit "${tag}")"
    if [[ -n "${remote_commit}" ]]; then
        if [[ "${mode}" == "print" ]]; then
            # The dry run inspects a released version, where component tags
            # (commit A) legitimately differ from the root tag (commit B), so
            # report tree identity rather than commit equality.
            if ! git cat-file -e "${remote_commit}^{commit}" 2>/dev/null; then
                echo "# ${module}: ${tag} on origin at ${remote_commit} (not available locally; git fetch --tags origin to compare trees)"
            elif components_tree_matches "${remote_commit}" "${release_commit}"; then
                echo "# ${module}: ${tag} already on origin at ${remote_commit} (components/ tree matches ${version}), nothing to do"
            else
                echo "# ${module}: WARNING ${tag} on origin at ${remote_commit} has a DIFFERENT components/ tree than ${version} — run 'verify' for details"
            fi
            return 0
        fi
        if [[ "${remote_commit}" != "${release_commit}" ]]; then
            die "remote tag ${tag} points at ${remote_commit}, not release commit ${release_commit}; resolve the tag on origin before releasing"
        fi
        echo "# ${module}: ${tag} already on origin at ${release_commit}, skipping"
        return 0
    fi

    local_commit="$(git rev-parse -q --verify "refs/tags/${tag}^{commit}" || true)"
    if [[ -n "${local_commit}" && "${local_commit}" != "${release_commit}" ]]; then
        die "local tag ${tag} points at ${local_commit}, not release commit ${release_commit}; delete it (git tag -d ${tag}) and rerun"
    fi

    if [[ "${mode}" == "print" ]]; then
        if [[ -z "${local_commit}" ]]; then
            echo "git tag -a ${tag} -m 'Release ${tag}' ${release_commit}"
        else
            echo "# ${module}: local tag ${tag} exists but is not on origin"
        fi
        echo "git push origin ${tag}"
        return 0
    fi

    if [[ -z "${local_commit}" ]]; then
        git tag -a "${tag}" -m "Release ${tag}" "${release_commit}"
    else
        echo "# ${module}: local tag ${tag} exists but was never pushed, pushing"
    fi
    git push origin "${tag}"
    echo "tagged and pushed ${tag} at ${release_commit}"
}

cmd_tag() { # $1 = mode (apply|print)
    local mode="$1" module found=0
    while IFS= read -r module; do
        [[ -n "${module}" ]] || continue
        found=1
        tag_module "${module}" "${mode}"
    done < <(list_modules "${release_commit}")
    if [[ "${found}" -eq 0 ]]; then
        echo "no component modules under components/*/*/ at ${release_commit} — nothing to tag"
    fi
}

case "${subcommand}" in
    tag)
        require_version
        [[ -n "${commit}" ]] || die "tag requires --commit <sha> (the version-bump commit A)"
        release_commit="$(git rev-parse -q --verify "${commit}^{commit}")" ||
            die "commit ${commit} not found; fetch first"
        echo "# release version: ${version} (commit ${release_commit})"
        cmd_tag apply
        ;;

    pin)
        require_version
        # Pin the root module to the component tags just pushed at commit A.
        # GOWORK=off so `go get` and `go mod tidy` resolve the published tags
        # instead of the committed workspace. Freshly pushed tags may not have
        # reached proxy.golang.org or sum.golang.org yet, so default to a
        # direct origin fetch and skip the checksum database for this
        # repository's own component modules (go.sum still records the hashes
        # computed from the download). Callers may override either variable.
        export GOPROXY="${GOPROXY:-direct}"
        export GONOSUMDB="${GONOSUMDB:-github.com/bomly-dev/bomly-cli/components}"
        pinned=0
        while IFS= read -r module; do
            [[ -n "${module}" ]] || continue
            module_path="$(module_path_at HEAD "${module}")"
            [[ -n "${module_path}" ]] ||
                die "${module}/go.mod at HEAD has no module directive"
            echo "pinning ${module_path}@${version}"
            GOWORK=off go get "${module_path}@${version}"
            pinned=1
        done < <(list_modules HEAD)
        if [[ "${pinned}" -eq 0 ]]; then
            echo "no component modules under components/*/*/ at HEAD — nothing to pin"
            exit 0
        fi
        GOWORK=off go mod tidy
        echo "pinned component modules at ${version}; commit the root go.mod/go.sum changes (commit B)"
        ;;

    verify)
        resolve_default_version
        require_version
        root_commit="$(remote_tag_commit "${version}")"
        [[ -n "${root_commit}" ]] || die "root tag ${version} is not on origin"
        git cat-file -e "${root_commit}^{commit}" 2>/dev/null ||
            die "commit ${root_commit} (root tag ${version}) is not available locally; run 'git fetch --tags origin' and rerun"
        checked=0
        while IFS= read -r module; do
            [[ -n "${module}" ]] || continue
            tag="${module}/${version}"
            component_commit="$(remote_tag_commit "${tag}")"
            [[ -n "${component_commit}" ]] ||
                die "component tag ${tag} is not on origin (root tag ${version} is at ${root_commit}); rerun: $0 tag --version ${version} --commit <bump commit A>"
            git cat-file -e "${component_commit}^{commit}" 2>/dev/null ||
                die "commit ${component_commit} (tag ${tag}) is not available locally; run 'git fetch --tags origin' and rerun"
            if ! components_tree_matches "${component_commit}" "${root_commit}"; then
                die "components/ tree differs between ${tag} (at ${component_commit}) and root tag ${version} (at ${root_commit}); the lockstep invariant is broken"
            fi
            echo "ok: ${tag} at ${component_commit} (components/ tree matches root tag)"
            checked=$((checked + 1))
        done < <(list_modules "${root_commit}")
        echo "verify ${version}: ${checked} component tag(s) in lockstep with the root tag at ${root_commit}"
        ;;

    dry-run)
        [[ -z "${commit}" ]] || die "--commit is only valid with the tag subcommand"
        resolve_default_version
        require_version
        release_commit="$(git rev-parse -q --verify "refs/tags/${version}^{commit}")" ||
            die "release tag ${version} not found locally; fetch tags first (git fetch --tags)"
        echo "# release version: ${version} (root tag commit ${release_commit})"
        echo "# dry run — tag phase (auto-version.yml runs this at the version-bump commit A):"
        cmd_tag print
        echo ""
        echo "# dry run — pin phase ('pin --version ${version}' runs these with GOWORK=off, then 'go mod tidy'):"
        pins=0
        while IFS= read -r module; do
            [[ -n "${module}" ]] || continue
            module_path="$(module_path_at "${release_commit}" "${module}")"
            [[ -n "${module_path}" ]] ||
                die "${module}/go.mod at ${version} has no module directive"
            echo "go get ${module_path}@${version}"
            pins=1
        done < <(list_modules "${release_commit}")
        if [[ "${pins}" -eq 0 ]]; then
            echo "# (no component modules — nothing to pin)"
        fi
        ;;
esac
