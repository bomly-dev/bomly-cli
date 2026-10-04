#!/usr/bin/env bash
set -euo pipefail

FUZZTIME="${FUZZTIME:-60s}"

# When FUZZ_RESULTS_JSONL is set, every target is attempted and one JSON line
# per target is written to that file, so the release assurance framework can
# record the whole run instead of stopping at the first failure. The script
# still exits non-zero when any target failed.
FUZZ_RESULTS_JSONL="${FUZZ_RESULTS_JSONL:-}"

# FUZZ_JOBS runs that many targets at once (default 1, one after another).
# Each target is its own `go test` process, so they parallelize cleanly; the
# release prerequisites stage uses this to keep thirty targets from taking
# thirty times one target's budget. Every target is attempted in this mode,
# and each one's output is printed whole when it finishes rather than
# interleaved with its neighbours'.
FUZZ_JOBS="${FUZZ_JOBS:-1}"

# FUZZ_GROUP picks which targets run: all (the default), parsers, or
# engine-and-plugin. See the target lists below for why there are two.
FUZZ_GROUP="${FUZZ_GROUP:-all}"
case "${FUZZ_JOBS}" in
  ''|*[!0-9]*|0) echo "FUZZ_JOBS must be a positive integer, got '${FUZZ_JOBS}'" >&2; exit 2 ;;
esac

# run_target fuzzes one "<package> <FuzzName>" pair, records it when a results
# file is set, and returns the target's exit status.
run_target() {
  local package="${1%% *}" fuzz="${1#* }" started status=0
  local -a workers=()
  # Concurrent fuzzers would each start one worker per CPU and fight over
  # them; give each an even share instead. (The array is expanded with the
  # ${x[@]+...} form below because bash 3.2, which macOS ships, treats an
  # empty array as unset under `set -u`.)
  if [ "${FUZZ_JOBS}" -gt 1 ]; then
    local cpus
    cpus="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"
    workers=("-parallel=$(( cpus / FUZZ_JOBS > 0 ? cpus / FUZZ_JOBS : 1 ))")
  fi
  echo "==> go test ${package} -run=^$ -fuzz=^${fuzz}$ -fuzztime=${FUZZTIME}"
  started="$(date -u +%s)"
  go test "${package}" -run=^$ -fuzz="^${fuzz}$" -fuzztime="${FUZZTIME}" ${workers[@]+"${workers[@]}"} || status=$?
  if [ -n "${FUZZ_RESULTS_JSONL}" ]; then
    # One short line per append, so concurrent targets cannot tear each other.
    printf '{"name":"%s %s","exit_code":%s,"duration_s":%s}\n' \
      "${package##*/}" "${fuzz}" "${status}" "$(( $(date -u +%s) - started ))" \
      >> "${FUZZ_RESULTS_JSONL}"
  fi
  return "${status}"
}

# Internal entry point for the parallel mode: run one target, print its output
# in one piece, and exit with its status.
if [ "${1:-}" = "--target" ]; then
  output="$(mktemp)"
  status=0
  run_target "$2" > "${output}" 2>&1 || status=$?
  cat "${output}"
  rm -f "${output}"
  exit "${status}"
fi

# The SDK's own fuzz targets (package URL canonicalization, graph/registry
# transport JSON) moved with the sdk package to the bomly-sdk repository and
# run there.
#
# The targets are in two groups. The packages of the second group pull in most
# of the module graph, and a fuzz build instruments every dependency, so each
# of those targets spends minutes compiling before it fuzzes for the first
# second. In one list they held the whole run open: the other 28 targets were
# done in five minutes and the job then compiled these two for six more. CI
# runs each group as its own job (FUZZ_GROUP); locally, the default runs both.
engine_and_plugin_targets=(
  "github.com/bomly-dev/bomly-cli/internal/engine FuzzConsolidateVulnerabilities"
  "github.com/bomly-dev/bomly-cli/internal/plugin FuzzPluginPathSanitizers"
)
parser_targets=(
  "github.com/bomly-dev/bomly-cli/internal/assurance FuzzParseCatalog"
  "github.com/bomly-dev/bomly-cli/internal/assurance FuzzParseCheckResult"
  "github.com/bomly-dev/bomly-cli/internal/assurance FuzzParseGoTestEvents"
  "github.com/bomly-dev/bomly-cli/internal/assurance/sbominterop FuzzEvaluateMergedLinks"
  "github.com/bomly-dev/bomly-cli/internal/config FuzzLoadFile"
  "github.com/bomly-dev/bomly-cli/internal/detectors/cargo FuzzDepGraphFromCargoLock"
  "github.com/bomly-dev/bomly-cli/internal/detectors/cargo FuzzDepGraphFromCargoLockWorkspace"
  "github.com/bomly-dev/bomly-cli/internal/detectors/cocoapods FuzzDepGraphFromPodfileLock"
  "github.com/bomly-dev/bomly-cli/internal/detectors/composer FuzzDepGraphFromComposerLock"
  "github.com/bomly-dev/bomly-cli/internal/detectors/conan FuzzDepGraphFromConanJSON"
  "github.com/bomly-dev/bomly-cli/internal/detectors/githubactions FuzzParseWorkflowRefs"
  "github.com/bomly-dev/bomly-cli/internal/detectors/gomod FuzzDepGraphFromGoList"
  "github.com/bomly-dev/bomly-cli/internal/detectors/gomod FuzzParseGoSumDigests"
  "github.com/bomly-dev/bomly-cli/internal/detectors/mix FuzzDepGraphFromMixLock"
  "github.com/bomly-dev/bomly-cli/internal/detectors/node FuzzPackageManagerWarnings"
  "github.com/bomly-dev/bomly-cli/internal/detectors/node/npm FuzzDepGraphFromNPMLockfile"
  "github.com/bomly-dev/bomly-cli/internal/detectors/node/pnpm FuzzDepGraphFromPNPMLockfile"
  "github.com/bomly-dev/bomly-cli/internal/detectors/node/yarn FuzzDepGraphFromYarnLockfile"
  "github.com/bomly-dev/bomly-cli/internal/detectors/node/bun FuzzDepGraphFromBunLockfile"
  "github.com/bomly-dev/bomly-cli/internal/detectors/nuget FuzzDepGraphFromNuGetLock"
  "github.com/bomly-dev/bomly-cli/internal/detectors/nuget FuzzDepGraphFromPackagesConfig"
  "github.com/bomly-dev/bomly-cli/internal/detectors/pub FuzzDepGraphFromPubLock"
  "github.com/bomly-dev/bomly-cli/internal/detectors/python FuzzDepGraphFromPoetryLock"
  "github.com/bomly-dev/bomly-cli/internal/detectors/python FuzzDepGraphFromUVLock"
  "github.com/bomly-dev/bomly-cli/internal/detectors/python FuzzDepGraphFromPipfileLock"
  "github.com/bomly-dev/bomly-cli/internal/detectors/ruby FuzzDepGraphFromBundlerLock"
  "github.com/bomly-dev/bomly-cli/internal/detectors/swiftpm FuzzDepGraphFromSwiftResolved"
  "github.com/bomly-dev/bomly-cli/internal/baseline FuzzLoad"
)

case "${FUZZ_GROUP}" in
  all) targets=("${parser_targets[@]}" "${engine_and_plugin_targets[@]}") ;;
  parsers) targets=("${parser_targets[@]}") ;;
  engine-and-plugin) targets=("${engine_and_plugin_targets[@]}") ;;
  *) echo "FUZZ_GROUP must be all, parsers, or engine-and-plugin, got '${FUZZ_GROUP}'" >&2; exit 2 ;;
esac

if [ -n "${FUZZ_RESULTS_JSONL}" ]; then
  : > "${FUZZ_RESULTS_JSONL}"
fi

failures=0

if [ "${FUZZ_JOBS}" -gt 1 ]; then
  # xargs keeps going past a failing target and exits non-zero if any failed.
  if ! printf '%s\0' "${targets[@]}" | xargs -0 -n 1 -P "${FUZZ_JOBS}" "$0" --target; then
    echo "one or more fuzz targets failed" >&2
    exit 1
  fi
  exit 0
fi

for target in "${targets[@]}"; do
  status=0
  if [ -n "${FUZZ_RESULTS_JSONL}" ]; then
    run_target "${target}" || status=$?
  else
    run_target "${target}"
  fi
  if [ "${status}" -ne 0 ]; then
    failures=$((failures + 1))
  fi
done

if [ "${failures}" -ne 0 ]; then
  echo "${failures} fuzz target(s) failed" >&2
  exit 1
fi
