#!/usr/bin/env bash
set -euo pipefail

FUZZTIME="${FUZZTIME:-60s}"

# When FUZZ_RESULTS_JSONL is set, every target is attempted and one JSON line
# per target is written to that file, so the release assurance framework can
# record the whole run instead of stopping at the first failure. The script
# still exits non-zero when any target failed.
FUZZ_RESULTS_JSONL="${FUZZ_RESULTS_JSONL:-}"

# The SDK's own fuzz targets (package URL canonicalization, graph/registry
# transport JSON) moved with the sdk package to the bomly-sdk repository and
# run there.
targets=(
  "github.com/bomly-dev/bomly-cli/internal/assurance FuzzParseCatalog"
  "github.com/bomly-dev/bomly-cli/internal/assurance FuzzParseCheckResult"
  "github.com/bomly-dev/bomly-cli/internal/assurance FuzzParseGoTestEvents"
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
  "github.com/bomly-dev/bomly-cli/internal/sbom FuzzUnmarshalAutoJSON"
  "github.com/bomly-dev/bomly-cli/internal/sbom FuzzNormalizeSPDXLicenseExpression"
  "github.com/bomly-dev/bomly-cli/internal/baseline FuzzLoad"
  "github.com/bomly-dev/bomly-cli/internal/engine FuzzConsolidateVulnerabilities"
  "github.com/bomly-dev/bomly-cli/internal/plugin FuzzPluginPathSanitizers"
)

if [ -n "${FUZZ_RESULTS_JSONL}" ]; then
  : > "${FUZZ_RESULTS_JSONL}"
fi

failures=0
for target in "${targets[@]}"; do
  package="${target%% *}"
  fuzz="${target#* }"
  echo "==> go test ${package} -run=^$ -fuzz=^${fuzz}$ -fuzztime=${FUZZTIME}"
  started="$(date -u +%s)"
  status=0
  if [ -n "${FUZZ_RESULTS_JSONL}" ]; then
    go test "${package}" -run=^$ -fuzz="^${fuzz}$" -fuzztime="${FUZZTIME}" || status=$?
  else
    go test "${package}" -run=^$ -fuzz="^${fuzz}$" -fuzztime="${FUZZTIME}"
  fi
  if [ "${status}" -ne 0 ]; then
    failures=$((failures + 1))
  fi
  if [ -n "${FUZZ_RESULTS_JSONL}" ]; then
    printf '{"name":"%s %s","exit_code":%s,"duration_s":%s}\n' \
      "${package##*/}" "${fuzz}" "${status}" "$(( $(date -u +%s) - started ))" \
      >> "${FUZZ_RESULTS_JSONL}"
  fi
done

if [ "${failures}" -ne 0 ]; then
  echo "${failures} fuzz target(s) failed" >&2
  exit 1
fi
