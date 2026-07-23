#!/usr/bin/env bash
set -euo pipefail

FUZZTIME="${FUZZTIME:-60s}"

targets=(
  "github.com/bomly-dev/bomly-cli/internal/config FuzzLoadFile"
  "github.com/bomly-dev/bomly-cli/internal/analyzers/govulncheck FuzzParseGovulncheckJSON"
  "github.com/bomly-dev/bomly-cli/internal/analyzers/jsreach FuzzExtractImportedPackages"
  "github.com/bomly-dev/bomly-cli/internal/detectors/cargo FuzzDepGraphFromCargoLock"
  "github.com/bomly-dev/bomly-cli/internal/detectors/cocoapods FuzzDepGraphFromPodfileLock"
  "github.com/bomly-dev/bomly-cli/internal/detectors/composer FuzzDepGraphFromComposerLock"
  "github.com/bomly-dev/bomly-cli/internal/detectors/conan FuzzDepGraphFromConanJSON"
  "github.com/bomly-dev/bomly-cli/internal/detectors/githubactions FuzzParseWorkflowRefs"
  "github.com/bomly-dev/bomly-cli/internal/detectors/gomod FuzzDepGraphFromGoList"
  "github.com/bomly-dev/bomly-cli/internal/detectors/mix FuzzDepGraphFromMixLock"
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
  "github.com/bomly-dev/bomly-cli/internal/baseline FuzzLoad"
  "github.com/bomly-dev/bomly-cli/internal/engine FuzzConsolidateVulnerabilities"
  "github.com/bomly-dev/bomly-cli/sdk FuzzCanonicalizePackageURL"
  "github.com/bomly-dev/bomly-cli/sdk FuzzGraphJSON"
  "github.com/bomly-dev/bomly-cli/sdk FuzzPackageRegistryJSON"
  "github.com/bomly-dev/bomly-cli/internal/plugin FuzzPluginPathSanitizers"
)

for target in "${targets[@]}"; do
  package="${target%% *}"
  fuzz="${target#* }"
  echo "==> go test ${package} -run=^$ -fuzz=^${fuzz}$ -fuzztime=${FUZZTIME}"
  go test "${package}" -run=^$ -fuzz="^${fuzz}$" -fuzztime="${FUZZTIME}"
done
