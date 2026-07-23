#!/usr/bin/env bash
set -euo pipefail

FUZZTIME="${FUZZTIME:-60s}"

targets=(
  "github.com/bomly-dev/bomly-cli/internal/detectors/node/npm FuzzDepGraphFromNPMLockfile"
  "github.com/bomly-dev/bomly-cli/internal/detectors/node/pnpm FuzzDepGraphFromPNPMLockfile"
  "github.com/bomly-dev/bomly-cli/internal/detectors/node/yarn FuzzDepGraphFromYarnLockfile"
  "github.com/bomly-dev/bomly-cli/internal/sbom FuzzUnmarshalAutoJSON"
  "github.com/bomly-dev/bomly-cli/internal/baseline FuzzLoad"
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
