#!/usr/bin/env sh
set -eu

repo="${BOMLY_REPO:-bomly-dev/bomly-cli}"
binary="${BOMLY_BINARY:-bomly}"
version="${BOMLY_VERSION:-latest}"
install_dir="${BOMLY_INSTALL_DIR:-/usr/local/bin}"

case "$binary" in
  bomly|bomly-lite) ;;
  *) echo "BOMLY_BINARY must be bomly or bomly-lite" >&2; exit 1 ;;
esac

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$os" in
  linux|darwin) ;;
  *) echo "unsupported OS: $os" >&2; exit 1 ;;
esac

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch="amd64" ;;
  arm64|aarch64) arch="arm64" ;;
  *) echo "unsupported architecture: $arch" >&2; exit 1 ;;
esac

# Testing/air-gapped seam: when BOMLY_INSTALL_ARCHIVE points at a local copy
# of a release tar.gz, install from it directly and skip version resolution,
# download, and checksum verification. The bypass applies only when the
# variable is explicitly set — normal installs always download and verify the
# archive against the release's SHA256SUMS.
local_archive="${BOMLY_INSTALL_ARCHIVE:-}"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT INT TERM

if [ -n "$local_archive" ]; then
  if [ ! -f "$local_archive" ]; then
    echo "BOMLY_INSTALL_ARCHIVE ${local_archive} is not a file" >&2
    exit 1
  fi
  echo "notice: BOMLY_INSTALL_ARCHIVE is set; installing from ${local_archive} without download or checksum verification" >&2
  if [ "$version" = "latest" ]; then
    version="local"
  fi
  archive="$(basename "$local_archive")"
  cp "$local_archive" "${tmpdir}/${archive}"
else
  if [ "$version" = "latest" ]; then
    version="$(curl -fsSL "https://api.github.com/repos/${repo}/releases/latest" | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
  fi

  if [ -z "$version" ]; then
    echo "could not resolve Bomly version" >&2
    exit 1
  fi

  asset_version="${version#v}"
  archive="${binary}_${asset_version}_${os}_${arch}.tar.gz"
  base_url="https://github.com/${repo}/releases/download/${version}"

  curl -fsSL "${base_url}/${archive}" -o "${tmpdir}/${archive}"
  curl -fsSL "${base_url}/SHA256SUMS" -o "${tmpdir}/SHA256SUMS"

  (
    cd "$tmpdir"
    grep "  ${archive}\$" SHA256SUMS > SHA256SUMS.selected
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum -c SHA256SUMS.selected
    else
      shasum -a 256 -c SHA256SUMS.selected
    fi
  )
fi

(
  cd "$tmpdir"
  mkdir extracted
  tar -xzf "$archive" -C extracted
)

# License and notice files from the archive are installed beside the binary's
# prefix so they persist after the temp dir is removed: a `<prefix>/bin`
# install dir gets `<prefix>/share/doc/bomly`, anything else gets a
# `bomly-docs` subdirectory of the install dir itself.
case "$install_dir" in
  */bin) doc_dir="${install_dir%/bin}/share/doc/bomly" ;;
  *) doc_dir="${install_dir}/bomly-docs" ;;
esac

mkdir_cmd="mkdir -p"
install_cmd="install -m 0755"
install_doc_cmd="install -m 0644"
copy_cmd="cp -R"
remove_cmd="rm -rf"
if [ ! -w "$install_dir" ]; then
  if command -v sudo >/dev/null 2>&1; then
    mkdir_cmd="sudo mkdir -p"
    install_cmd="sudo install -m 0755"
    install_doc_cmd="sudo install -m 0644"
    copy_cmd="sudo cp -R"
    remove_cmd="sudo rm -rf"
  else
    echo "$install_dir is not writable and sudo was not found" >&2
    exit 1
  fi
fi

$mkdir_cmd "$install_dir"
$install_cmd "${tmpdir}/extracted/${binary}" "${install_dir}/bomly"

$mkdir_cmd "$doc_dir"
for doc in LICENSE NOTICE; do
  if [ -f "${tmpdir}/extracted/${doc}" ]; then
    $install_doc_cmd "${tmpdir}/extracted/${doc}" "${doc_dir}/${doc}"
  else
    echo "warning: ${doc} not found in ${archive}; skipping" >&2
  fi
done
if [ -d "${tmpdir}/extracted/licenses" ]; then
  $remove_cmd "${doc_dir}/licenses"
  $copy_cmd "${tmpdir}/extracted/licenses" "${doc_dir}/licenses"
else
  echo "warning: licenses/ not found in ${archive}; skipping" >&2
fi

echo "Installed ${binary} ${version} to ${install_dir}/bomly"
echo "Installed license and notice files to ${doc_dir}"
