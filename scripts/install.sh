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
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT INT TERM

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
  tar -xzf "$archive" "$binary"
)

mkdir_cmd="mkdir -p"
install_cmd="install -m 0755"
if [ ! -w "$install_dir" ]; then
  if command -v sudo >/dev/null 2>&1; then
    mkdir_cmd="sudo mkdir -p"
    install_cmd="sudo install -m 0755"
  else
    echo "$install_dir is not writable and sudo was not found" >&2
    exit 1
  fi
fi

$mkdir_cmd "$install_dir"
$install_cmd "${tmpdir}/${binary}" "${install_dir}/bomly"

echo "Installed ${binary} ${version} to ${install_dir}/bomly"
