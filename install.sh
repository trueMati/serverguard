#!/usr/bin/env bash
set -euo pipefail

repo="${SERVERGUARD_REPO:-trueMati/serverguard}"
version="${SERVERGUARD_VERSION:-latest}"
install_dir="${SERVERGUARD_INSTALL_DIR:-/usr/local/bin}"

case "$(uname -s)" in
  Linux) ;;
  *)
    echo "ServerGuard currently supports Linux only." >&2
    exit 1
    ;;
esac

case "$(uname -m)" in
  x86_64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  *)
    echo "Unsupported architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

command -v curl >/dev/null 2>&1 || {
  echo "curl is required." >&2
  exit 1
}
command -v sha256sum >/dev/null 2>&1 || {
  echo "sha256sum is required." >&2
  exit 1
}

asset="serverguard_linux_${arch}"
if [[ "$version" == "latest" ]]; then
  base_url="https://github.com/${repo}/releases/latest/download"
else
  [[ "$version" == v* ]] || version="v${version}"
  base_url="https://github.com/${repo}/releases/download/${version}"
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

curl --fail --silent --show-error --location \
  "${base_url}/${asset}" \
  --output "${tmp_dir}/${asset}"
curl --fail --silent --show-error --location \
  "${base_url}/checksums.txt" \
  --output "${tmp_dir}/checksums.txt"

expected="$(awk -v file="${asset}" '$2 == file { print $1; exit }' "${tmp_dir}/checksums.txt")"
if [[ -z "$expected" ]]; then
  echo "No checksum found for ${asset}." >&2
  exit 1
fi

actual="$(sha256sum "${tmp_dir}/${asset}" | awk '{print $1}')"
if [[ "$actual" != "$expected" ]]; then
  echo "Checksum verification failed." >&2
  exit 1
fi

mkdir -p "$install_dir" 2>/dev/null || true
if [[ -w "$install_dir" ]]; then
  install -m 0755 "${tmp_dir}/${asset}" "${install_dir}/serverguard"
else
  command -v sudo >/dev/null 2>&1 || {
    echo "sudo is required to install into ${install_dir}." >&2
    exit 1
  }
  sudo install -m 0755 "${tmp_dir}/${asset}" "${install_dir}/serverguard"
fi

echo "ServerGuard installed at ${install_dir}/serverguard"
