#!/bin/sh
# Downloads the frp release pinned in Dockerfile.agent, checks its SHA-256
# and extracts frpc and frps into the given folder. Used by the memory
# budget test; the image build has its own download stage.
set -eu

dest=${1:?usage: fetch.sh <folder>}
root=$(cd "$(dirname "$0")/../.." && pwd)
dockerfile="$root/Dockerfile.agent"

arg() { sed -n "s/^ARG $1=\([0-9A-Za-z.]*\)\$/\1/p" "$dockerfile" | head -n 1; }

version=$(arg FRP_VERSION)
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64; sum=$(arg FRP_SHA256_AMD64) ;;
  aarch64 | arm64) arch=arm64; sum=$(arg FRP_SHA256_ARM64) ;;
  *) echo "fetch.sh: unsupported machine $(uname -m)" >&2; exit 1 ;;
esac
case "$sum" in
  *[!0-9a-f]*) sum="" ;;
esac
if [ -z "$version" ] || [ ${#sum} -ne 64 ]; then
  echo "fetch.sh: frp pin not found in $dockerfile" >&2
  exit 1
fi

if [ -x "$dest/frpc" ] && [ -x "$dest/frps" ] && [ "$(cat "$dest/.version" 2>/dev/null)" = "$version-$arch-$sum" ]; then
  exit 0
fi

name="frp_${version}_linux_${arch}"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/frp.tar.gz" \
  "https://github.com/fatedier/frp/releases/download/v${version}/${name}.tar.gz"
echo "$sum  $tmp/frp.tar.gz" | sha256sum -c - >/dev/null
tar -xzf "$tmp/frp.tar.gz" -C "$tmp" "$name/frpc" "$name/frps"
mkdir -p "$dest"
install -m 0755 "$tmp/$name/frpc" "$tmp/$name/frps" "$dest/"
echo "$version-$arch-$sum" > "$dest/.version"
echo "frp $version ($arch) in $dest"
