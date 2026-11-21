#!/bin/sh
# install.sh: curl-pipe installer for pillarbox.
# Usage: curl -fsSL https://raw.githubusercontent.com/leonardobetti/pillarbox-cli/main/scripts/install.sh | sh
# Env: PILLARBOX_VERSION (default: latest release), PILLARBOX_INSTALL_DIR (default: ~/.local/bin)
set -eu

REPO="leonardobetti/pillarbox-cli"
VERSION="${1:-${PILLARBOX_VERSION:-}}"
INSTALL_DIR="${PILLARBOX_INSTALL_DIR:-$HOME/.local/bin}"

os=$(uname -s)
arch=$(uname -m)
case "$os" in
  Darwin) os=darwin ;;
  Linux)  os=linux ;;
  *) echo "pillarbox: unsupported OS: $os" >&2; exit 1 ;;
esac
case "$arch" in
  x86_64|amd64)   arch=amd64 ;;
  arm64|aarch64)  arch=arm64 ;;
  *) echo "pillarbox: unsupported architecture: $arch" >&2; exit 1 ;;
esac

if [ -z "$VERSION" ]; then
  VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
    | grep -o '"tag_name": *"v[0-9.]*"' | head -1 | cut -d'"' -f4 | sed 's/^v//')
  if [ -z "$VERSION" ]; then
    echo "pillarbox: could not find the latest release" >&2
    exit 1
  fi
fi

archive="pillarbox_${VERSION}_${os}_${arch}.tar.gz"
base="https://github.com/$REPO/releases/download/v${VERSION}"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

curl -fsSLO "$base/$archive"
curl -fsSLO "$base/checksums.txt"

if command -v sha256sum >/dev/null 2>&1; then
  grep "$archive" checksums.txt | sha256sum -c -
else
  grep "$archive" checksums.txt | shasum -a 256 -c -
fi

tar -xzf "$archive" pillarbox
mkdir -p "$INSTALL_DIR"
mv pillarbox "$INSTALL_DIR/pillarbox"
chmod 755 "$INSTALL_DIR/pillarbox"

echo "pillarbox $VERSION installed to $INSTALL_DIR/pillarbox"
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) echo "note: $INSTALL_DIR is not on your PATH" >&2 ;;
esac
