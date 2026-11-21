#!/bin/sh
# install.sh: curl-pipe installer for pillarbox.
# Usage: curl -fsSL https://raw.githubusercontent.com/leonardobetti/pillarbox-cli/main/scripts/install.sh | sh
# Env: PILLARBOX_VERSION (default: latest release), PILLARBOX_INSTALL_DIR (default: ~/.local/bin)
#
# The latest version is resolved through releases/latest/download, not the
# REST API: unauthenticated API calls are rate-limited to 60 per hour.
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

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

if [ -n "$VERSION" ]; then
  archive="pillarbox_${VERSION}_${os}_${arch}.tar.gz"
  curl -fsSLO "https://github.com/$REPO/releases/download/v${VERSION}/$archive"
  curl -fsSLO "https://github.com/$REPO/releases/download/v${VERSION}/checksums.txt"
else
  # Fixed asset name: the latest release redirects to it without an API call.
  curl -fsSLO "https://github.com/$REPO/releases/latest/download/checksums.txt"
  archive=$(grep -o "pillarbox_[0-9.]*_${os}_${arch}\.tar\.gz" checksums.txt | head -1)
  if [ -z "$archive" ]; then
    echo "pillarbox: no release asset for ${os}_${arch}" >&2
    exit 1
  fi
  VERSION=$(echo "$archive" | sed 's/pillarbox_\([0-9.]*\)_.*/\1/')
  curl -fsSLO "https://github.com/$REPO/releases/download/v${VERSION}/$archive"
fi

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
