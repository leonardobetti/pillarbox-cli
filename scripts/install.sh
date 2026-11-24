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

init_colors() {
  if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_RESET='\033[0m'
    C_BOLD='\033[1m'
    C_DIM='\033[2m'
    C_RED='\033[1;31m'
    C_GREEN='\033[1;32m'
    C_YELLOW='\033[1;33m'
    C_BLUE='\033[1;34m'
    C_MAGENTA='\033[1;35m'
    C_CYAN='\033[1;36m'
    C_WHITE='\033[1;37m'
  else
    C_RESET=''
    C_BOLD=''
    C_DIM=''
    C_RED=''
    C_GREEN=''
    C_YELLOW=''
    C_BLUE=''
    C_MAGENTA=''
    C_CYAN=''
    C_WHITE=''
  fi
}

print_banner() {
  printf '\n'
  printf '  %b%s%b\n' "$C_MAGENTA" ' ____  ___ _     _        _    ____  ____   ___ __  __' "$C_RESET"
  printf '  %b%s%b\n' "$C_BLUE"    '|  _ \|_ _| |   | |      / \  |  _ \| __ ) / _ \\ \/ /' "$C_RESET"
  printf '  %b%s%b\n' "$C_CYAN"    '| |_) || || |   | |     / _ \ | |_) |  _ \| | | |\  / ' "$C_RESET"
  printf '  %b%s%b\n' "$C_GREEN"   '|  __/ | || |___| |___ / ___ \|  _ <| |_) | |_| |/  \ ' "$C_RESET"
  printf '  %b%s%b\n' "$C_YELLOW"  '|_|   |___|_____|_____/_/   \_\_| \_\____/ \___//_/\_\' "$C_RESET"
  printf '  %b%s%b\n\n' "$C_DIM" "Terminal file encryption" "$C_RESET"
}

step() {
  printf '  %b==>%b %s\n' "$C_CYAN" "$C_RESET" "$1"
}

ok() {
  printf '  %b✓%b %s\n' "$C_GREEN" "$C_RESET" "$1"
}

warn() {
  printf '  %b!%b %s\n' "$C_YELLOW" "$C_RESET" "$1"
}

die() {
  printf '  %b✗%b %s\n' "$C_RED" "$C_RESET" "$1" >&2
  exit 1
}

init_colors
print_banner

command -v curl >/dev/null 2>&1 || die "curl is required to install pillarbox"

os=$(uname -s)
arch=$(uname -m)
case "$os" in
  Darwin) os=darwin ;;
  Linux)  os=linux ;;
  *) die "unsupported OS: $os" ;;
esac
case "$arch" in
  x86_64|amd64)  arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) die "unsupported architecture: $arch" ;;
esac

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

if [ -n "$VERSION" ]; then
  archive="pillarbox_${VERSION}_${os}_${arch}.tar.gz"
  step "Downloading pillarbox v${VERSION} (${os}/${arch})"
  curl -fsSLO "https://github.com/$REPO/releases/download/v${VERSION}/$archive" || die "failed to download $archive"
  curl -fsSLO "https://github.com/$REPO/releases/download/v${VERSION}/checksums.txt" || die "failed to download checksums.txt"
else
  step "Resolving latest release"
  # Fixed asset name: the latest release redirects to it without an API call.
  curl -fsSLO "https://github.com/$REPO/releases/latest/download/checksums.txt" || die "failed to fetch latest release metadata"
  archive=$(grep -o "pillarbox_[0-9.]*_${os}_${arch}\.tar\.gz" checksums.txt | head -1)
  if [ -z "$archive" ]; then
    die "no release asset for ${os}_${arch}"
  fi
  VERSION=$(printf '%s\n' "$archive" | sed 's/pillarbox_\([0-9.]*\)_.*/\1/')
  step "Downloading pillarbox v${VERSION} (${os}/${arch})"
  curl -fsSLO "https://github.com/$REPO/releases/download/v${VERSION}/$archive" || die "failed to download $archive"
fi

step "Verifying SHA-256 checksum"
if command -v sha256sum >/dev/null 2>&1; then
  grep "$archive" checksums.txt | sha256sum -c - >/dev/null 2>&1 || die "checksum verification failed for $archive"
elif command -v shasum >/dev/null 2>&1; then
  grep "$archive" checksums.txt | shasum -a 256 -c - >/dev/null 2>&1 || die "checksum verification failed for $archive"
else
  die "sha256sum or shasum is required to verify checksums"
fi

step "Extracting pillarbox"
tar -xzf "$archive" pillarbox

step "Installing to $INSTALL_DIR/pillarbox"
mkdir -p "$INSTALL_DIR"
mv pillarbox "$INSTALL_DIR/pillarbox"
chmod 755 "$INSTALL_DIR/pillarbox"

printf '\n'
ok "Pillarbox v${VERSION} installed"
printf '    %b%s%b\n\n' "$C_DIM" "$INSTALL_DIR/pillarbox" "$C_RESET"
printf '  Run %b%s%b to get started.\n\n' "$C_BOLD" "pillarbox" "$C_RESET"

case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *)
    warn "$INSTALL_DIR is not on your PATH."
    printf '    Add it with:\n'
    printf '    %bexport PATH="%s:$PATH"%b\n\n' "$C_WHITE" "$INSTALL_DIR" "$C_RESET"
    ;;
esac
