#!/bin/bash
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then SUDO_CMD="sudo"; else SUDO_CMD=""; fi
REPO="phpr-source/sing-box.json"
TAG="${1:-stable}"
if [ "$TAG" = "testing" ]; then
  TAG="sing-box-testing"
else
  TAG="sing-box-stable"
fi
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) FILE_ARCH="amd64-v3" ;;
  aarch64|arm64) FILE_ARCH="arm64" ;;
  armv7l) FILE_ARCH="armv7" ;;
  armv6l) FILE_ARCH="armv6" ;;
  mips*) FILE_ARCH="mips" ;;
  *) echo "Unsupported arch: $ARCH"; exit 1 ;;
esac
echo "Fetching latest release for $FILE_ARCH (tag: $TAG)..."

ASSET_URL=$(curl -sSL "https://api.github.com/repos/$REPO/releases/tags/$TAG" | \
  jq -r --arg arch "$FILE_ARCH" '
    [ .assets[] | select(.name | test($arch) and endswith(".tar.gz") and (contains("original") | not)) ] | first | .browser_download_url // empty
  ')

[ -z "$ASSET_URL" ] && { echo "❌ No release found for $FILE_ARCH"; exit 1; }
echo "Downloading $ASSET_URL ..."
curl -fLO "$ASSET_URL" || { echo "❌ Download failed"; exit 1; }
FILE_NAME=$(basename "$ASSET_URL")
tar -xzf "$FILE_NAME"
chmod +x sing-box
$SUDO_CMD mv sing-box /usr/local/bin/
echo "✅ Installation complete."
