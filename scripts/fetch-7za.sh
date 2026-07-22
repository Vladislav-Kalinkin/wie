#!/usr/bin/env bash
# One-time setup: download the Windows x64 7-Zip Extra PE into real_exes/.
# Requires: curl, Homebrew p7zip (for unpacking the Extra archive).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$ROOT/real_exes"

if [[ -f "$DEST/7za.exe" ]]; then
  echo "7za.exe already present at $DEST/7za.exe"
  file "$DEST/7za.exe"
  exit 0
fi

if ! command -v 7za &>/dev/null; then
  echo "Installing p7zip (needed to unpack the Extra archive)…"
  brew install p7zip
fi

mkdir -p "$DEST"

VER=26.02
VER_COMPACT=2602
TMP="/tmp/7z-extra-$$"
mkdir -p "$TMP"

curl -fL -o "$TMP/extra.7z" \
  "https://github.com/ip7z/7zip/releases/download/${VER}/7z${VER_COMPACT}-extra.7z"

7za x -y -o"$TMP/out" "$TMP/extra.7z"

cp -f "$TMP/out/x64/7za.exe"  "$DEST/"
cp -f "$TMP/out/x64/7za.dll"  "$DEST/"
cp -f "$TMP/out/x64/7zxa.dll" "$DEST/"

rm -rf "$TMP"

echo "downloaded:"
file "$DEST/7za.exe"
